package hoopsnake

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/peterbourgon/ff/v3/ffcli"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/client/tailscale"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

// TailnetSSH defines an SSH service that listens on a tailnet and runs a given shell program.
//
// The zero value of TailnetSSH is not a valid instance. Use
// TailnetSSHFromArgs to construct a valid one.
type TailnetSSH struct {
	ssh.Server
	serviceName       string
	stateDir          string
	hostKeyFile       string
	authorizedKeyFile string
	tsnetVerbose      bool
	deleteExisting    bool
	maxNodeAge        time.Duration
	tags              []string
	command           []string
}

var ErrMissingServiceName = fmt.Errorf("service name must be set via -name")
var ErrMissingACLTag = fmt.Errorf("service must have at least one ACL tag")
var ErrMissingCommand = fmt.Errorf("ssh connections must run a command - pass that as the remaining cli arguments")

// / TailnetSSHFromArgs parses CLI arguments and constructs a validated TailnetSSH structure.
func TailnetSSHFromArgs(args []string) (*TailnetSSH, error) {
	s := &TailnetSSH{}
	fs := flag.NewFlagSet("hoopsnake", flag.ExitOnError)
	fs.StringVar(&s.serviceName, "name", "", "Machine name to set on the tailnet")
	fs.StringVar(&s.stateDir, "stateDir", "", "Directory where hoopsnake stores tsnet state")
	fs.StringVar(&s.hostKeyFile, "hostKey", "", "Pathname to the SSH host key")
	fs.StringVar(&s.authorizedKeyFile, "authorizedKeys", "", "Pathname to a file listing authorized client keys")
	fs.BoolVar(&s.tsnetVerbose, "tsnetVerbose", false, "Log tsnet messages verbosely")
	fs.BoolVar(&s.deleteExisting, "deleteExisting", false, "Delete any down node with a conflicting name, if one exists")
	fs.DurationVar(&s.maxNodeAge, "maxNodeAge", 30*time.Second, "Matching node must be offline at least this long if -deleteExisting is set")

	var tags string
	fs.StringVar(&tags, "tags", "", "Tailnet ACL tags assigned to the node, comma-separated")
	root := &ffcli.Command{
		ShortUsage: fmt.Sprintf("%s -name <serviceName> -tags <tags> [flags] <command> [argv ...]", path.Base(args[0])),
		FlagSet:    fs,
		Exec:       func(context.Context, []string) error { return nil },
	}
	if err := root.Parse(args[1:]); err != nil {
		return nil, fmt.Errorf("could not parse args: %w", err)
	}

	if s.serviceName == "" {
		return nil, ErrMissingServiceName
	}

	err := s.setupAuthorizedKeys()
	if err != nil {
		return nil, err
	}
	err = s.setupHostKey()
	if err != nil {
		return nil, err
	}
	s.tags = strings.Split(tags, ",")
	if len(s.tags) == 0 {
		return nil, ErrMissingACLTag
	}

	s.command = root.FlagSet.Args()
	if len(s.command) == 0 {
		return nil, ErrMissingCommand
	}

	return s, nil
}

func (s *TailnetSSH) setupAuthorizedKeys() error {
	authorizedKeysBytes, err := os.ReadFile(s.authorizedKeyFile)
	if err != nil {
		log.Fatalf("Could not read authorized keys file %q: %v", s.authorizedKeyFile, err)
	}
	var authorizedPubKeys []gossh.PublicKey
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return fmt.Errorf("Could not parse authorized key: %w", err)
		}

		authorizedPubKeys = append(authorizedPubKeys, pubKey)
		authorizedKeysBytes = rest
	}
	if len(authorizedPubKeys) > 0 {
		s.Server.PublicKeyHandler = func(ctx ssh.Context, key ssh.PublicKey) bool {
			log.Printf("Attempting auth for user %q with public key %q", ctx.User(), gossh.MarshalAuthorizedKey(key))
			matched := false
			for _, authorized := range authorizedPubKeys {
				if ssh.KeysEqual(key, authorized) {
					matched = true
				}
			}
			return matched
		}
	}
	return nil
}

func (s *TailnetSSH) setupHostKey() error {
	if s.hostKeyFile != "" {
		return ssh.HostKeyFile(s.hostKeyFile)(&s.Server)
	}
	return nil
}

// Run starts listening for connections and runs, in perpetuity.
//
// If Run returns an error, that means it can no longer listen - these
// errors are fatal.
func (s *TailnetSSH) Run(ctx context.Context, quit <-chan os.Signal) error {
	var err error
	s.Server.Handler = s.handle

	srv := &tsnet.Server{
		Hostname:   s.serviceName,
		Dir:        s.stateDir,
		Logf:       logger.Discard,
		ControlURL: os.Getenv("TS_URL"),
	}
	if s.tsnetVerbose {
		srv.Logf = log.Printf
	}

	authKey := os.Getenv("TS_AUTHKEY")
	if authKey == "" {
		var tsClient *tailscale.Client
		authKey, tsClient, err = s.mintAuthKey(ctx)
		if err != nil {
			return fmt.Errorf("could not mint auth key: %w", err)
		}
		if s.deleteExisting {
			err = s.cleanupOldNodes(ctx, tsClient)
			if err != nil {
				return fmt.Errorf("could not clean up old nodes: %w", err)
			}
		}
	}
	srv.AuthKey = authKey

	_, err = srv.Up(ctx)
	if err != nil {
		return fmt.Errorf("could not connect to tailnet: %w", err)
	}
	defer srv.Close()

	listener, err := srv.Listen("tcp", ":22")
	if err != nil {
		return fmt.Errorf("could not listen on tailnet: %w", err)
	}

	terminated := false
	go func() {
		signal := <-quit
		terminated = true
		log.Printf("Received signal %v, terminating...", signal)
		srv.Close()
	}()

	log.Printf("starting ssh server on port :22...")
	err = s.Server.Serve(listener)
	if err != nil && !terminated {
		return fmt.Errorf("ssh server failed serving: %w", err)
	}
	return nil
}

var ErrNoAPIKeys = fmt.Errorf("neither TS_API_KEY, nor TS_API_CLIENT_ID and TS_API_CLIENT_SECRET are set")

func (s *TailnetSSH) setupTSClient(ctx context.Context) (*tailscale.Client, error) {
	tailscale.I_Acknowledge_This_API_Is_Unstable = true // needed in order to use API clients.
	apiKey := os.Getenv("TS_API_KEY")
	if apiKey != "" {
		return tailscale.NewClient("-", tailscale.APIKey(apiKey)), nil
	}

	clientID := os.Getenv("TS_API_CLIENT_ID")
	clientSecret := os.Getenv("TS_API_CLIENT_SECRET")
	baseURL := cmp.Or(os.Getenv("TS_BASE_URL"), "https://api.tailscale.com")
	tsClient := tailscale.NewClient("-", nil)
	tsClient.BaseURL = baseURL
	if clientID == "" || clientSecret == "" {
		return nil, ErrNoAPIKeys
	}
	credentials := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tsClient.BaseURL + "/api/v2/oauth/token",
		Scopes:       []string{"device"},
	}
	tsClient.HTTPClient = credentials.Client(ctx)
	return tsClient, nil
}

func (s *TailnetSSH) mintAuthKey(ctx context.Context) (string, *tailscale.Client, error) {
	tsClient, err := s.setupTSClient(ctx)
	if err != nil {
		return "", nil, err
	}
	caps := tailscale.KeyCapabilities{
		Devices: tailscale.KeyDeviceCapabilities{
			Create: tailscale.KeyDeviceCreateCapabilities{
				Tags:      s.tags,
				Ephemeral: true,
			},
		},
	}

	authkey, _, err := tsClient.CreateKey(ctx, caps)
	if err != nil {
		return "", nil, fmt.Errorf("minting a tailscale pre-authenticated key: %w", err)
	}
	return authkey, tsClient, nil
}

func (s *TailnetSSH) cleanupOldNodes(ctx context.Context, tsClient *tailscale.Client) error {
	devs, err := tsClient.Devices(ctx, tailscale.DeviceAllFields)
	if err != nil {
		return fmt.Errorf("listing existing devices: %w", err)
	}
	for _, dev := range devs {
		lastSeen, _ := time.Parse(time.RFC3339, dev.LastSeen)
		if dev.Hostname != s.serviceName {
			continue
		}
		recency := time.Since(lastSeen)
		if recency < s.maxNodeAge {
			log.Printf("node %q/%q was seen %v ago, not evicting.", dev.Name, dev.DeviceID, recency)
			continue
		}
		log.Printf("node %v was last seen %v, evicting", dev.Name, lastSeen)
		err := tsClient.DeleteDevice(ctx, dev.DeviceID)
		if err != nil {
			return fmt.Errorf("deleting device %q: %w", dev.DeviceID, err)
		}
	}
	return nil
}

func setWinsize(f *os.File, w, h int) {
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func (s *TailnetSSH) handle(sess ssh.Session) {
	// The command is passed in from the CLI, it's trusted by fiat:
	cmd := exec.Command(s.command[0], s.command[1:]...) // #nosec G204

	ptyReq, winCh, isPty := sess.Pty()
	if isPty {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		f, err := pty.Start(cmd)
		if err != nil {
			log.Printf("Error starting the command in a PTY: %v", err)
			return
		}
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			_, err := io.Copy(f, sess) // stdin
			if err != nil {
				log.Printf("Received error piping into process stdin, closing connection: %v", err)
				sess.Close()
			}
		}()
		_, _ = io.Copy(sess, f) // stdout; we don't care if there's an error
		err = cmd.Wait()
		if err != nil {
			log.Printf("Error waiting for the command: %v", err)
			return
		}
	} else {
		cmd.Stdin = sess
		cmd.Stdout = sess
		cmd.Stderr = sess
		err := cmd.Start()
		if err != nil {
			log.Printf("Error starting the command without a PTY: %v", err)
			return
		}
		err = cmd.Wait()
		if err != nil {
			log.Printf("Error waiting for the command: %v", err)
			return
		}
	}
}
