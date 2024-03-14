package spidereffer

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
	tags              []string
	command           []string
}

// / TailnetSSHFromArgs parses CLI arguments and constructs a validated TailnetSSH structure.
func TailnetSSHFromArgs(args []string) (*TailnetSSH, error) {
	s := &TailnetSSH{}
	fs := flag.NewFlagSet("spidereffer", flag.ExitOnError)
	fs.StringVar(&s.serviceName, "name", "", "Machine name to set on the tailnet")
	fs.StringVar(&s.stateDir, "stateDir", "", "Directory where spidereffer stores tsnet state")
	fs.StringVar(&s.hostKeyFile, "hostKey", "", "Pathname to the SSH host key")
	fs.StringVar(&s.authorizedKeyFile, "authorizedKeys", "", "Pathname to a file listing authorized client keys")
	fs.BoolVar(&s.tsnetVerbose, "tsnetVerbose", false, "Log tsnet messages verbosely")
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
		return nil, fmt.Errorf("service name must be set via -name")
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
		return nil, fmt.Errorf("service must have at least one ACL tag")
	}

	s.command = root.FlagSet.Args()
	if len(s.command) == 0 {
		return nil, fmt.Errorf("ssh connections must run a command - pass that as the remaining cli arguments")
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
func (s *TailnetSSH) Run(ctx context.Context) error {
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
	clientID := os.Getenv("TS_API_CLIENT_ID")
	clientSecret := os.Getenv("TS_API_CLIENT_SECRET")
	if clientID != "" && clientSecret != "" {
		authKey, err := s.setupOAuth(ctx, clientID, clientSecret)
		if err != nil {
			return fmt.Errorf("could not setup with oauth2: %w", err)
		}
		srv.AuthKey = authKey
	}

	_, err := srv.Up(ctx)
	if err != nil {
		return fmt.Errorf("could not connect to tailnet: %w", err)
	}
	listener, err := srv.Listen("tcp", ":22")
	if err != nil {
		return fmt.Errorf("could not listen on tailnet: %w", err)
	}
	log.Printf("starting ssh server on port :22...")
	return s.Server.Serve(listener)
}

// setupOAuth uses an OAuth2 client ID&secret to mint an API key and
// to ensure the requested node name is free. It returns the created
// auth key.
func (s *TailnetSSH) setupOAuth(ctx context.Context, clientID, clientSecret string) (string, error) {
	// Welp, tailscale do not want external folks to use this, but I don't _not_ want to use this:
	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	baseURL := cmp.Or(os.Getenv("TS_BASE_URL"), "https://api.tailscale.com")
	credentials := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     baseURL + "/api/v2/oauth/token",
		Scopes:       []string{"device"},
	}
	tsClient := tailscale.NewClient("-", nil)
	tsClient.HTTPClient = credentials.Client(ctx)
	tsClient.BaseURL = baseURL
	caps := tailscale.KeyCapabilities{
		Devices: tailscale.KeyDeviceCapabilities{
			Create: tailscale.KeyDeviceCreateCapabilities{
				Tags: s.tags,
			},
		},
	}

	authkey, _, err := tsClient.CreateKey(ctx, caps)
	if err != nil {
		return "", fmt.Errorf("minting a tailscale pre-authenticated key: %w", err)
	}

	// Now that we have an auth key, clean out the node list so our name is free:
	devs, err := tsClient.Devices(ctx, tailscale.DeviceAllFields)
	if err != nil {
		return "", fmt.Errorf("listing existing devices: %w", err)
	}
	for _, dev := range devs {
		if dev.Hostname == s.serviceName {
			log.Println("There already is a device named %q: %v", s.serviceName, dev.LastSeen)
		}
	}

	return authkey, nil
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func (s *TailnetSSH) handle(sess ssh.Session) {
	cmd := exec.Command(s.command[0], s.command[1:]...)
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
			io.Copy(f, sess) // stdin
		}()
		io.Copy(sess, f) // stdout
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
