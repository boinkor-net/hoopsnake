package spidereffer

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/peterbourgon/ff/v3/ffcli"
	gossh "golang.org/x/crypto/ssh"
)

// TailnetSSH defines an SSH service that listens on a tailnet and runs a given shell program.
//
// The zero value of TailnetSSH is not a valid instance. Use
// TailnetSSHFromArgs to construct a valid one.
type TailnetSSH struct {
	ssh.Server
	serviceName       string
	hostKeyFile       string
	authorizedKeyFile string
	command           []string
}

// / TailnetSSHFromArgs parses CLI arguments and constructs a validated TailnetSSH structure.
func TailnetSSHFromArgs(args []string) (*TailnetSSH, error) {
	s := &TailnetSSH{}
	fs := flag.NewFlagSet("spidereffer", flag.ExitOnError)
	fs.StringVar(&s.serviceName, "name", "", "Machine name to set on the tailnet")
	fs.StringVar(&s.hostKeyFile, "hostKey", "", "Pathname to the SSH host key")
	fs.StringVar(&s.authorizedKeyFile, "authorizedKeys", "", "Pathname to a file listing authorized client keys")
	root := &ffcli.Command{
		ShortUsage: fmt.Sprintf("%s -name <serviceName> [flags] <command> [argv ...]", path.Base(args[0])),
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

	s.Server.Addr = "127.0.0.1:2222"
	log.Printf("starting ssh server on port %s...", s.Server.Addr)
	return s.Server.ListenAndServe()
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
