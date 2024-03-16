package hoopsnake

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/client/tailscale"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

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
		ControlURL: os.Getenv("TS_BASE_URL"),
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
