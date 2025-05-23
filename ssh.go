package hoopsnake

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/reiver/go-cast"
	gossh "golang.org/x/crypto/ssh"
)

var (
	authentications = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "hoopsnake_authentications",
		Help: "Number of authentications attempted",
	}, []string{"user", "pubkey_fpr", "pubkey", "success"})
)

func (s *TailnetSSH) setupAuthorizedKeys() error {
	for _, path := range s.authorizedKeyFiles {
		authorizedKeysBytes, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("Could not read authorized keys file %q: %v", path, err)
		}
		for len(authorizedKeysBytes) > 0 {
			pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
			if err != nil {
				return fmt.Errorf("Could not parse authorized key: %w", err)
			}

			s.authorizedPubKeys = append(s.authorizedPubKeys, pubKey)
			authorizedKeysBytes = rest
		}
	}
	if len(s.authorizedPubKeys) > 0 {
		s.Server.PublicKeyHandler = s.validatePubkey
	}
	return nil
}

func (s *TailnetSSH) validatePubkey(ctx ssh.Context, key ssh.PublicKey) bool {
	log.Printf("Attempting auth for user %q with public key %q", ctx.User(), gossh.MarshalAuthorizedKey(key))
	matched := false
	for _, authorized := range s.authorizedPubKeys {
		if ssh.KeysEqual(key, authorized) {
			matched = true
		}
	}
	authentications.With(prometheus.Labels{
		"user":       ctx.User(),
		"pubkey":     string(gossh.MarshalAuthorizedKey(key)),
		"pubkey_fpr": gossh.FingerprintSHA256(key),
		"success":    strconv.FormatBool(matched),
	}).Inc()
	return matched
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
	var err error
	s.Server.Handler = s.handle

	srv, err := s.tsnetServer(ctx)
	if err != nil {
		return fmt.Errorf("could not setup a tsnet server: %w", err)
	}

	// Do not shut down the tsnet server as soon as we're meant
	// to close client connections; it shuts down after the
	// SSH server terminates.
	netCtx := context.WithoutCancel(ctx)
	_, err = srv.Up(netCtx)
	if err != nil {
		return fmt.Errorf("could not connect to tailnet: %w", err)
	}
	defer srv.Close()

	listener, err := srv.Listen("tcp", ":22")
	if err != nil {
		return fmt.Errorf("could not listen on tailnet: %w", err)
	}

	if s.configTestOnly {
		log.Printf("Configuration tested ok")
		srv.Close()
		return nil
	}

	err = s.setupPrometheus(ctx, srv)
	if err != nil {
		log.Printf("Setting up prometheus failed, but continuing anyway: %v", err)
	}
	log.Printf("starting ssh server on port :22...")
	go func() {
		<-ctx.Done()
		_ = s.Server.Close()
	}()
	err = s.Server.Serve(listener)
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("ssh server failed serving: %w", err)
	}
	return nil
}

func setWinsize(f *os.File, width, height int) {
	w, err := cast.Uint16(width)
	if err != nil {
		return
	}
	h, err := cast.Uint16(height)
	if err != nil {
		return
	}
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{h, w, 0, 0})))
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
