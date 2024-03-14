package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	// _ "tailscale.com/tsnet"
)

var serviceName = flag.String("name", "", "Machine name to set on the tailnet")
var hostKey = flag.String("hostKey", "", "Pathname to the SSH host key")
var authorizedKeys = flag.String("authorizedKeys", "", "Pathname to a file listing authorized client keys")

func main() {
	flag.Parse()
	authorizedKeysBytes, err := os.ReadFile(*authorizedKeys)
	if err != nil {
		log.Fatalf("Could not read authorized keys file %q: %v", *authorizedKeys, err)
	}
	var authorizedPubKeys []gossh.PublicKey
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Fatalf("Could not parse authorized key: %v", err)
		}

		authorizedPubKeys = append(authorizedPubKeys, pubKey)
		authorizedKeysBytes = rest
	}

	ssh.Handle(func(s ssh.Session) {
		authorizedKey := gossh.MarshalAuthorizedKey(s.PublicKey())
		io.WriteString(s, fmt.Sprintf("public key used by %s:\n", s.User()))
		s.Write(authorizedKey)
	})
	publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
		log.Printf("Attempting auth for user %q with public key %q", ctx.User(), gossh.MarshalAuthorizedKey(key))
		matched := false
		for _, authorized := range authorizedPubKeys {
			if ssh.KeysEqual(key, authorized) {
				matched = true
			}
		}
		return matched
	})
	log.Println("starting ssh server on port 2222...")
	log.Fatal(ssh.ListenAndServe("127.0.0.1:2222", nil, publicKeyOption))
}
