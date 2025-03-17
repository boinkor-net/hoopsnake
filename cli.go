package hoopsnake

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/peterbourgon/ff/v3/ffcli"
	gossh "golang.org/x/crypto/ssh"
)

type paths []string

func (p *paths) String() string {
	return strings.Join(*p, ", ")
}

func (p *paths) Set(value string) error {
	_, err := os.Stat(value)
	if err != nil {
		return fmt.Errorf("can not use %q: %w", value, err)
	}
	*p = append(*p, value)
	return nil
}

// TailnetSSH defines an SSH service that listens on a tailnet and runs a given shell program.
//
// The zero value of TailnetSSH is not a valid instance. Use
// TailnetSSHFromArgs to construct a valid one.
type TailnetSSH struct {
	ssh.Server
	serviceName        string
	stateDir           string
	hostKeyFile        string
	authorizedKeyFiles paths
	tsnetVerbose       bool
	deleteExisting     bool
	maxNodeAge         time.Duration
	prometheusAddr     string
	clientIDFile       string
	clientSecretFile   string
	tags               []string
	command            []string
	authorizedPubKeys  []gossh.PublicKey
	configTestOnly     bool
}

var ErrMissingServiceName = fmt.Errorf("service name must be set via -name")
var ErrMissingACLTag = fmt.Errorf("service must have at least one ACL tag")
var ErrMissingCommand = fmt.Errorf("ssh connections must run a command - pass that as the remaining cli arguments")
var ErrMissingOauthCredential = fmt.Errorf("either none or both of -clientIdFile and -clientSecretFile must be passed")

// / TailnetSSHFromArgs parses CLI arguments and constructs a validated TailnetSSH structure.
func TailnetSSHFromArgs(args []string) (*TailnetSSH, error) {
	s := &TailnetSSH{}
	fs := flag.NewFlagSet("hoopsnake", flag.ExitOnError)
	fs.StringVar(&s.serviceName, "name", "", "Machine name to set on the tailnet")
	fs.StringVar(&s.stateDir, "stateDir", "", "Directory where hoopsnake stores tsnet state")
	fs.StringVar(&s.hostKeyFile, "hostKey", "", "Pathname to the SSH host key")
	fs.Var(&s.authorizedKeyFiles, "authorizedKeys", "Pathnames to file listing authorized client keys (can be specified multiple times)")
	fs.BoolVar(&s.tsnetVerbose, "tsnetVerbose", false, "Log tsnet messages verbosely")
	fs.BoolVar(&s.deleteExisting, "deleteExisting", false, "Delete any down node with a conflicting name, if one exists")
	fs.DurationVar(&s.maxNodeAge, "maxNodeAge", 30*time.Second, "Matching node must be offline at least this long if -deleteExisting is set")
	fs.StringVar(&s.prometheusAddr, "prometheusAddr", ":9021", "Address on the tailnet node where prometheus requests get answered")
	fs.StringVar(&s.clientIDFile, "clientIdFile", "", "File containing the tailscale OAUTH2 client ID")
	fs.StringVar(&s.clientSecretFile, "clientSecretFile", "", "File containing the tailscale OAUTH2 client secret")
	fs.BoolVar(&s.configTestOnly, "configtest", false, "Validate that authkeys can be generated. Exits 0 if everything works.")

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
	if (s.clientIDFile != "" && s.clientSecretFile == "") || (s.clientIDFile == "" && s.clientSecretFile != "") {
		return nil, ErrMissingOauthCredential
	}

	s.command = root.FlagSet.Args()
	if len(s.command) == 0 {
		return nil, ErrMissingCommand
	}

	return s, nil
}

// getCredential retrieves the named credential from the process
// environment.
//
// If the credential can't be retrieved from any of these sources,
// getCredential returns a second value of false.
//
// If the credential exists on the environment, it is unset from the
// process environment immediately, to prevent polluting downstream
// programs' environments.
func getCredential(name string) (string, bool) {
	// from environment directly:
	fromEnv, ok := os.LookupEnv(name)
	if ok {
		os.Unsetenv(name)
		return fromEnv, true
	}
	return "", false
}
