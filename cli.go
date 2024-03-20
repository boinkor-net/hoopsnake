package hoopsnake

import (
	"context"
	"flag"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/peterbourgon/ff/v3/ffcli"
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
	prometheusAddr    string
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
	fs.StringVar(&s.prometheusAddr, "prometheusAddr", ":9021", "Address on the tailnet node where prometheus requests get answered")

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
