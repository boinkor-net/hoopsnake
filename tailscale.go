package hoopsnake

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

var ErrNoAPIKeys = fmt.Errorf("neither TS_API_KEY, nor TS_API_CLIENT_ID and TS_API_CLIENT_SECRET are set")

func (s *TailnetSSH) tsnetServer(ctx context.Context) (*tsnet.Server, error) {
	state, err := mem.New(nil, "")
	if err != nil {
		return nil, fmt.Errorf("allocating in-memory state: %w", err)
	}
	srv := &tsnet.Server{
		Store:      state,
		Ephemeral:  true,
		Hostname:   s.serviceName,
		Dir:        s.stateDir,
		Logf:       logger.Discard,
		ControlURL: os.Getenv("TS_BASE_URL"),
	}
	if s.tsnetVerbose {
		srv.Logf = log.Printf
	}

	authKey, ok := getCredential("TS_AUTHKEY")
	if !ok {
		var tsClient *tailscale.Client
		authKey, tsClient, err = s.mintAuthKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("could not mint auth key: %w", err)
		}
		if s.deleteExisting {
			err = s.cleanupOldNodes(ctx, tsClient)
			if err != nil {
				return nil, fmt.Errorf("could not clean up old nodes: %w", err)
			}
		}
	}
	srv.AuthKey = authKey
	return srv, nil
}

func (s *TailnetSSH) setupTSClient(ctx context.Context) (*tailscale.Client, error) {
	tailscale.I_Acknowledge_This_API_Is_Unstable = true // needed in order to use API clients.
	apiKey, ok := getCredential("TS_API_KEY")
	if ok {
		log.Printf("WARNING: Using TS_API_KEY, the most inconvenient and insecure way to authenticate to tailscale. Please use oauth clients instead.")
		return tailscale.NewClient("-", tailscale.APIKey(apiKey)), nil
	}

	var clientID, clientSecret string
	if s.clientIDFile != "" && s.clientSecretFile != "" {
		cidB, err := os.ReadFile(s.clientIDFile)
		if err != nil {
			return nil, fmt.Errorf("could not read client ID %q: %w", s.clientIDFile, err)
		}
		csB, err := os.ReadFile(s.clientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("could not read client secret %q: %w", s.clientIDFile, err)
		}
		clientID = strings.TrimSpace(string(cidB))
		clientSecret = strings.TrimSpace(string(csB))
	} else {
		var idOk, secOk bool
		clientID, idOk = getCredential("TS_API_CLIENT_ID")
		clientSecret, secOk = getCredential("TS_API_CLIENT_SECRET")
		if !idOk || !secOk {
			return nil, ErrNoAPIKeys
		}
	}

	baseURL := cmp.Or(os.Getenv("TS_BASE_URL"), "https://api.tailscale.com")
	tsClient := tailscale.NewClient("-", nil)
	tsClient.BaseURL = baseURL
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
		return "", nil, fmt.Errorf("minting a tailscale pre-authenticated key for tags %v: %w", s.tags, err)
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
