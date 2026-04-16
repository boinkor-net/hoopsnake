package hoopsnake

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"tailscale.com/client/tailscale/v2"
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

func (s *TailnetSSH) setupTSClient() (*tailscale.Client, error) {
	apiKey, ok := getCredential("TS_API_KEY")
	if ok {
		log.Printf("WARNING: Using TS_API_KEY, the most inconvenient and insecure way to authenticate to tailscale. Please use oauth clients instead.")
		return &tailscale.Client{Tailnet: "-", APIKey: apiKey}, nil
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

	baseURLStr := cmp.Or(os.Getenv("TS_BASE_URL"), "https://api.tailscale.com")
	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		return nil, fmt.Errorf("could not parse TS_BASE_URL (%#v) as a URL: %w", baseURLStr, err)
	}

	tsClient := &tailscale.Client{
		Tailnet: "-",
	}
	tsClient.BaseURL = baseURL
	tsClient.Auth = &tailscale.OAuth{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"device"},
	}
	return tsClient, nil
}

func (s *TailnetSSH) mintAuthKey(ctx context.Context) (string, *tailscale.Client, error) {
	tsClient, err := s.setupTSClient()
	if err != nil {
		return "", nil, err
	}
	ckr := tailscale.CreateKeyRequest{}
	ckr.Capabilities.Devices.Create.Tags = s.tags
	ckr.Capabilities.Devices.Create.Ephemeral = true
	ckr.Capabilities.Devices.Create.Preauthorized = s.preauthorized
	authkey, err := tsClient.Keys().CreateAuthKey(ctx, ckr)
	if err != nil {
		return "", nil, fmt.Errorf("minting a tailscale pre-authenticated key for tags %v: %w", s.tags, err)
	}
	return authkey.Key, tsClient, nil
}

func (s *TailnetSSH) cleanupOldNodes(ctx context.Context, tsClient *tailscale.Client) error {
	devs, err := tsClient.Devices().List(ctx, tailscale.WithFields(tailscale.IncludeFieldsAll))
	if err != nil {
		return fmt.Errorf("listing existing devices: %w", err)
	}
	for _, dev := range devs {
		if dev.Hostname != s.serviceName {
			continue
		}
		recency := time.Since(dev.LastSeen.Time)
		if recency < s.maxNodeAge {
			log.Printf("node %q/%q was seen %v ago, not evicting.", dev.Name, dev.ID, recency)
			continue
		}
		log.Printf("node %v was last seen %v, evicting", dev.Name, dev.LastSeen.Time)
		err := tsClient.Devices().Delete(ctx, dev.ID)
		if err != nil {
			return fmt.Errorf("deleting device %q: %w", dev.ID, err)
		}
	}
	return nil
}
