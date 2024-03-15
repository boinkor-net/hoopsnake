package hoopsnake

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/client/tailscale"
)

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
