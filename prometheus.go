package hoopsnake

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"tailscale.com/tsnet"
)

func (s *TailnetSSH) setupPrometheus(srv *tsnet.Server) error {
	if s.prometheusAddr == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	listener, err := srv.Listen("tcp", s.prometheusAddr)
	if err != nil {
		return fmt.Errorf("could not listen on prometheus address %v: %w", s.prometheusAddr, err)
	}
	go func() {
		server := http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 1 * time.Second,
		}
		log.Printf("Failed to listen on prometheus address: %v", server.Serve(listener))
		os.Exit(20)
	}()
	listenAddr := s.prometheusAddr
	if listenAddr[0] == ':' {
		v4, _ := srv.TailscaleIPs()
		listenAddr = v4.String() + listenAddr
	}
	log.Printf("Serving prometheus metrics at http://%s/metrics", listenAddr)
	return nil
}
