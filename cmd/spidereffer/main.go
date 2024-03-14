package main

import (
	"context"
	"log"
	"os"

	"github.com/antifuchs/spidereffer"
	// _ "tailscale.com/tsnet"
)

func main() {
	cli, err := spidereffer.TailnetSSHFromArgs(os.Args)
	if err != nil {
		log.Fatalf("Invalid command line: %v", err)
	}

	ctx := context.Background()
	log.Fatal(cli.Run(ctx))
}
