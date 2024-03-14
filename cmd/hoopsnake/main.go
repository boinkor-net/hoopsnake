package main

import (
	"context"
	"log"
	"os"

	"github.com/antifuchs/hoopsnake"
	// _ "tailscale.com/tsnet"
)

func main() {
	cli, err := hoopsnake.TailnetSSHFromArgs(os.Args)
	if err != nil {
		log.Fatalf("Invalid command line: %v", err)
	}

	ctx := context.Background()
	log.Fatal(cli.Run(ctx))
}
