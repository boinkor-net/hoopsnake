package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/boinkor-net/hoopsnake"
)

func main() {
	cli, err := hoopsnake.TailnetSSHFromArgs(os.Args)
	if err != nil {
		log.Fatalf("Invalid command line: %v", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	ctx := context.Background()
	err = cli.Run(ctx, c)
	if err != nil {
		log.Fatal(err)
	}
}
