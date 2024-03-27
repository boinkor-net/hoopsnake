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

	ctx := context.Background()
	ctx, terminate := context.WithCancel(ctx)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		signal := <-c
		log.Printf("Received signal %v, terminating...", signal)
		terminate()
	}()

	err = cli.Run(ctx)
	if err != nil {
		log.Fatal(err)
	}
}
