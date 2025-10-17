package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kurrent-io/dns-sidecar/dns"
)

func run(ctx context.Context, configPath string) error {
	configByts, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config file (%v): %w", configPath, err)
	}

	config := dns.Config {
		Listen: "127.0.0.1:53",
	}
	err = json.Unmarshal(configByts, &config)
	if err != nil {
		return fmt.Errorf("parsing config file (%v): %w", configPath, err)
	}

	if config.Resolver == "" {
		return errors.New("resolver is required")
	}

	lookupFn, err := dns.MakeLookupFunc(config.Rules)
	if err != nil {
		return err
	}

	return dns.DNS(ctx, config.Listen, config.Resolver, lookupFn)
}

func SignalCancelContext(base context.Context) context.Context {
	ctx, cancel := context.WithCancel(base)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer cancel()
		<-sigs
	}()
	return ctx
}

func main() {
	ctx := SignalCancelContext(context.Background())

	configPath := "/dns.conf"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	err := run(ctx, configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
