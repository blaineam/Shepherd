// SPDX-License-Identifier: AGPL-3.0-or-later

// Command shepherd runs the Shepherd network guardian.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"shepherd/internal/config"
	"shepherd/internal/dnsengine"
	"shepherd/internal/portal"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("shepherd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "shepherd.toml", "path to the configuration file")
	showVersion := fs.Bool("version", false, "print the version and exit")
	printToken := fs.Bool("print-token", false, "print the portal access token and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "shepherd", version)
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *cfgPath, *printToken, stdout); err != nil {
		fmt.Fprintf(stderr, "shepherd: %v\n", err)
		return 1
	}
	return 0
}

// run starts every service and blocks until ctx ends or one fails to start.
func run(ctx context.Context, cfgPath string, printToken bool, stdout io.Writer) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return err
	}
	token, err := portal.LoadOrCreateToken(cfg.DataDir)
	if err != nil {
		return err
	}
	if printToken {
		fmt.Fprintln(stdout, token)
		return nil
	}

	filter := dnsengine.NewFilter()
	rules, err := dnsengine.LoadRules(filepath.Join(cfg.DataDir, "rules.json"), filter,
		map[string]bool{dnsengine.PolicyPrivateRelay: cfg.Privacy.BlockPrivateRelay})
	if err != nil {
		return err
	}
	var lists []dnsengine.ListConfig
	for _, l := range cfg.Lists {
		lists = append(lists, dnsengine.ListConfig{Name: l.Name, URL: l.URL})
	}
	listMgr := dnsengine.NewListManager(filter, cfg.DataDir, lists, cfg.DNS.ProtectedDomains)
	pool, err := dnsengine.NewPool(cfg.DNS.Upstreams)
	if err != nil {
		return err
	}
	engine := &dnsengine.Engine{
		Filter: filter, Pool: pool, Cache: dnsengine.NewCache(cfg.DNS.CacheSize),
		Log: dnsengine.NewQueryLog(cfg.DNS.LogSize), Stats: dnsengine.NewStats(),
		BlockNXDOMAIN: cfg.DNS.BlockMode == "nxdomain",
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go pool.Probe(ctx, time.Duration(cfg.DNS.ProbeIntervalSeconds)*time.Second)
	go listMgr.Run(ctx, 24*time.Hour)

	srv := portal.New(portal.Deps{Engine: engine, Lists: listMgr, Rules: rules, Token: token, Version: version})
	httpSrv := &http.Server{Addr: cfg.Portal.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	portalErr := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			portalErr <- fmt.Errorf("portal: %w", err)
			cancel()
		}
	}()
	defer httpSrv.Shutdown(context.Background())

	log.Printf("shepherd %s: dns on %v, portal on http://%s", version, cfg.DNS.Listen, cfg.Portal.Listen)
	log.Printf("portal token is in %s (or run with -print-token)", filepath.Join(cfg.DataDir, "portal-token"))
	if err := dnsengine.Serve(ctx, cfg.DNS.Listen, engine); err != nil {
		return err
	}
	select {
	case err := <-portalErr:
		return err
	default:
		return nil
	}
}
