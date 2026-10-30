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
	"shepherd/internal/geo"
	"shepherd/internal/history"
	"shepherd/internal/portal"
	"shepherd/internal/settings"
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

	prefs, err := settings.Open(filepath.Join(cfg.DataDir, "settings.json"))
	if err != nil {
		return err
	}
	deps := portal.Deps{Engine: engine, Lists: listMgr, Rules: rules, Token: token, Version: version, Settings: prefs}

	if cfg.Map.Enabled {
		var locator geo.Locator
		engine.Geo = &locator
		mgr := geo.NewManager(&locator, cfg.DataDir)
		mgr.BaseURL = cfg.Map.DatabaseURL
		deps.Geo = mgr
		go mgr.Run(ctx)
		if cfg.Map.AutoHome {
			auto := &geo.AutoHome{Detector: geo.NewWANDetector(), Placer: &locator, Store: prefs}
			deps.DetectHome = auto.Once
			go auto.Run(ctx)
		}
	}

	if cfg.History.Mode == "encrypted" {
		store, err := openHistory(cfg)
		if err != nil {
			return err
		}
		defer store.Close()
		if pass := os.Getenv("SHEPHERD_HISTORY_PASSPHRASE"); pass != "" && store.Locked() {
			if err := store.Unlock(pass); err != nil {
				log.Printf("history: unlocking from SHEPHERD_HISTORY_PASSPHRASE: %v", err)
			}
		}
		if !store.Locked() { // bring the recent past back into the live view after a restart
			past, _, _ := store.Query(dnsengine.HistoryQuery{Limit: cfg.DNS.LogSize})
			engine.Log.Preload(past)
		}
		engine.Log.SetSink(store.Append)
		go store.Run(ctx)
		deps.History = store
	}

	srv := portal.New(deps)
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

// openHistory opens the encrypted history with the configured key source.
func openHistory(cfg config.Config) (*history.Store, error) {
	dir := filepath.Join(cfg.DataDir, "history")
	var keys history.KeySource
	if cfg.History.KeySource == "passphrase" {
		keys = &history.PassphraseKey{Dir: filepath.Join(dir, "keys")}
	} else {
		path := cfg.History.KeyFile
		if path == "" {
			path = filepath.Join(dir, "history.key")
		}
		keys = &history.FileKey{Path: path}
	}
	return history.Open(history.Options{
		Dir: filepath.Join(dir, "store"), Keys: keys,
		RetentionDays: cfg.History.RetentionDays, MaxBytes: int64(cfg.History.MaxMB) << 20,
	})
}
