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
	// An install that has run before has a portal token or a rules.json. Its
	// blocking behavior is carried over exactly (see openPolicy).
	existing := fileExists(filepath.Join(cfg.DataDir, "portal-token")) || fileExists(filepath.Join(cfg.DataDir, "rules.json"))
	token, err := portal.LoadOrCreateToken(cfg.DataDir)
	if err != nil {
		return err
	}
	if printToken {
		fmt.Fprintln(stdout, token)
		return nil
	}

	filter := dnsengine.NewFilter()
	policy, err := openPolicy(cfg, filter, existing)
	if err != nil {
		return err
	}
	geoBlock, err := dnsengine.OpenGeoBlockStore(filepath.Join(cfg.DataDir, "geoblock.json"))
	if err != nil {
		return err
	}
	listMgr := dnsengine.NewScopedListManager(filter, policy, cfg.DataDir, cfg.DNS.ProtectedDomains)
	pool, err := dnsengine.NewPool(cfg.DNS.Upstreams, dnsengine.WithBootstrap(cfg.DNS.Bootstrap...))
	if err != nil {
		return err
	}
	// Runtime edits made in the portal live in upstreams.json and, once it
	// exists, win over dns.upstreams.
	ups := dnsengine.OpenUpstreamStore(filepath.Join(cfg.DataDir, "upstreams.json"), pool)
	if err := ups.LoadProblem(); err != nil {
		log.Printf("upstreams: ignoring the saved list, using the configuration: %v", err)
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

	registry, stopDevices, err := startDevices(ctx, cfg, engine)
	if err != nil {
		return err
	}
	defer func() { cancel(); stopDevices() }() // sources stop, then the registry is saved

	prefs, err := settings.Open(filepath.Join(cfg.DataDir, "settings.json"))
	if err != nil {
		return err
	}
	deps := portal.Deps{Engine: engine, Lists: listMgr, Policy: policy, Devices: registry, Upstreams: ups,
		Token: token, Version: version, Settings: prefs, GeoBlock: geoBlock}

	var mapLocator *geo.Locator
	var asnLocator *geo.ASNLocator
	if cfg.Map.Enabled {
		mapLocator = &geo.Locator{}
		engine.Geo = mapLocator
		mgr := geo.NewManager(mapLocator, cfg.DataDir)
		mgr.BaseURL = cfg.Map.DatabaseURL
		deps.Geo = mgr
		go mgr.Run(ctx)
		if cfg.Map.AutoHome {
			auto := &geo.AutoHome{Detector: geo.NewWANDetector(), Placer: mapLocator, Store: prefs}
			deps.DetectHome = auto.Once
			go auto.Run(ctx)
		}
		asnLocator = &geo.ASNLocator{}
		asnMgr := geo.NewASNManager(asnLocator, cfg.DataDir)
		asnMgr.BaseURL = cfg.Map.DatabaseURL
		go asnMgr.Run(ctx)
	}
	// Country blocking depends on the same shared Locator: it reuses
	// whatever engine.Geo already placed on the globe, so it never opens a
	// second database and degrades to a no-op when [map] is off (see
	// startGeoBlock and docs/GEOBLOCK.md).
	startGeoBlock(engine, geoBlock, registry, mapLocator)

	if cfg.Classify.Enabled {
		if _, err := startClassify(ctx, cfg, engine, registry, asnLocator); err != nil {
			return err
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// catalogOverride replaces the shipped catalog. It is a test seam: production
// leaves it nil.
var catalogOverride *dnsengine.CatalogSet

// openPolicy opens <data>/policy.json. On first run it is seeded from the old
// files: rules.json (allow, block and policy switches) and the config's
// [[lists]], so an install that predates the policy store keeps exactly the
// blocking it had. A brand new install also gets the catalog's recommended
// items at network scope (protection is opt-out). The recommended items are
// left off when the install already existed, when no_default_lists is set, or
// when the config defines its own [[lists]]: in all three the user chose what
// is blocked. After first run policy.json is the only source of truth.
func openPolicy(cfg config.Config, filter *dnsengine.Filter, existing bool) (*dnsengine.PolicyStore, error) {
	var lists []dnsengine.ListConfig
	for _, l := range cfg.Lists {
		lists = append(lists, dnsengine.ListConfig{Name: l.Name, URL: l.URL})
	}
	return dnsengine.OpenPolicyStore(filepath.Join(cfg.DataDir, "policy.json"), filter, dnsengine.PolicyOptions{
		Catalog: catalogOverride,
		Legacy: &dnsengine.LegacyConfig{
			RulesPath: filepath.Join(cfg.DataDir, "rules.json"), Lists: lists, BlockPrivateRelay: cfg.Privacy.BlockPrivateRelay,
		},
		ExtraProtected: cfg.DNS.ProtectedDomains,
		NoRecommended:  existing || cfg.NoDefaultLists || !cfg.ListsAreDefault(),
	})
}

// argonTime and argonMemKiB override the passphrase key's Argon2id cost.
// Production leaves them zero (the strong defaults); tests lower them.
var argonTime, argonMemKiB uint32

// openHistory opens the encrypted history with the configured key source.
func openHistory(cfg config.Config) (*history.Store, error) {
	dir := filepath.Join(cfg.DataDir, "history")
	var keys history.KeySource
	if cfg.History.KeySource == "passphrase" {
		keys = &history.PassphraseKey{Dir: filepath.Join(dir, "keys"), Time: argonTime, MemoryKiB: argonMemKiB}
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
