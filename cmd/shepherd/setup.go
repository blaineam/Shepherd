// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"shepherd/internal/config"
	"shepherd/internal/dnsengine"
	"shepherd/internal/routerusage"
	"shepherd/internal/secrets"
	"shepherd/internal/selftest"
	"shepherd/internal/setup"
)

// probeTimeout bounds the one probe the setup page makes per resolver. It is
// generous because a cold DoT or DoH upstream has to finish bootstrap, TCP
// and TLS before it can answer, and calling that a failure would send the
// owner off to debug a resolver that works.
const probeTimeout = 10 * time.Second

// setupPort is where first-run setup listens: on every address rather than
// loopback, because the whole point is that the person installing Shepherd
// on a NAS can reach it from their laptop, with the one-time token in the
// printed URL keeping the rest of the network out.
//
// It is deliberately not the portal's own 8787. Setup stays up after the
// file is written, while Shepherd starts on it, so the two listeners exist
// at the same time and cannot share a port.
const setupPort = 8788

// setupSeams replaces the setup flow's outside edges. It is a test seam,
// like catalogOverride: production leaves it nil.
var setupSeams func(*setup.Server)

// newSetupServer builds first-run setup with the real host, resolver and
// router implementations behind it.
func newSetupServer(cfgPath string) (*setup.Server, error) {
	s, err := setup.NewServer(&setup.Server{
		ConfigPath:    cfgPath,
		Categories:    setupCategories(),
		HostAddrs:     setup.HostAddrs,
		PortFree:      setup.PortFree,
		TestUpstream:  testUpstream,
		ConnectRouter: connectUniFi,
	})
	if err != nil {
		return nil, err
	}
	if setupSeams != nil {
		setupSeams(s)
	}
	return s, nil
}

// serveSetup serves the setup page and returns the file it wrote, or "" if
// the process was asked to stop first. The server keeps running for the
// caller to hand a started Shepherd to, and to Close.
func serveSetup(ctx context.Context, s *setup.Server, port int) (string, error) {
	// Something else may already own the preferred port -- on a NAS that
	// is common, and binding the wildcard can succeed while another
	// process still owns loopback, so the page would appear to come up
	// and then answer somebody else's service. Check first, and move to
	// a port the operating system picks rather than failing to start.
	if port != 0 && !setup.PortFree("127.0.0.1", port) {
		log.Printf("setup: something already listens on port %d, so setup is taking a free port instead", port)
		port = 0
	}
	addr := net.JoinHostPort("", strconv.Itoa(port))
	return s.Run(ctx, addr, log.Printf)
}

// setupIfUnconfigured runs setup when there is no configuration file, which
// is what makes the first start of a new install a guided one. An install
// that has a file never sees it; "shepherd setup" is how it is asked for
// again.
//
// The returned server is still serving: setup's second half -- proving DNS
// works, handing over the portal token, switching categories on, pointing
// the router here -- can only happen once Shepherd is up on the file that
// was just written, so run() calls Started on it and closes it at the end.
// Nil means there was nothing to set up, or setup could not run.
//
// A failure to bring up the setup listener is deliberately not fatal: a
// port already in use must not stop an install whose defaults would
// otherwise work, so it is logged and Shepherd starts on the defaults.
func setupIfUnconfigured(ctx context.Context, cfgPath string) *setup.Server {
	if fileExists(cfgPath) {
		return nil
	}
	s, err := newSetupServer(cfgPath)
	if err != nil {
		log.Printf("setup: %v", err)
		return nil
	}
	written, err := serveSetup(ctx, s, setupPort)
	if err != nil {
		log.Printf("setup: %v", err)
		log.Printf("setup: starting on the defaults instead (loopback only); run \"shepherd setup\" to configure it")
		return nil
	}
	if written == "" {
		if ctx.Err() == nil {
			log.Printf("setup: nothing was written; starting on the defaults (loopback only)")
		}
		s.Close()
		return nil
	}
	log.Printf("setup: wrote %s; starting Shepherd on it", written)
	return s
}

// testUpstream probes one candidate resolver the way the portal's own test
// button does, by asking it a unique uncached name and waiting for an
// answer. The pool it borrows to do that is thrown away: nothing is
// configured yet, and Pool.Test deliberately touches no pool state.
func testUpstream(ctx context.Context, addr string) error {
	def := config.Default().DNS
	pool, err := dnsengine.NewPool(def.Upstreams, dnsengine.WithBootstrap(def.Bootstrap...))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	res := pool.Test(ctx, addr)
	if res.OK {
		return nil
	}
	if res.Err != "" {
		return errors.New(res.Err)
	}
	return fmt.Errorf("answered %s", res.Rcode)
}

// connectUniFi reads the controller once to prove the credentials work, then
// keeps them in the data directory's secrets.json, which is the same place
// and the same format the portal's Bandwidth screen uses. Verifying first
// matters more here than in the portal: the owner is about to walk away and
// leave a daemon running, and a password typo would otherwise surface days
// later as an empty Bandwidth screen.
func connectUniFi(ctx context.Context, dataDir string, c setup.RouterConn) error {
	src, err := routerusage.NewUniFi(routerusage.UniFiConfig{
		BaseURL:         c.BaseURL,
		Username:        c.Username,
		Password:        c.Password,
		Site:            c.Site,
		AllowSelfSigned: c.AllowSelfSigned,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if _, err := src.Poll(ctx); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	store, err := secrets.Open(filepath.Join(dataDir, secrets.FileName))
	if err != nil {
		return err
	}
	if _, err := store.SetUniFi(secrets.UniFi{
		BaseURL:         c.BaseURL,
		Username:        c.Username,
		Password:        c.Password,
		Site:            c.Site,
		AllowSelfSigned: c.AllowSelfSigned,
		Enabled:         true,
	}); err != nil {
		return err
	}
	return nil
}

// setupOnly is the "shepherd setup" subcommand: serve the setup page, write
// the file, exit. It exists for an install that already has a configuration
// and wants to go through setup again, and for writing a file somewhere else
// (-config) before starting Shepherd for real.
func setupOnly(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("shepherd setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "shepherd.toml", "the configuration file to write")
	port := fs.Int("port", setupPort, "the port to serve setup on")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := newSetupServer(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "setup: %v\n", err)
		return 1
	}
	defer s.Close()
	written, err := serveSetup(ctx, s, *port)
	if err != nil {
		fmt.Fprintf(stderr, "setup: %v\n", err)
		return 1
	}
	if written == "" {
		fmt.Fprintln(stderr, "setup: stopped; nothing was written")
		return 1
	}
	// Nothing starts after this subcommand, so the page's second half has
	// nothing to show; it says so and the owner closes it.
	fmt.Fprintf(stderr, "setup: wrote %s; start Shepherd to use it\n", written)
	return 0
}

// runningSetup is what the setup page is handed once Shepherd is up on the
// file it wrote: the portal to link to and sign into, a way to prove DNS
// filtering actually works from here, and the network-wide blocking the
// owner chose during setup.
func runningSetup(cfg config.Config, token string, policy *dnsengine.PolicyStore, skipped *skipSet) setup.Running {
	return setup.Running{
		PortalURL:     "http://" + cfg.Portal.Listen,
		Token:         token,
		Verify:        verifyDNS(cfg, skipped),
		SetCategories: applyCategories(policy),
	}
}

// verifyDNS asks Shepherd's own listeners a name that must resolve and one
// it must block, over UDP and TCP. It is the self-test (docs/DNS-QA.md) run
// once on demand rather than a second implementation: the same checks the
// Upstreams screen shows later, so setup cannot say "working" about
// something the portal will call broken an hour from now.
func verifyDNS(cfg config.Config, skipped *skipSet) func(context.Context) []setup.ListenerCheck {
	return func(ctx context.Context) []setup.ListenerCheck {
		skip := map[string]bool{}
		for _, a := range skipped.list() {
			skip[a] = true
		}
		var addrs []string
		for _, a := range cfg.DNS.ListenAddrs() {
			if !skip[a] {
				addrs = append(addrs, a)
			}
		}
		t := selftest.New(selftest.Options{
			Addrs:     func() []string { return addrs },
			GoodName:  cfg.Selftest.GoodName,
			NotServed: cfg.Selftest.NotServed,
		})
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return checksFrom(t.RunOnce(ctx))
	}
}

// checksFrom flattens a self-test report into the per-address, per-protocol
// answer the page shows: did it answer, did a good name resolve, was a
// blocked name blocked.
func checksFrom(rep selftest.Report) []setup.ListenerCheck {
	var out []setup.ListenerCheck
	for _, l := range rep.Listeners {
		byProto := map[string]*setup.ListenerCheck{}
		for _, p := range l.Probes {
			c := byProto[p.Proto]
			if c == nil {
				c = &setup.ListenerCheck{Addr: l.Addr, Proto: p.Proto}
				byProto[p.Proto] = c
			}
			switch p.Check {
			case "listener":
				c.Answers = p.OK
			case "resolve":
				c.Resolve = p.OK
			case "block":
				c.Blocks = p.OK
			}
			if !p.OK && c.Detail == "" {
				c.Detail = p.Detail
			}
		}
		for _, proto := range []string{"udp", "tcp"} {
			if c := byProto[proto]; c != nil {
				out = append(out, *c)
			}
		}
	}
	return out
}

// setupCategories are the network-wide blocking choices setup offers, taken
// from the shipped catalog so the page and the portal's Blocking screen
// always agree about what exists (docs/POLICY.md).
//
// Only a few are offered, and the suggested ones are the two nobody argues
// with on a household network. Everything else -- per-device rules, groups,
// schedules, the other categories -- is the portal's job, and setup saying
// so is better than setup growing a second policy editor.
func setupCategories() []setup.Category {
	cat, err := dnsengine.DefaultCatalog()
	if err != nil || cat == nil {
		return nil // a build whose catalog will not load says nothing here
	}
	offered := []struct {
		id        string
		suggested bool
	}{
		{"malware-phishing", true},
		{"ads-trackers", true},
		{"adult", false},
		{"gambling", false},
		{"piracy", false},
		{"substances", false},
		{"dating", false},
	}
	var out []setup.Category
	for _, o := range offered {
		e, ok := cat.ByID(o.id)
		if !ok || e.Kind != dnsengine.KindCategory {
			continue // a catalog that no longer has it is not an error
		}
		out = append(out, setup.Category{ID: e.ID, Name: e.Name, Description: e.Description, Suggested: o.suggested})
	}
	return out
}

// applyCategories switches the chosen categories on at network scope, in
// the policy store the portal owns from here on -- the same object the
// Blocking screen edits, not a copy written into shepherd.toml.
func applyCategories(policy *dnsengine.PolicyStore) func([]string) error {
	if policy == nil {
		return nil
	}
	return func(ids []string) error {
		for _, id := range ids {
			if err := policy.SetItem(dnsengine.NetworkScope(), id, true); err != nil {
				return fmt.Errorf("blocking %s: %w", id, err)
			}
		}
		return nil
	}
}
