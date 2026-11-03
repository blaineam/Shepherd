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
	"shepherd/internal/setup"
)

// probeTimeout bounds the one probe the setup page makes per resolver. It is
// generous because a cold DoT or DoH upstream has to finish bootstrap, TCP
// and TLS before it can answer, and calling that a failure would send the
// owner off to debug a resolver that works.
const probeTimeout = 10 * time.Second

// setupPort is where first-run setup listens. It is the portal's own default
// port, on every address rather than loopback, because the whole point is
// that the person installing Shepherd on a NAS can reach it from their
// laptop; the one-time token in the printed URL is what keeps the rest of
// the network out, and the listener stops as soon as setup finishes.
const setupPort = 8787

// setupSeams replaces the setup flow's outside edges. It is a test seam,
// like catalogOverride: production leaves it nil.
var setupSeams func(*setup.Server)

// newSetupServer builds first-run setup with the real host, resolver and
// router implementations behind it.
func newSetupServer(cfgPath string) (*setup.Server, error) {
	s, err := setup.NewServer(&setup.Server{
		ConfigPath:    cfgPath,
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

// runSetup serves first-run setup and reports whether a configuration was
// written. Shepherd then carries straight on with it: the owner started one
// process, and finishing the page should be the end of it, not the moment
// they have to go back to a terminal.
func runSetup(ctx context.Context, cfgPath string, port int) (bool, error) {
	s, err := newSetupServer(cfgPath)
	if err != nil {
		return false, err
	}
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
	written, err := s.Run(ctx, addr, log.Printf)
	if err != nil {
		return false, err
	}
	if written == "" {
		return false, nil // ctx ended: nothing was written
	}
	log.Printf("setup: wrote %s; starting Shepherd on it", written)
	return true, nil
}

// setupIfUnconfigured runs setup when there is no configuration file, which
// is what makes the first start of a new install a guided one. An install
// that has a file never sees it; "shepherd setup" is how it is asked for
// again.
//
// A failure to bring up the setup listener is deliberately not fatal: a port
// already in use must not stop an install whose defaults would otherwise
// work, so it is logged and Shepherd starts on the defaults.
func setupIfUnconfigured(ctx context.Context, cfgPath string) {
	if fileExists(cfgPath) {
		return
	}
	ok, err := runSetup(ctx, cfgPath, setupPort)
	if err != nil {
		log.Printf("setup: %v", err)
		log.Printf("setup: starting on the defaults instead (loopback only); run \"shepherd setup\" to configure it")
		return
	}
	if !ok && ctx.Err() == nil {
		log.Printf("setup: nothing was written; starting on the defaults (loopback only)")
	}
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
	ok, err := runSetup(ctx, *cfgPath, *port)
	if err != nil {
		fmt.Fprintf(stderr, "setup: %v\n", err)
		return 1
	}
	if !ok {
		fmt.Fprintln(stderr, "setup: stopped; nothing was written")
		return 1
	}
	return 0
}
