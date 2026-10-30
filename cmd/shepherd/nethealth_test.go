// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/nethealth"
)

// fakeNethealthConn behaves like fakeScanConn: no real socket, nothing to
// read, which is all a latency probe needs (the connection succeeding is
// the whole signal).
type fakeNethealthConn struct{}

func (fakeNethealthConn) Read([]byte) (int, error)         { return 0, errors.New("no data") }
func (fakeNethealthConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeNethealthConn) Close() error                     { return nil }
func (fakeNethealthConn) LocalAddr() net.Addr              { return nil }
func (fakeNethealthConn) RemoteAddr() net.Addr             { return nil }
func (fakeNethealthConn) SetDeadline(time.Time) error      { return nil }
func (fakeNethealthConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeNethealthConn) SetWriteDeadline(time.Time) error { return nil }

// fakeNethealthDial answers every address with a successful connection, so
// every target is reachable; tests that want a loss/outage reading use
// failAll below instead.
func fakeNethealthDial(ctx context.Context, network, address string) (net.Conn, error) {
	return fakeNethealthConn{}, nil
}

func failAllNethealthDial(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
}

func withNethealthSeams(t *testing.T, every, bufferbloatEvery time.Duration, dial nethealth.DialFunc, load nethealth.LoadFunc, gw func() (netip.Addr, error)) {
	t.Helper()
	oldEvery, oldDial, oldBEvery, oldLoad, oldGW, oldBDur := nethealthEvery, nethealthDial, nethealthBufferbloatEvery, nethealthLoad, nethealthGateway, nethealthBufferbloatDuration
	nethealthEvery, nethealthDial, nethealthBufferbloatEvery, nethealthLoad = every, dial, bufferbloatEvery, load
	nethealthBufferbloatDuration = 20 * time.Millisecond // keep bufferbloat tests fast regardless of production's 5s default
	if gw != nil {
		nethealthGateway = gw
	}
	t.Cleanup(func() {
		nethealthEvery, nethealthDial, nethealthBufferbloatEvery, nethealthLoad, nethealthGateway, nethealthBufferbloatDuration = oldEvery, oldDial, oldBEvery, oldLoad, oldGW, oldBDur
	})
}

// toggleDial lets a test flip a dial function's behavior after a Prober has
// already been constructed with it: the Prober captures the DialFunc value
// at New() and never re-reads the package-level test seam afterward (the
// same as internal/portscan.Scanner/internal/vulnscan.Scanner), so
// "recovers later" tests need the function itself to be swappable, not the
// variable that only mattered at construction time.
type toggleDial struct {
	fail atomic.Bool
}

func (d *toggleDial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if d.fail.Load() {
		return failAllNethealthDial(ctx, network, address)
	}
	return fakeNethealthDial(ctx, network, address)
}

func noGateway() (netip.Addr, error) { return netip.Addr{}, errors.New("no default route") }

func TestStartNethealthProbesAndPersists(t *testing.T) {
	withNethealthSeams(t, 15*time.Millisecond, 0, fakeNethealthDial, nil, noGateway)

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.Upstreams = []string{"9.9.9.10"}
	cfg.Nethealth.Enabled = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, targets, err := startNethealth(ctx, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 {
		t.Fatal("expected a non-empty target list")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := p.Latest(); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	latest, ok := p.Latest()
	if !ok || latest.ReachableTargets == 0 {
		t.Fatalf("Latest() = %+v, %v; want at least one reachable target", latest, ok)
	}

	path := filepath.Join(cfg.DataDir, "nethealth.json")
	waitForFile(t, path)

	reloaded := nethealth.New(nethealth.Options{})
	if err := reloaded.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := reloaded.Latest(); !ok {
		t.Fatal("reloaded prober has no history")
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
}

func TestStartNethealthIncludesGatewayWhenAvailable(t *testing.T) {
	gw := netip.MustParseAddr("203.0.113.1")
	var mu sync.Mutex
	var seen []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		mu.Lock()
		seen = append(seen, host)
		mu.Unlock()
		return fakeNethealthConn{}, nil
	}
	withNethealthSeams(t, 0, 0, dial, nil, func() (netip.Addr, error) { return gw, nil })

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.Upstreams = []string{"9.9.9.10"}
	cfg.Nethealth.Enabled = true
	ctx, cancel := context.WithCancel(context.Background())
	if _, _, err := startNethealth(ctx, cfg, nil); err != nil {
		cancel()
		t.Fatal(err)
	}
	waitForFile(t, filepath.Join(cfg.DataDir, "nethealth.json"))
	cancel()
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, h := range seen {
		if h == gw.String() {
			found = true
		}
	}
	if !found {
		t.Errorf("gateway %s was never probed; probed %v", gw, seen)
	}
}

func TestStartNethealthSkipsGatewayWhenUnavailable(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		mu.Lock()
		seen = append(seen, host)
		mu.Unlock()
		return fakeNethealthConn{}, nil
	}
	withNethealthSeams(t, 0, 0, dial, nil, noGateway)

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.Upstreams = []string{"9.9.9.10"}
	cfg.Nethealth.Enabled = true
	ctx, cancel := context.WithCancel(context.Background())
	if _, _, err := startNethealth(ctx, cfg, nil); err != nil {
		cancel()
		t.Fatal(err)
	}
	waitForFile(t, filepath.Join(cfg.DataDir, "nethealth.json"))
	cancel()
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	for _, h := range seen {
		if h == "203.0.113.1" {
			t.Errorf("should not have probed a gateway when none was available; probed %v", seen)
		}
	}
}

func TestStartNethealthRaisesAndResolvesDegradedAlarm(t *testing.T) {
	td := &toggleDial{}
	td.fail.Store(true)
	withNethealthSeams(t, 10*time.Millisecond, 0, td.dial, nil, noGateway)

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.Upstreams = []string{"9.9.9.10"}
	cfg.Nethealth.Enabled = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	if _, _, err := startNethealth(ctx, cfg, eng); err != nil {
		t.Fatal(err)
	}

	var page alarms.Page
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		eng.Drain()
		page = eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeNetworkDegraded}}})
		if page.Total > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if page.Total != 1 {
		t.Fatalf("expected exactly one network-degraded alarm after sustained failures, got %d", page.Total)
	}

	// Switch to a dial that always succeeds: the very next sample should
	// resolve the alarm.
	td.fail.Store(false)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		eng.Drain()
		page = eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeNetworkDegraded}, States: []alarms.State{alarms.StateResolved}}})
		if page.Total > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if page.Total != 1 {
		t.Fatalf("expected the alarm to resolve once samples recovered, got %d resolved", page.Total)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
}

func TestStartNethealthWorksWithoutAnAlarmEngine(t *testing.T) {
	withNethealthSeams(t, 10*time.Millisecond, 0, failAllNethealthDial, nil, noGateway)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.Upstreams = []string{"9.9.9.10"}
	cfg.Nethealth.Enabled = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, _, err := startNethealth(ctx, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := p.Latest(); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := p.Latest(); !ok {
		t.Fatal("expected a sample even with no alarm engine wired in")
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
}

// TestStartNethealthBuildsTargetsAndWorksManuallyWhileFullyDisabled covers
// the scenario the default config leaves everyone in: [nethealth] is off
// (cfg.Nethealth.Enabled defaults false — see docs/NETHEALTH.md), so the
// scheduled Run loop never starts and Latest() never has anything on its
// own, but the Prober itself, its target list and its persistence hooks
// must still be built so a manual probe (what the portal's "Probe now"
// uses, via ProbeNow) still works and persists.
func TestStartNethealthBuildsTargetsAndWorksManuallyWhileFullyDisabled(t *testing.T) {
	withNethealthSeams(t, time.Hour, time.Hour, fakeNethealthDial, nil, noGateway)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.Upstreams = []string{"9.9.9.10"}
	// cfg.Nethealth.Enabled and BufferbloatEnabled are left at their
	// default (false) deliberately.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, targets, err := startNethealth(ctx, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 {
		t.Fatal("expected a non-empty target list even while disabled")
	}
	if _, ok := p.Latest(); ok {
		t.Fatal("expected no sample yet: the schedule must not have started")
	}

	sample := p.ProbeNow(ctx, targets)
	if sample.ReachableTargets == 0 {
		t.Fatalf("manual probe found nothing reachable: %+v", sample)
	}
	path := filepath.Join(cfg.DataDir, "nethealth.json")
	waitForFile(t, path)
	reloaded := nethealth.New(nethealth.Options{})
	if err := reloaded.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := reloaded.Latest(); !ok {
		t.Fatal("manual probe's result was not persisted")
	}
}

func TestStartNethealthBufferbloatScheduledWhenEnabled(t *testing.T) {
	var loadCalled bool
	load := func(ctx context.Context) error {
		loadCalled = true
		<-ctx.Done()
		return nil
	}
	withNethealthSeams(t, time.Hour, 15*time.Millisecond, fakeNethealthDial, load, noGateway)

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.Upstreams = []string{"9.9.9.10"}
	cfg.Nethealth.BufferbloatEnabled = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, _, err := startNethealth(ctx, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := p.LatestBufferbloat(); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := p.LatestBufferbloat(); !ok {
		t.Fatal("expected a bufferbloat check to have run")
	}
	if !loadCalled {
		t.Error("expected the injected Load to have been called")
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
}

func TestStartNethealthBufferbloatNotScheduledWhenDisabled(t *testing.T) {
	withNethealthSeams(t, 10*time.Millisecond, 10*time.Millisecond, fakeNethealthDial, nil, noGateway)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.Upstreams = []string{"9.9.9.10"}
	cfg.Nethealth.BufferbloatEnabled = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, _, err := startNethealth(ctx, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, ok := p.LatestBufferbloat(); ok {
		t.Error("bufferbloat should not have run while disabled")
	}
	cancel()
}

func TestStartNethealthIgnoresUnreadableHistory(t *testing.T) {
	withNethealthSeams(t, time.Hour, 0, fakeNethealthDial, nil, noGateway)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DNS.Upstreams = []string{"9.9.9.10"}
	cfg.Nethealth.Enabled = true
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "nethealth.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, _, err := startNethealth(ctx, cfg, nil); err != nil {
		cancel()
		t.Fatalf("startNethealth must tolerate a corrupt history file: %v", err)
	}
	path := filepath.Join(cfg.DataDir, "nethealth.json")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 && b[0] == '{' {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
}
