// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/portscan"
	"shepherd/internal/vulnscan"
)

// fakeVulnConn behaves like fakeScanConn (cmd/shepherd/portscan_test.go): no
// real socket, no data to read, which is all the telnet-exposed signature
// needs (the connection succeeding is the whole signal).
type fakeVulnConn struct{}

func (fakeVulnConn) Read([]byte) (int, error)         { return 0, errors.New("no data") }
func (fakeVulnConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeVulnConn) Close() error                     { return nil }
func (fakeVulnConn) LocalAddr() net.Addr              { return nil }
func (fakeVulnConn) RemoteAddr() net.Addr             { return nil }
func (fakeVulnConn) SetDeadline(time.Time) error      { return nil }
func (fakeVulnConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeVulnConn) SetWriteDeadline(time.Time) error { return nil }

func fakeVulnDial(open map[string]bool) vulnscan.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if open[address] {
			return fakeVulnConn{}, nil
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
}

// syncOpenSet guards a set of "open" addresses behind a mutex. Plain
// fakeScanDial/fakeVulnDial maps are safe everywhere else in this file
// because nothing ever mutates them after the dial func is built; a test
// that flips an address from open to closed partway through, like
// TestStartVulnscanResolvesAlarmWhenFindingClears, needs this instead,
// since startVulnscan's background goroutine (its one initial scan, before
// its own, effectively-never-firing ticker) can still be reading the set
// concurrently with that mutation.
type syncOpenSet struct {
	mu   sync.Mutex
	open map[string]bool
}

func newSyncOpenSet(initiallyOpen ...string) *syncOpenSet {
	s := &syncOpenSet{open: make(map[string]bool, len(initiallyOpen))}
	for _, addr := range initiallyOpen {
		s.open[addr] = true
	}
	return s
}

func (s *syncOpenSet) has(addr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open[addr]
}

func (s *syncOpenSet) set(addr string, open bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open[addr] = open
}

func syncScanDial(s *syncOpenSet) portscan.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if s.has(address) {
			return fakeScanConn{}, nil
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
}

func syncVulnDial(s *syncOpenSet) vulnscan.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if s.has(address) {
			return fakeVulnConn{}, nil
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
}

func TestStartVulnscanProbesPortscanResultsAndRaisesAlarm(t *testing.T) {
	oldPSEvery, oldPSDial := portscanEvery, portscanDial
	oldVSEvery, oldVSDial := vulnscanEvery, vulnscanDial
	oldExposure := portscanExposure
	portscanEvery, vulnscanEvery = 15*time.Millisecond, 15*time.Millisecond
	portscanDial = fakeScanDial(map[string]bool{net.JoinHostPort("203.0.113.60", "23"): true})
	vulnscanDial = fakeVulnDial(map[string]bool{net.JoinHostPort("203.0.113.60", "23"): true})
	// Without this the WAN-exposure checker is real, because
	// config.Default() enables it, and startPortscan builds a live
	// upnpigd client that does SSDP multicast discovery. Nothing answers
	// on CI or inside Docker, so the discovery sits there until it times
	// out and eats the scan budget this test then waits three seconds
	// for. The sibling test in portscan_test.go already uses this seam
	// for the same reason; this one did not, and that is the whole of why
	// it failed there and passed on a developer machine with a router.
	portscanExposure = fakeExposure{}
	t.Cleanup(func() {
		portscanEvery, portscanDial = oldPSEvery, oldPSDial
		vulnscanEvery, vulnscanDial = oldVSEvery, oldVSDial
		portscanExposure = oldExposure
	})

	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:00:00:02:01", IP: "203.0.113.60", Time: time.Now()})
	if id == "" {
		t.Fatal("observation was rejected")
	}

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ps, err := startPortscan(ctx, cfg, reg)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	vs, err := startVulnscan(ctx, cfg, reg, ps, eng)
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ds, ok := vs.Result(id); ok && len(ds.Findings) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	ds, ok := vs.Result(id)
	if !ok || len(ds.Findings) != 1 || ds.Findings[0].SignatureID != "telnet-exposed" {
		t.Fatalf("Result(%q) = %+v, %v; want one telnet-exposed finding", id, ds, ok)
	}

	// The scan that just updated Result() calls OnScan (which raises the
	// alarm) synchronously right after, but on the scanner's own
	// background goroutine, and Raise itself only queues the event for its
	// worker — so poll rather than assume a single eng.Drain() right after
	// seeing the finding has already seen the Raise land.
	var page alarms.Page
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		eng.Drain()
		page = eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeVulnerabilityFound}, DeviceID: id}})
		if page.Total > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if page.Total != 1 {
		t.Fatalf("expected exactly one vulnerability-found alarm, got %d", page.Total)
	}
	if page.Alarms[0].Severity != alarms.SeverityHigh {
		t.Fatalf("alarm severity = %v, want high (telnet-exposed's own severity)", page.Alarms[0].Severity)
	}

	path := filepath.Join(cfg.DataDir, "vulnscan.json")
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("vulnscan history was never saved to %s: %v", path, err)
	}

	// Stop the background scanners and give them a moment to actually exit
	// before the deferred cancel (a no-op here) and TempDir cleanup run:
	// their 15ms tickers can otherwise still be mid-write when the test
	// function returns.
	cancel()
	time.Sleep(20 * time.Millisecond)
}

func TestStartVulnscanResolvesAlarmWhenFindingClears(t *testing.T) {
	addr := net.JoinHostPort("203.0.113.61", "23")
	// A mutex-guarded set, not a plain map: this test flips addr from open
	// to closed partway through, while startVulnscan's background
	// goroutine (its one scan at startup, before a ticker that will not
	// fire again inside this test) can still be reading it concurrently.
	open := newSyncOpenSet(addr)
	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:00:00:02:02", IP: "203.0.113.61", Time: time.Now()})
	if id == "" {
		t.Fatal("observation was rejected")
	}

	ps := portscan.New(portscan.Options{Dial: syncScanDial(open), Ports: []int{23}, Concurrency: 2, Timeout: time.Second})
	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oldVSDial := vulnscanDial
	vulnscanDial = syncVulnDial(open)
	t.Cleanup(func() { vulnscanDial = oldVSDial })

	vs, err := startVulnscan(ctx, cfg, reg, ps, eng)
	if err != nil {
		t.Fatal(err)
	}

	ps.Scan(ctx, portscan.TargetsFromDevices(reg.List()))
	vs.Scan(ctx, vulnscan.TargetsFromPortscan(ps.Results()))
	eng.Drain()
	page := eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeVulnerabilityFound}, DeviceID: id}})
	if page.Total != 1 || page.Alarms[0].State == alarms.StateResolved {
		t.Fatalf("expected one open vulnerability-found alarm, got %+v", page.Alarms)
	}

	// Telnet closes: portscan no longer reports it open, so vulnscan has
	// nothing to probe for this device and the finding resolves.
	open.set(addr, false)
	ps.Scan(ctx, portscan.TargetsFromDevices(reg.List()))
	vs.Scan(ctx, vulnscan.TargetsFromPortscan(ps.Results()))
	eng.Drain()
	page = eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeVulnerabilityFound}, DeviceID: id, States: []alarms.State{alarms.StateResolved}}})
	if page.Total != 1 {
		t.Fatalf("expected the alarm to be resolved once the finding cleared, got %+v", page.Alarms)
	}
	cancel()
	time.Sleep(20 * time.Millisecond) // let startVulnscan's background goroutine actually stop first
}

func TestStartVulnscanWorksWithoutAnAlarmEngine(t *testing.T) {
	open := map[string]bool{net.JoinHostPort("203.0.113.62", "23"): true}
	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:00:00:02:03", IP: "203.0.113.62", Time: time.Now()})
	if id == "" {
		t.Fatal("observation was rejected")
	}
	ps := portscan.New(portscan.Options{Dial: fakeScanDial(open), Ports: []int{23}, Concurrency: 2, Timeout: time.Second})

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oldVSDial := vulnscanDial
	vulnscanDial = fakeVulnDial(open)
	t.Cleanup(func() { vulnscanDial = oldVSDial })

	vs, err := startVulnscan(ctx, cfg, reg, ps, nil)
	if err != nil {
		t.Fatal(err)
	}
	ps.Scan(ctx, portscan.TargetsFromDevices(reg.List()))
	ds := vs.Scan(ctx, vulnscan.TargetsFromPortscan(ps.Results()))
	if len(ds) != 1 || len(ds[0].Findings) != 1 {
		t.Fatalf("Scan with a nil alarm engine must still probe and record: %+v", ds)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
}

func TestStartVulnscanUsesTheConfiguredInterval(t *testing.T) {
	oldEvery, oldDial := vulnscanEvery, vulnscanDial
	vulnscanEvery = 0 // force startVulnscan to use the configuration's own value
	vulnscanDial = fakeVulnDial(nil)
	t.Cleanup(func() { vulnscanEvery, vulnscanDial = oldEvery, oldDial })

	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	ps := portscan.New(portscan.Options{Dial: fakeScanDial(nil)})
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Vulnscan.IntervalSeconds = 86400
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := startVulnscan(ctx, cfg, reg, ps, nil); err != nil {
		cancel()
		t.Fatal(err)
	}
	waitForFile(t, filepath.Join(cfg.DataDir, "vulnscan.json"))
	cancel()
	// Give Run's background goroutine a moment to actually observe
	// cancellation and return before the test ends and its TempDir is
	// removed: cancel() only signals, it does not wait, and a write still
	// landing after that removal races with the cleanup.
	time.Sleep(20 * time.Millisecond)
}

func TestStartVulnscanIgnoresUnreadableHistory(t *testing.T) {
	oldEvery, oldDial := vulnscanEvery, vulnscanDial
	vulnscanEvery = time.Hour
	vulnscanDial = fakeVulnDial(nil)
	t.Cleanup(func() { vulnscanEvery, vulnscanDial = oldEvery, oldDial })

	reg := devices.New(devices.Options{NodeID: "t"})
	ps := portscan.New(portscan.Options{Dial: fakeScanDial(nil)})
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "vulnscan.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := startVulnscan(ctx, cfg, reg, ps, nil); err != nil {
		cancel()
		t.Fatalf("startVulnscan must tolerate a corrupt history file: %v", err)
	}
	waitForFile(t, filepath.Join(cfg.DataDir, "vulnscan.json"))
	cancel()
	time.Sleep(20 * time.Millisecond) // let Run's goroutine actually stop before TempDir cleanup
}

func TestVulnscanDeviceNameFallsBackToID(t *testing.T) {
	if got := vulnscanDeviceName(nil, "abc123"); got != "abc123" {
		t.Fatalf("vulnscanDeviceName(nil registry) = %q, want the raw ID", got)
	}
	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	if got := vulnscanDeviceName(reg, "missing-device"); got != "missing-device" {
		t.Fatalf("vulnscanDeviceName(unknown id) = %q, want the raw ID", got)
	}
}
