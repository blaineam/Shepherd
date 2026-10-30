// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/portscan"
)

// fakeScanDial answers "open" for every address in open and refuses
// everything else, without ever touching a real socket.
func fakeScanDial(open map[string]bool) portscan.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if open[address] {
			return fakeScanConn{}, nil
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
}

type fakeScanConn struct{}

func (fakeScanConn) Read([]byte) (int, error)         { return 0, errors.New("no data") }
func (fakeScanConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeScanConn) Close() error                     { return nil }
func (fakeScanConn) LocalAddr() net.Addr              { return nil }
func (fakeScanConn) RemoteAddr() net.Addr             { return nil }
func (fakeScanConn) SetDeadline(time.Time) error      { return nil }
func (fakeScanConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeScanConn) SetWriteDeadline(time.Time) error { return nil }

func TestStartPortscanScansKnownDevicesAndPersists(t *testing.T) {
	oldEvery, oldDial := portscanEvery, portscanDial
	portscanEvery = 20 * time.Millisecond
	portscanDial = fakeScanDial(map[string]bool{net.JoinHostPort("203.0.113.50", "23"): true})
	t.Cleanup(func() { portscanEvery, portscanDial = oldEvery, oldDial })

	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:00:00:01:01", IP: "203.0.113.50", Time: time.Now()})
	if id == "" {
		t.Fatal("observation was rejected")
	}

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := startPortscan(ctx, cfg, reg)
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ds, ok := s.Result(id); ok && len(ds.Ports) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	ds, ok := s.Result(id)
	if !ok || len(ds.Ports) != 1 || !ds.Ports[0].Open || ds.Ports[0].Port != 23 {
		t.Fatalf("Result(%q) = %+v, %v; want port 23 open", id, ds, ok)
	}

	path := filepath.Join(cfg.DataDir, "portscan.json")
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("portscan history was never saved to %s: %v", path, err)
	}

	// A fresh scanner loading that same file sees the same result.
	reloaded := portscan.New(portscan.Options{})
	if err := reloaded.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if rds, ok := reloaded.Result(id); !ok || len(rds.Ports) != 1 {
		t.Fatalf("reloaded Result(%q) = %+v, %v", id, rds, ok)
	}
}

func TestStartPortscanUsesTheConfiguredInterval(t *testing.T) {
	oldEvery, oldDial := portscanEvery, portscanDial
	portscanEvery = 0 // force startPortscan to use the configuration's own value
	portscanDial = fakeScanDial(nil)
	t.Cleanup(func() { portscanEvery, portscanDial = oldEvery, oldDial })

	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Portscan.IntervalSeconds = 21600
	ctx, cancel := context.WithCancel(context.Background())
	// The long interval means Run's ticker never fires again in this test;
	// just prove it starts cleanly and wait for its one immediate scan (and
	// save) to finish before the temp dir is torn down.
	if _, err := startPortscan(ctx, cfg, reg); err != nil {
		cancel()
		t.Fatal(err)
	}
	waitForFile(t, filepath.Join(cfg.DataDir, "portscan.json"))
	cancel()
}

// waitForFile polls until path exists, for a background goroutine's first
// write to land before a test's temp dir goes away.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s was never written", path)
}

// fakeExposure is a portscan.ExposureChecker that always reports
// wan_forwarded, without ever touching a real IGD.
type fakeExposure struct{}

func (fakeExposure) Exposure(ctx context.Context, ip string, port int) (bool, bool) {
	return true, true
}

func TestStartPortscanUsesTheExposureSeam(t *testing.T) {
	oldEvery, oldDial, oldExposure := portscanEvery, portscanDial, portscanExposure
	portscanEvery = 20 * time.Millisecond
	portscanDial = fakeScanDial(map[string]bool{net.JoinHostPort("203.0.113.60", "23"): true})
	portscanExposure = fakeExposure{}
	t.Cleanup(func() { portscanEvery, portscanDial, portscanExposure = oldEvery, oldDial, oldExposure })

	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:00:00:02:01", IP: "203.0.113.60", Time: time.Now()})
	if id == "" {
		t.Fatal("observation was rejected")
	}

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	// The seam must win even when the configuration disables the feature:
	// a test never needs to build a real upnpigd.Checker to exercise this
	// wiring.
	cfg.Portscan.WANExposure.Enabled = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := startPortscan(ctx, cfg, reg)
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ds, ok := s.Result(id); ok && len(ds.Ports) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	ds, ok := s.Result(id)
	if !ok || len(ds.Ports) != 1 {
		t.Fatalf("Result(%q) = %+v, %v", id, ds, ok)
	}
	if ds.Ports[0].Exposure != portscan.ExposureWANForwarded {
		t.Fatalf("Exposure = %q, want %q (the seam checker always says WAN-forwarded)", ds.Ports[0].Exposure, portscan.ExposureWANForwarded)
	}
}

func TestStartPortscanWANExposureDisabledNeverSetsExposure(t *testing.T) {
	oldEvery, oldDial, oldExposure := portscanEvery, portscanDial, portscanExposure
	portscanEvery = 20 * time.Millisecond
	portscanDial = fakeScanDial(map[string]bool{net.JoinHostPort("203.0.113.61", "23"): true})
	portscanExposure = nil // no seam: startPortscan must honor cfg instead
	t.Cleanup(func() { portscanEvery, portscanDial, portscanExposure = oldEvery, oldDial, oldExposure })

	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:00:00:02:02", IP: "203.0.113.61", Time: time.Now()})
	if id == "" {
		t.Fatal("observation was rejected")
	}

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Portscan.WANExposure.Enabled = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := startPortscan(ctx, cfg, reg)
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ds, ok := s.Result(id); ok && len(ds.Ports) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	ds, ok := s.Result(id)
	if !ok || len(ds.Ports) != 1 {
		t.Fatalf("Result(%q) = %+v, %v", id, ds, ok)
	}
	if ds.Ports[0].Exposure != "" {
		t.Fatalf("Exposure = %q, want empty: wan_exposure is disabled and no seam was set", ds.Ports[0].Exposure)
	}
}

func TestStartPortscanIgnoresUnreadableHistory(t *testing.T) {
	oldEvery, oldDial := portscanEvery, portscanDial
	portscanEvery = time.Hour
	portscanDial = fakeScanDial(nil)
	t.Cleanup(func() { portscanEvery, portscanDial = oldEvery, oldDial })

	reg := devices.New(devices.Options{NodeID: "t"})
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "portscan.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := startPortscan(ctx, cfg, reg); err != nil {
		cancel()
		t.Fatalf("startPortscan must tolerate a corrupt history file: %v", err)
	}
	path := filepath.Join(cfg.DataDir, "portscan.json")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 && b[0] == '{' {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
}
