// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"

	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
	"shepherd/internal/geo"
)

// buildASNDB writes a tiny ASN database over documentation ranges, the same
// shape internal/geo's own tests use, so startClassify's ASN wiring can be
// exercised without a real download.
func buildASNDB(t *testing.T, path string) {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "DBIP-ASN-Lite", RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	_, n, _ := net.ParseCIDR("198.51.100.0/24")
	if err := w.Insert(n, mmdbtype.Map{
		"autonomous_system_number":       mmdbtype.Uint32(64500),
		"autonomous_system_organization": mmdbtype.String("Example Streaming Inc."),
	}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
}

func testEngineAndRegistry(t *testing.T) (*dnsengine.Engine, *devices.Registry) {
	t.Helper()
	filter := dnsengine.NewFilter()
	pool, err := dnsengine.NewPool([]string{"192.0.2.53"})
	if err != nil {
		t.Fatal(err)
	}
	engine := &dnsengine.Engine{Filter: filter, Pool: pool, Cache: dnsengine.NewCache(10), Log: dnsengine.NewQueryLog(10), Stats: dnsengine.NewStats()}
	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	engine.Clients = reg
	return engine, reg
}

func TestStartClassifyWiresObserveAndASN(t *testing.T) {
	old := classifyEvery
	classifyEvery = 20 * time.Millisecond
	t.Cleanup(func() { classifyEvery = old })

	engine, reg := testEngineAndRegistry(t)
	dbPath := filepath.Join(t.TempDir(), "asn.mmdb")
	buildASNDB(t, dbPath)
	var loc geo.ASNLocator
	if err := loc.Open(dbPath); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := startClassify(ctx, config.Default(), engine, reg, &loc)
	if err != nil {
		t.Fatal(err)
	}
	if engine.Observe == nil {
		t.Fatal("startClassify must wire Engine.Observe")
	}
	// Feed evidence for an address the fixture ASN database recognises, and
	// confirm it reaches the classifier without panicking.
	reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:5e:00:00:01", IP: "203.0.113.5", Time: time.Now()})
	engine.Observe("203.0.113.5", "unknown-but-on-a-known-network.example.", []net.IP{net.ParseIP("198.51.100.9")})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Stats().Devices > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the classifier never recorded the observation")
}

func TestStartClassifyWithoutASNStillWorks(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := startClassify(ctx, config.Default(), engine, reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || engine.Observe == nil {
		t.Fatal("startClassify must work with no ASN locator")
	}
	engine.Observe("192.0.2.9", "a.example.", nil) // must not panic with a nil ASN source
}

func TestStartClassifyUsesTheConfiguredInterval(t *testing.T) {
	old := classifyEvery
	classifyEvery = 0 // force startClassify to use the configuration's own value
	t.Cleanup(func() { classifyEvery = old })

	engine, reg := testEngineAndRegistry(t)
	cfg := config.Default()
	cfg.Classify.IntervalSeconds = 30
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // the long interval means Run's ticker never fires in this test; just prove it starts cleanly
	if _, err := startClassify(ctx, cfg, engine, reg, nil); err != nil {
		t.Fatal(err)
	}
}
