// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
	"shepherd/internal/threats"
)

func TestStartThreatsHooksTheEngineAndRaisesAlarms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("bad.example.com\n")) }))
	defer srv.Close()
	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	engine, reg := testEngineAndRegistry(t)
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:00:00:00:02", IP: "192.0.2.20", Hostname: "laptop"})
	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	old := threatsEvery
	threatsEvery = time.Hour
	t.Cleanup(func() { threatsEvery = old })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	th, err := startThreats(ctx, cfg, engine, reg, eng)
	if err != nil || th == nil || engine.OnEntry == nil {
		t.Fatalf("startThreats: %v %v hook=%v", th, err, engine.OnEntry != nil)
	}
	// Point the engine at the test feed rather than the real internet.
	th2 := threats.New(threats.Options{Client: srv.Client(), Feeds: []threats.Feed{{ID: "d", Kind: threats.KindDomain, URL: srv.URL, Describes: "a malware host"}},
		OnMatch: func(m threats.Match) { reportThreatMatch(eng, reg, th, m) }})
	th2.Refresh(context.Background())

	// A query from a known device, attributed by its address when the
	// entry carries no device yet; and one from an unknown client.
	th2.Observe(dnsengine.Entry{Client: "192.0.2.20", Name: "bad.example.com", Action: "blocked", Time: time.Now()})
	th2.Observe(dnsengine.Entry{Client: "192.0.2.99", Name: "bad.example.com", Action: "allowed", Time: time.Now()})
	th2.Observe(dnsengine.Entry{Client: "192.0.2.20", DeviceID: id, Device: "laptop", Name: "x.bad.example.com", Action: "blocked", Time: time.Now()})

	var page alarms.Page
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		eng.Drain()
		page = eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeThreatMatch}}})
		if page.Total >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if page.Total != 2 {
		t.Fatalf("threat alarms = %d, want 2 (one per device and indicator; the third query folds)", page.Total)
	}
	var byDevice, byClient bool
	for _, a := range page.Alarms {
		if a.DeviceID == id && a.Key == "threat-match|"+id+"|bad.example.com|" {
			byDevice = true
		}
		if a.DeviceID == "" && a.Key == "threat-match|192.0.2.99|bad.example.com|" {
			byClient = true
		}
	}
	if !byDevice || !byClient {
		t.Fatalf("alarms = %+v", page.Alarms)
	}
	// A match that already names its device picks up the device's groups.
	g, _ := reg.CreateGroup("Kids", "")
	reg.BulkAssignGroup([]string{id}, g.ID)
	reportThreatMatch(eng, reg, th, threats.Match{Client: "192.0.2.20", DeviceID: id, Device: "laptop", Name: "other.example.net", Indicator: "other.example.net", FeedID: "d", Action: "allowed", Time: time.Now()})
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		eng.Drain()
		page = eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeThreatMatch}, Text: "other.example.net"}})
		if page.Total > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if page.Total != 1 || len(page.Alarms[0].GroupIDs) != 1 || page.Alarms[0].GroupIDs[0] != g.ID {
		t.Fatalf("grouped alarm = %+v", page.Alarms)
	}
	// No alarm engine: still logged, never a panic.
	reportThreatMatch(nil, reg, th, threats.Match{Client: "192.0.2.20", Name: "bad.example.com", Indicator: "bad.example.com", FeedID: "d"})

	// Off in the configuration: nothing is wired.
	cfg.Threats.Enabled = false
	e2, _ := testEngineAndRegistry(t)
	if th, err := startThreats(ctx, cfg, e2, reg, eng); th != nil || err != nil || e2.OnEntry != nil {
		t.Fatalf("disabled: %v %v", th, err)
	}
}
