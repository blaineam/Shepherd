// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"shepherd/internal/arp"
	"shepherd/internal/dnsengine"
)

// newARPHarness builds a minimal server with the given ARP status (nil for
// "disabled"), enough to exercise /api/arp/stats without the rest of the
// harness's policy and list machinery.
func newARPHarness(t *testing.T, mon ARPStatus) (*httptest.Server, string) {
	t.Helper()
	filter := dnsengine.NewFilter()
	pool, err := dnsengine.NewPool([]string{"192.0.2.53"})
	if err != nil {
		t.Fatal(err)
	}
	engine := &dnsengine.Engine{Filter: filter, Pool: pool, Cache: dnsengine.NewCache(10), Log: dnsengine.NewQueryLog(10), Stats: dnsengine.NewStats()}
	token := strings.Repeat("t", 64)
	srv := New(Deps{Engine: engine, Token: token, ARP: mon})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, token
}

func TestARPStatsReportsDisabledWhenNoMonitor(t *testing.T) {
	ts, token := newARPHarness(t, nil)
	res := do(t, "GET", ts.URL+"/api/arp/stats", token, "", nil)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["enabled"] != false {
		t.Errorf("body = %v, want enabled:false", body)
	}
	if _, has := body["stats"]; has {
		t.Errorf("disabled response should not carry stats: %v", body)
	}
}

func TestARPStatsReportsTheMonitorsCounters(t *testing.T) {
	mac, err := arp.ParseMAC("02:00:00:00:00:01")
	if err != nil {
		t.Fatal(err)
	}
	sender := netip.MustParseAddr("192.0.2.10")
	target := netip.MustParseAddr("192.0.2.1")

	mon := arp.NewMonitor(arp.NewFakeSource(), arp.DefaultConfig())
	mon.Handle(arp.NewRequest(mac, sender, target))

	ts, token := newARPHarness(t, mon)
	res := do(t, "GET", ts.URL+"/api/arp/stats", token, "", nil)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["enabled"] != true {
		t.Errorf("body = %v, want enabled:true", body)
	}
	stats, ok := body["stats"].(map[string]any)
	if !ok {
		t.Fatalf("body = %v, want a stats object", body)
	}
	if frames, _ := stats["frames"].(float64); frames < 1 {
		t.Errorf("stats = %v, want at least one frame counted", stats)
	}
}
