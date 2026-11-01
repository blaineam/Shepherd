// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"shepherd/internal/dnsengine"
	"shepherd/internal/threats"
)

func TestThreatsReportsOffWithoutAnEngine(t *testing.T) {
	h := newHarness(t)
	out := h.ok("GET", "/api/threats", "", 200)
	if out["enabled"] != false || len(out["feeds"].([]any)) != 0 || len(out["matches"].([]any)) != 0 {
		t.Fatalf("status = %v", out)
	}
	h.expect("POST", "/api/threats/refresh", "", 404)
}

func TestThreatsStatusMatchesAndManualRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("bad.example.com\n")) }))
	defer srv.Close()
	h := newHarness(t)
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	th := threats.New(threats.Options{Client: srv.Client(), Now: func() time.Time { return now },
		Feeds: []threats.Feed{{ID: "d", Name: "D", Kind: threats.KindDomain, URL: srv.URL, Describes: "a malware host"}}})
	h.srv.Threats, h.srv.ThreatsEnabled = th, true

	before := h.ok("GET", "/api/threats", "", 200)
	if before["enabled"] != true || before["loaded"] != 0.0 || before["feeds"].([]any)[0].(map[string]any)["count"] != 0.0 {
		t.Fatalf("before refresh = %v", before)
	}
	res := h.ok("POST", "/api/threats/refresh", "", 200)
	if res["feeds"].([]any)[0].(map[string]any)["count"] != 1.0 {
		t.Fatalf("refresh = %v", res)
	}
	th.Observe(dnsengine.Entry{Client: "192.0.2.5", Device: "Laptop", DeviceID: "d1", Name: "x.bad.example.com", Action: "blocked"})
	after := h.ok("GET", "/api/threats", "", 200)
	feeds := after["feeds"].([]any)
	if after["loaded"] != 1.0 || feeds[0].(map[string]any)["describes"] != "a malware host" {
		t.Fatalf("after = %v", after)
	}
	m := after["matches"].([]any)[0].(map[string]any)
	if m["device"] != "Laptop" || m["indicator"] != "bad.example.com" || m["action"] != "blocked" || m["feed_id"] != "d" {
		t.Fatalf("match = %v", m)
	}
}
