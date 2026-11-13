// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"shepherd/internal/decoy"
	"shepherd/internal/detect"
	"shepherd/internal/dnsengine"
)

func TestDetectReportsOffWithoutAnEngine(t *testing.T) {
	h := newHarness(t)
	out := h.ok("GET", "/api/detect", "", 200)
	dc := out["decoy"].(map[string]any)
	if out["enabled"] != false || len(out["findings"].([]any)) != 0 || dc["enabled"] != false || len(dc["ports"].([]any)) != 0 || len(dc["touches"].([]any)) != 0 {
		t.Fatalf("status = %v", out)
	}
	if _, has := out["status"]; has {
		t.Error("no status without an engine")
	}
}

func TestDetectStatusFindingsAndDecoyPorts(t *testing.T) {
	h := newHarness(t)
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	det, err := detect.New(detect.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	dc := decoy.New(decoy.Options{Ports: []int{23}, Listen: func(string, string) (net.Listener, error) { return nil, errors.New("permission denied") }})
	dc.Start(context.Background())
	h.srv.Detect, h.srv.Decoy, h.srv.DetectEnabled = det, dc, true

	det.Observe(dnsengine.Entry{Time: now, Client: "192.0.2.5", Device: "TV", DeviceID: "d1", Name: "dns.google", Action: "allowed"})
	out := h.ok("GET", "/api/detect", "", 200)
	st := out["status"].(map[string]any)
	if out["enabled"] != true || st["learning"] != true || st["findings"] != 1.0 || st["traffic"] != false {
		t.Fatalf("status = %v", out)
	}
	f := out["findings"].([]any)[0].(map[string]any)
	if f["kind"] != "encrypted-dns" || f["device"] != "TV" || f["subject"] != "dns.google" || f["summary"] == "" {
		t.Fatalf("finding = %v", f)
	}
	port := out["decoy"].(map[string]any)["ports"].([]any)[0].(map[string]any)
	if out["decoy"].(map[string]any)["enabled"] != true || port["port"] != 23.0 || port["listening"] != false || port["error"] != "permission denied" {
		t.Fatalf("decoy = %v", out["decoy"])
	}
}
