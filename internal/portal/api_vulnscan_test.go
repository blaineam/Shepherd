// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shepherd/internal/portscan"
	"shepherd/internal/vulnscan"
)

// fakeVulnscanConn answers every Read with nothing (EOF-like): enough for
// the telnet-exposed signature, which only needs the connection itself to
// succeed, and harmless for every other probe (an empty banner/response
// just matches nothing).
type fakeVulnscanConn struct{}

func (fakeVulnscanConn) Read([]byte) (int, error)         { return 0, errors.New("no data") }
func (fakeVulnscanConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeVulnscanConn) Close() error                     { return nil }
func (fakeVulnscanConn) LocalAddr() net.Addr              { return nil }
func (fakeVulnscanConn) RemoteAddr() net.Addr             { return nil }
func (fakeVulnscanConn) SetDeadline(time.Time) error      { return nil }
func (fakeVulnscanConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeVulnscanConn) SetWriteDeadline(time.Time) error { return nil }

func fakeVulnscanDial(open map[string]bool) vulnscan.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if open[address] {
			return fakeVulnscanConn{}, nil
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
}

// seedPortscan runs a real portscan.Scanner against the harness's current
// devices so vulnscan has something to probe, exactly as cmd/shepherd's
// wiring would hand it portscan's own live results.
func (h *harness) seedPortscan(open map[string]bool) {
	h.t.Helper()
	ps := portscan.New(portscan.Options{
		Dial: fakePortscanDial(open), Ports: []int{21, 22, 23, 80}, Concurrency: 4, Timeout: time.Second,
	})
	ps.Scan(context.Background(), portscan.TargetsFromDevices(h.reg.List()))
	h.srv.Portscan = ps
}

func TestVulnscanStatus(t *testing.T) {
	h := newHarness(t)
	m := h.ok("GET", "/api/vulnscan", "", 200)
	if m["enabled"] != false {
		t.Errorf("enabled = %v, want false (the harness never starts the scheduled scan)", m["enabled"])
	}
	sigs, ok := m["signatures"].([]any)
	if !ok || len(sigs) == 0 {
		t.Fatalf("signatures = %v, want the built-in list", m["signatures"])
	}
	first := sigs[0].(map[string]any)
	if first["id"] == "" || first["severity"] == "" || first["description"] == "" {
		t.Fatalf("signature = %v, missing required fields", first)
	}

	h.srv.VulnscanEnabled = true
	m = h.ok("GET", "/api/vulnscan", "", 200)
	if m["enabled"] != true {
		t.Errorf("enabled = %v, want true once set", m["enabled"])
	}
}

func TestVulnscanDevicesEmptyUntilScanned(t *testing.T) {
	h := newHarness(t)
	m := h.ok("GET", "/api/vulnscan/devices", "", 200)
	devs, _ := m["devices"].([]any)
	if len(devs) != 0 {
		t.Fatalf("devices = %v, want none before any scan", devs)
	}
}

func TestVulnscanGetDeviceUnknown(t *testing.T) {
	h := newHarness(t)
	h.expect("GET", "/api/vulnscan/devices/nope", "", 404)
}

func TestVulnscanGetDeviceNeverScanned(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:00:00:00:10", "203.0.113.20", "")
	m := h.ok("GET", "/api/vulnscan/devices/"+id, "", 200)
	if m["device_id"] != id {
		t.Fatalf("device_id = %v, want %v", m["device_id"], id)
	}
	if _, has := m["last_scanned"]; has {
		t.Errorf("last_scanned present for a device never scanned: %v", m)
	}
	findings, _ := m["findings"].([]any)
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none", findings)
	}
}

func TestVulnscanScanNowAllDevices(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:00:00:00:11", "203.0.113.21", "kitchen-tv")
	h.seedPortscan(map[string]bool{net.JoinHostPort("203.0.113.21", "23"): true})
	h.srv.Vulnscan = vulnscan.New(vulnscan.Options{
		Dial:        fakeVulnscanDial(map[string]bool{net.JoinHostPort("203.0.113.21", "23"): true}),
		Concurrency: 4, Timeout: time.Second,
	})

	m := h.ok("POST", "/api/vulnscan/scan", "{}", 200)
	devs, _ := m["devices"].([]any)
	if len(devs) != 1 {
		t.Fatalf("scanned devices = %v, want 1", devs)
	}
	d := devs[0].(map[string]any)
	if d["device_id"] != id || d["ip"] != "203.0.113.21" {
		t.Fatalf("scanned device = %v", d)
	}
	findings := d["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want exactly one (telnet-exposed)", findings)
	}
	f := findings[0].(map[string]any)
	if f["signature_id"] != "telnet-exposed" || f["active"] != true || f["port"] != float64(23) {
		t.Fatalf("finding = %v, want an active telnet-exposed finding on port 23", f)
	}

	// Follow-up reads (without rescanning) see the same result.
	list := h.ok("GET", "/api/vulnscan/devices", "", 200)
	if ds := list["devices"].([]any); len(ds) != 1 {
		t.Fatalf("GET devices after a scan = %v", ds)
	}
	one := h.ok("GET", "/api/vulnscan/devices/"+id, "", 200)
	if one["name"] != "kitchen-tv" {
		t.Errorf("name = %v, want the device's known name", one["name"])
	}
}

func TestVulnscanScanNowOneDevice(t *testing.T) {
	h := newHarness(t)
	target := h.addDevice("02:00:00:00:00:12", "203.0.113.22", "")
	other := h.addDevice("02:00:00:00:00:13", "203.0.113.23", "")
	h.seedPortscan(map[string]bool{
		net.JoinHostPort("203.0.113.22", "23"): true,
		net.JoinHostPort("203.0.113.23", "23"): true,
	})
	h.srv.Vulnscan = vulnscan.New(vulnscan.Options{
		Dial: fakeVulnscanDial(map[string]bool{
			net.JoinHostPort("203.0.113.22", "23"): true,
			net.JoinHostPort("203.0.113.23", "23"): true,
		}), Concurrency: 4, Timeout: time.Second,
	})

	m := h.ok("POST", "/api/vulnscan/scan", `{"device_id":"`+target+`"}`, 200)
	devs, _ := m["devices"].([]any)
	if len(devs) != 1 || devs[0].(map[string]any)["device_id"] != target {
		t.Fatalf("scan one device = %v, want only %q", devs, target)
	}
	if _, ok := h.srv.Vulnscan.Result(other); ok {
		t.Error("scanning one device must not touch another device's record")
	}
}

func TestVulnscanScanNowUnknownDevice(t *testing.T) {
	h := newHarness(t)
	h.expect("POST", "/api/vulnscan/scan", `{"device_id":"nope"}`, 404)
}

func TestVulnscanScanNowDeviceWithNoOpenPortsSucceedsWithNoFindings(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:00:00:00:14", "203.0.113.24", "")
	h.seedPortscan(nil) // portscan ran, found nothing open
	h.srv.Vulnscan = vulnscan.New(vulnscan.Options{Dial: fakeVulnscanDial(nil)})
	m := h.ok("POST", "/api/vulnscan/scan", `{"device_id":"`+id+`"}`, 200)
	devs, _ := m["devices"].([]any)
	if len(devs) != 1 {
		t.Fatalf("devices = %v, want one (scanned, just nothing found)", devs)
	}
	findings, _ := devs[0].(map[string]any)["findings"].([]any)
	if len(findings) != 0 {
		t.Fatalf("findings = %v, want none", findings)
	}
}

func TestVulnscanScanNowDeviceNeverPortscanned(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:00:00:00:15", "203.0.113.25", "")
	h.expect("POST", "/api/vulnscan/scan", `{"device_id":"`+id+`"}`, 400)
}

const testFeedDoc = `{"schema": 1, "generated_at": "2026-11-01T06:00:00Z", "signatures": [
  {"id": "kev-cve-2024-6387", "name": "OpenSSH regreSSHion", "severity": "critical", "description": "d",
   "cves": ["CVE-2024-6387"], "ports": [22], "match": {"product": "openssh", "versions": [{"gte": "8.5", "lt": "9.8"}]}},
  {"id": "telnet-exposed", "name": "Telnet exposed (feed)", "severity": "critical", "description": "d", "ports": [23],
   "match": {"contains": "login:"}}
]}`

func TestVulnscanStatusReportsFeedSignaturesAndStatus(t *testing.T) {
	h := newHarness(t)
	m := h.ok("GET", "/api/vulnscan", "", 200)
	if m["feed"] != nil {
		t.Fatalf("feed = %v, want null when the harness has no feed", m["feed"])
	}
	builtin := len(vulnscan.BuiltinSignatures())
	if m["builtin_signatures"] != float64(builtin) || m["feed_signatures"] != float64(0) {
		t.Fatalf("counts = %v / %v", m["builtin_signatures"], m["feed_signatures"])
	}
	for _, s := range m["signatures"].([]any) {
		if s.(map[string]any)["source"] != "builtin" {
			t.Fatalf("every signature should be builtin with no feed: %v", s)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, testFeedDoc) }))
	defer srv.Close()
	h.srv.VulnscanFeed = &vulnscan.FeedUpdater{URL: srv.URL, OnChange: func(sigs []vulnscan.Signature, _ bool) { h.srv.Vulnscan.SetFeedSignatures(sigs) }}

	m = h.ok("POST", "/api/vulnscan/feed/refresh", "{}", 200)
	if m["changed"] != true {
		t.Fatalf("refresh = %v, want changed", m)
	}
	feed := m["feed"].(map[string]any)
	if feed["signatures"] != float64(2) || feed["url"] != srv.URL || feed["last_error"] != nil {
		t.Fatalf("feed status = %v", feed)
	}

	m = h.ok("GET", "/api/vulnscan", "", 200)
	// One feed signature is new, the other overrides telnet-exposed in place.
	if m["builtin_signatures"] != float64(builtin-1) || m["feed_signatures"] != float64(2) {
		t.Fatalf("counts after feed = %v / %v", m["builtin_signatures"], m["feed_signatures"])
	}
	var kev map[string]any
	for _, s := range m["signatures"].([]any) {
		if sm := s.(map[string]any); sm["id"] == "kev-cve-2024-6387" {
			kev = sm
		}
	}
	if kev == nil || kev["source"] != "feed" || kev["cves"].([]any)[0] != "CVE-2024-6387" {
		t.Fatalf("feed signature = %v", kev)
	}
	if m["feed"].(map[string]any)["generated_at"] == nil {
		t.Fatalf("feed status missing generated_at: %v", m["feed"])
	}

	// Unchanged upstream: still 200, just not changed.
	m = h.ok("POST", "/api/vulnscan/feed/refresh", "{}", 200)
	if m["changed"] != false {
		t.Fatalf("second refresh = %v", m)
	}
}

func TestVulnscanFeedRefreshFailures(t *testing.T) {
	h := newHarness(t)
	h.expect("POST", "/api/vulnscan/feed/refresh", "{}", 400) // feed disabled

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	h.srv.VulnscanFeed = &vulnscan.FeedUpdater{URL: srv.URL}
	h.expect("POST", "/api/vulnscan/feed/refresh", "{}", 502)
	m := h.ok("GET", "/api/vulnscan", "", 200)
	if le := m["feed"].(map[string]any)["last_error"]; le == nil || !strings.Contains(le.(string), "HTTP 503") {
		t.Fatalf("last_error = %v", le)
	}
}

func TestVulnscanDevicesReportResolvedFindings(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:00:00:00:14", "203.0.113.24", "attic-cam")
	path := filepath.Join(t.TempDir(), "vulnscan.json")
	doc := fmt.Sprintf(`{"devices": {%q: {"device_id": %q, "ip": "203.0.113.24", "last_scanned": "2026-10-30T10:00:00Z", "findings": [
	  {"signature_id": "telnet-exposed", "name": "Telnet exposed", "description": "d", "severity": "high", "port": 23,
	   "active": false, "first_seen": "2026-10-01T10:00:00Z", "last_seen": "2026-10-20T10:00:00Z", "resolved_at": "2026-10-30T10:00:00Z"}]}}}`, id, id)
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Vulnscan.Load(path); err != nil {
		t.Fatal(err)
	}
	m := h.ok("GET", "/api/vulnscan/devices/"+id, "", 200)
	findings := m["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings = %v", findings)
	}
	f := findings[0].(map[string]any)
	if f["active"] != false || f["resolved_at"] == nil || !strings.HasPrefix(f["resolved_at"].(string), "2026-10-30") {
		t.Fatalf("resolved finding = %v", f)
	}
}
