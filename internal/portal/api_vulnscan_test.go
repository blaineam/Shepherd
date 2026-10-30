// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"net"
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
