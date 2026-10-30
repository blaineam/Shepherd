// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"shepherd/internal/devices"
	"shepherd/internal/portscan"
)

// fakePortscanConn and fakePortscanDial let these tests drive the real
// Scanner end to end through the portal API without ever touching a real
// socket: a closed map of addresses answers "open", everything else is a
// simulated connection refusal.
type fakePortscanConn struct{}

func (fakePortscanConn) Read([]byte) (int, error)         { return 0, errors.New("no data") }
func (fakePortscanConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakePortscanConn) Close() error                     { return nil }
func (fakePortscanConn) LocalAddr() net.Addr              { return nil }
func (fakePortscanConn) RemoteAddr() net.Addr             { return nil }
func (fakePortscanConn) SetDeadline(time.Time) error      { return nil }
func (fakePortscanConn) SetReadDeadline(time.Time) error  { return nil }
func (fakePortscanConn) SetWriteDeadline(time.Time) error { return nil }

func fakePortscanDial(open map[string]bool) portscan.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if open[address] {
			return fakePortscanConn{}, nil
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
}

func TestPortscanStatus(t *testing.T) {
	h := newHarness(t)
	m := h.ok("GET", "/api/portscan", "", 200)
	if m["enabled"] != false {
		t.Errorf("enabled = %v, want false (the harness never starts the scheduled scan)", m["enabled"])
	}
	ports, ok := m["ports"].([]any)
	if !ok || len(ports) == 0 {
		t.Fatalf("ports = %v, want the built-in default list", m["ports"])
	}
	risky, ok := m["risky_ports"].(map[string]any)
	if !ok || len(risky) == 0 {
		t.Fatalf("risky_ports = %v, want a non-empty map", m["risky_ports"])
	}
	if note, ok := risky["23"]; !ok || note == "" {
		t.Errorf("risky_ports[23] = %v, want telnet's reason", note)
	}

	h.srv.PortscanEnabled = true
	m = h.ok("GET", "/api/portscan", "", 200)
	if m["enabled"] != true {
		t.Errorf("enabled = %v, want true once set", m["enabled"])
	}
}

func TestPortscanDevicesEmptyUntilScanned(t *testing.T) {
	h := newHarness(t)
	m := h.ok("GET", "/api/portscan/devices", "", 200)
	devs, _ := m["devices"].([]any)
	if len(devs) != 0 {
		t.Fatalf("devices = %v, want none before any scan", devs)
	}
}

func TestPortscanGetDeviceUnknown(t *testing.T) {
	h := newHarness(t)
	h.expect("GET", "/api/portscan/devices/nope", "", 404)
}

func TestPortscanGetDeviceNeverScanned(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:00:00:00:01", "203.0.113.10", "")
	m := h.ok("GET", "/api/portscan/devices/"+id, "", 200)
	if m["device_id"] != id {
		t.Fatalf("device_id = %v, want %v", m["device_id"], id)
	}
	if _, has := m["last_scanned"]; has {
		t.Errorf("last_scanned present for a device never scanned: %v", m)
	}
	ports, _ := m["ports"].([]any)
	if len(ports) != 0 {
		t.Errorf("ports = %v, want none", ports)
	}
}

func TestPortscanScanNowAllDevices(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:00:00:00:02", "203.0.113.11", "kitchen-tv")
	h.srv.Portscan = portscan.New(portscan.Options{
		Dial:  fakePortscanDial(map[string]bool{net.JoinHostPort("203.0.113.11", "23"): true}),
		Ports: []int{22, 23}, Concurrency: 4, Timeout: time.Second,
	})

	m := h.ok("POST", "/api/portscan/scan", "{}", 200)
	devs, _ := m["devices"].([]any)
	if len(devs) != 1 {
		t.Fatalf("scanned devices = %v, want 1", devs)
	}
	d := devs[0].(map[string]any)
	if d["device_id"] != id || d["ip"] != "203.0.113.11" {
		t.Fatalf("scanned device = %v", d)
	}
	ports := d["ports"].([]any)
	if len(ports) != 1 {
		t.Fatalf("ports = %v, want only port 23", ports)
	}
	p := ports[0].(map[string]any)
	if p["port"] != float64(23) || p["open"] != true || p["risky"] != true {
		t.Fatalf("port record = %v, want open+risky port 23", p)
	}

	// Follow-up reads (without rescanning) see the same result.
	list := h.ok("GET", "/api/portscan/devices", "", 200)
	if ds := list["devices"].([]any); len(ds) != 1 {
		t.Fatalf("GET devices after a scan = %v", ds)
	}
	one := h.ok("GET", "/api/portscan/devices/"+id, "", 200)
	if one["name"] != "kitchen-tv" {
		t.Errorf("name = %v, want the device's known name", one["name"])
	}
}

func TestPortscanScanNowOneDevice(t *testing.T) {
	h := newHarness(t)
	target := h.addDevice("02:00:00:00:00:03", "203.0.113.12", "")
	other := h.addDevice("02:00:00:00:00:04", "203.0.113.13", "")
	h.srv.Portscan = portscan.New(portscan.Options{
		Dial: fakePortscanDial(nil), Ports: []int{22}, Concurrency: 4, Timeout: time.Second,
	})

	m := h.ok("POST", "/api/portscan/scan", `{"device_id":"`+target+`"}`, 200)
	devs, _ := m["devices"].([]any)
	if len(devs) != 1 || devs[0].(map[string]any)["device_id"] != target {
		t.Fatalf("scan one device = %v, want only %q", devs, target)
	}
	if _, ok := h.srv.Portscan.Result(other); ok {
		t.Error("scanning one device must not touch another device's record")
	}
}

func TestPortscanScanNowUnknownDevice(t *testing.T) {
	h := newHarness(t)
	h.expect("POST", "/api/portscan/scan", `{"device_id":"nope"}`, 404)
}

func TestPortscanScanNowDeviceWithNoAddress(t *testing.T) {
	h := newHarness(t)
	// A MAC-only observation (no IP) creates a device with no current address.
	id := h.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:00:00:00:05", Time: time.Now()})
	if id == "" {
		t.Fatal("observation was rejected")
	}
	h.expect("POST", "/api/portscan/scan", `{"device_id":"`+id+`"}`, 400)
}
