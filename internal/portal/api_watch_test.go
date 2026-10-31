// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"shepherd/internal/watch"
)

// fakeWatch is a WatchEngine with no kernel behind it: the engine's own
// behaviour is tested in internal/watch, so what matters here is that the
// API reports it faithfully and that the kill switch reaches it.
type fakeWatch struct {
	snap     watch.Snapshot
	killErr  error
	rearmErr error
	kills    int
	rearms   int
	byDevice map[string]watch.DeviceStatus
}

func (f *fakeWatch) Snapshot() watch.Snapshot { return f.snap }
func (f *fakeWatch) DeviceStatuses() map[string]watch.DeviceStatus {
	return f.byDevice
}
func (f *fakeWatch) Kill() error {
	f.kills++
	if f.killErr != nil {
		return f.killErr
	}
	f.snap.Armed = false
	return nil
}
func (f *fakeWatch) Rearm() error {
	f.rearms++
	if f.rearmErr != nil {
		return f.rearmErr
	}
	f.snap.Armed = true
	return nil
}

var _ WatchEngine = (*fakeWatch)(nil)

// linkLocalText is a link-local address as the engine would report it,
// assembled rather than written out so no link-local literal is in the
// source (the same convention internal/ndp's tests use).
var linkLocalText = netip.AddrFrom16([16]byte{0xfe, 0x80, 15: 0x01}).String()

func runningWatch() *fakeWatch {
	return &fakeWatch{snap: watch.Snapshot{
		Enabled: true, Phase: watch.PhaseRunning, Relay: watch.RelayXDPNative, Armed: true,
		Interface: "eth0", GatewayIP: "192.0.2.1", GatewayMAC: "02:00:5e:00:00:01",
		ShepherdMAC: "02:00:5e:00:00:02", ShepherdIPs: []string{"192.0.2.2"},
		Steered: 1, Since: time.Now(),
		Stats:   watch.RelayStats{FramesRelayed: 1000, BytesRelayed: 1 << 20, PacketsPerSecond: 120, BytesPerSecond: 4096},
		Devices: []watch.DeviceStatus{{DeviceID: "d1", Name: "Phone", State: watch.StateSteered, Healthy: true}},
		History: []watch.HistoryRecord{{MAC: "02:00:5e:00:00:10", Reason: "panic stop", Time: time.Now()}},
	}}
}

func TestWatchStatusWithoutAnEngineIsHonestNotAnError(t *testing.T) {
	h := newHarness(t)
	out := h.ok("GET", "/api/watch", "", 200)
	if out["enabled"] != false || out["phase"] != watch.PhaseDisabled || out["reason"] == "" {
		t.Fatalf("status = %v", out)
	}
	if len(out["devices"].([]any)) != 0 || len(out["history"].([]any)) != 0 {
		t.Fatalf("status = %v", out)
	}
	// The kill switch cannot be pressed when there is nothing to kill.
	h.expect("POST", "/api/watch/kill", "", 404)
	h.expect("POST", "/api/watch/rearm", "", 404)
}

func TestWatchStatusReportsTheEngine(t *testing.T) {
	h := newHarness(t)
	fw := runningWatch()
	h.srv.Watch = fw
	out := h.ok("GET", "/api/watch", "", 200)
	if out["enabled"] != true || out["phase"] != watch.PhaseRunning || out["relay"] != watch.RelayXDPNative {
		t.Fatalf("status = %v", out)
	}
	if out["armed"] != true || out["interface"] != "eth0" || out["gateway_mac"] != "02:00:5e:00:00:01" || out["steered"] != 1.0 {
		t.Fatalf("status = %v", out)
	}
	stats := out["stats"].(map[string]any)
	if stats["frames_relayed"] != 1000.0 || stats["packets_per_second"] != 120.0 {
		t.Fatalf("stats = %v", stats)
	}
	devs := out["devices"].([]any)
	if len(devs) != 1 || devs[0].(map[string]any)["state"] != watch.StateSteered {
		t.Fatalf("devices = %v", devs)
	}
	if len(out["history"].([]any)) != 1 {
		t.Fatalf("history = %v", out["history"])
	}
}

func TestWatchKillAndRearm(t *testing.T) {
	h := newHarness(t)
	fw := runningWatch()
	h.srv.Watch = fw
	out := h.ok("POST", "/api/watch/kill", "", 200)
	if fw.kills != 1 || out["armed"] != false {
		t.Fatalf("kill: kills=%d out=%v", fw.kills, out)
	}
	out = h.ok("POST", "/api/watch/rearm", "", 200)
	if fw.rearms != 1 || out["armed"] != true {
		t.Fatalf("rearm: rearms=%d out=%v", fw.rearms, out)
	}
	// A kill switch that stopped steering but could not be persisted is a
	// 500, not a silent success: the owner must know it may come back.
	fw.killErr = errors.New("read-only file system")
	h.expect("POST", "/api/watch/kill", "", 500)
	fw.rearmErr = errors.New("read-only file system")
	h.expect("POST", "/api/watch/rearm", "", 500)
}

func TestDeviceCarriesTheWatchSwitchAndState(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:5e:00:00:10", "192.0.2.10", "phone")

	// Without an engine there is a switch but no state at all.
	d := h.ok("GET", "/api/devices/"+id, "", 200)
	if d["watch"] != "auto" {
		t.Fatalf("watch = %v", d["watch"])
	}
	if _, has := d["watch_state"]; has {
		t.Fatal("watch_state must be absent when Watch mode is not wired in")
	}

	fw := runningWatch()
	fw.byDevice = map[string]watch.DeviceStatus{id: {DeviceID: id, Name: "phone", State: watch.StateSteered,
		Healthy: true, BytesRelayed: 4096, PacketsRelayed: 32, BytesPerSecond: 512}}
	h.srv.Watch = fw

	d = h.ok("GET", "/api/devices/"+id, "", 200)
	st := d["watch_state"].(map[string]any)
	if st["state"] != watch.StateSteered || st["healthy"] != true || st["bytes_relayed"] != 4096.0 || st["bytes_per_second"] != 512.0 {
		t.Fatalf("watch_state = %v", st)
	}
	list := h.ok("GET", "/api/devices", "", 200)["devices"].([]any)
	if list[0].(map[string]any)["watch_state"].(map[string]any)["state"] != watch.StateSteered {
		t.Fatalf("list = %v", list)
	}

	// The switch is editable, and only to the three known positions.
	for _, want := range []string{"off", "on", "auto"} {
		d = h.ok("PATCH", "/api/devices/"+id, `{"watch":"`+want+`"}`, 200)
		if d["watch"] != want {
			t.Fatalf("watch = %v, want %q", d["watch"], want)
		}
	}
	h.expect("PATCH", "/api/devices/"+id, `{"watch":"maybe"}`, 400)

	// And in bulk.
	res := h.ok("POST", "/api/devices/bulk", `{"ids":["`+id+`"],"op":"set_watch","watch":"off"}`, 200)
	if res["changed"] != 1.0 {
		t.Fatalf("bulk = %v", res)
	}
	if d = h.ok("GET", "/api/devices/"+id, "", 200); d["watch"] != "off" {
		t.Fatalf("watch = %v", d["watch"])
	}
	h.expect("POST", "/api/devices/bulk", `{"ids":["`+id+`"],"op":"set_watch"}`, 400)
	h.expect("POST", "/api/devices/bulk", `{"ids":["`+id+`"],"op":"set_watch","watch":"maybe"}`, 400)
}

func TestWatchStatusReportsIPv6State(t *testing.T) {
	h := newHarness(t)
	fw := runningWatch()
	// Asked for, but the network cannot carry it: the portal says why
	// rather than showing it as on or hiding it.
	fw.snap.IPv6Wanted = true
	fw.snap.IPv6Reason = "this network has no global IPv6 route (unique-local addresses only), so there is no off-link IPv6 traffic to steer"
	h.srv.Watch = fw
	out := h.ok("GET", "/api/watch", "", 200)
	if out["ipv6"] != false || out["ipv6_wanted"] != true {
		t.Fatalf("status = %v", out)
	}
	if !strings.Contains(out["ipv6_reason"].(string), "no global IPv6 route") {
		t.Fatalf("reason = %v", out["ipv6_reason"])
	}

	fw.snap.IPv6, fw.snap.IPv6Reason, fw.snap.GatewayLinkLocal = true, "", linkLocalText
	fw.snap.Devices = []watch.DeviceStatus{{DeviceID: "d1", Name: "Phone", State: watch.StateSteered, Healthy: true,
		Families: []string{"ipv4", "ipv6"}, Steered: []watch.SteeredEntry{{MAC: "02:00:5e:00:00:10", IP: "192.0.2.10", Families: []string{"ipv4", "ipv6"}}}}}
	out = h.ok("GET", "/api/watch", "", 200)
	if out["ipv6"] != true || out["gateway_link_local"] != linkLocalText {
		t.Fatalf("status = %v", out)
	}
	d := out["devices"].([]any)[0].(map[string]any)
	fams := d["families"].([]any)
	if len(fams) != 2 || fams[1] != "ipv6" {
		t.Fatalf("families = %v", fams)
	}
}
