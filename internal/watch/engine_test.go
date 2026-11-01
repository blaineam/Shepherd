// SPDX-License-Identifier: AGPL-3.0-or-later

package watch

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"shepherd/internal/arp"
	"shepherd/internal/devices"
	"shepherd/internal/intercept"
	"shepherd/internal/traffic"
)

func TestNewRequiresARegistry(t *testing.T) {
	if _, err := New(Config{Enabled: true}); err != ErrNoRegistry {
		t.Fatalf("err = %v", err)
	}
}

func TestDisabledEngineReturnsAtOnceAndReportsDisabled(t *testing.T) {
	for _, mut := range []func(*Config){func(c *Config) { c.Enabled = false }, func(c *Config) { c.Mode = ModeOff }} {
		te := newTestEngine(t, newFakePlatform(), mut)
		te.addPhone(t)
		if err := te.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		snap := te.Snapshot()
		if snap.Enabled || snap.Phase != PhaseDisabled || snap.Reason == "" {
			t.Fatalf("snapshot = %+v", snap)
		}
		if len(snap.Devices) != 1 || snap.Devices[0].State != StateUnavailable {
			t.Fatalf("devices = %+v", snap.Devices)
		}
		if xdp, relay := te.plat.counts(); xdp+relay != 0 {
			t.Fatal("a disabled engine attached a relay")
		}
	}
}

func TestSteersAnEligibleDeviceThroughXDPAndUnsteersOnClose(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, nil)
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	snap := te.Snapshot()
	if snap.Relay != RelayXDPNative || snap.GatewayMAC != gwMAC.String() || snap.ShepherdMAC != shepherdMAC.String() || snap.Interface != "eth0" || !snap.Armed {
		t.Fatalf("snapshot = %+v", snap)
	}
	if snap.ShepherdIPs[0] != shepherdIP.String() || snap.GatewayIP != gwIP.String() || snap.Steered != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
	ds := te.status(t, id)
	if ds.State != StateSteered || len(ds.Steered) != 1 || ds.Steered[0].IP != phoneIP.String() || ds.Name != "phone" {
		t.Fatalf("device = %+v", ds)
	}
	if xdp, relay := plat.counts(); xdp != 1 || relay != 0 {
		t.Fatalf("attach counts xdp=%d relay=%d", xdp, relay)
	}
	if len(plat.groSets) != 0 {
		t.Fatal("XDP mode must leave GRO alone")
	}
	// The Spoofer's first claim went out through the platform's sender.
	waitFor(t, "an ARP claim", func() bool { return len(plat.sender.Frames()) > 0 })

	te.stop()
	<-te.done
	// Close unsteered the device; the corrective reply is the last frame.
	snap = te.Snapshot()
	if snap.Phase != PhaseUnavailable || snap.Steered != 0 {
		t.Fatalf("after stop: %+v", snap)
	}
	var sawClosed bool
	for _, h := range snap.History {
		if h.MAC == phoneMAC.String() && h.Reason == "controller closed" && h.DeviceID == id && h.Name == "phone" {
			sawClosed = true
		}
	}
	if !sawClosed {
		t.Fatalf("history = %+v", snap.History)
	}
}

func TestFallsBackToUserspaceWithGROOffAndRestoresIt(t *testing.T) {
	plat := newFakePlatform()
	plat.xdpErr = errBoom
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	if snap := te.Snapshot(); snap.Relay != RelayUserspace {
		t.Fatalf("relay = %q", snap.Relay)
	}
	if _, relay := plat.counts(); relay != 1 {
		t.Fatal("userspace relay not started")
	}
	plat.mu.Lock()
	sets := append([]bool(nil), plat.groSets...)
	plat.mu.Unlock()
	if len(sets) != 1 || sets[0] {
		t.Fatalf("GRO sets = %v, want [false]", sets)
	}
	te.stop()
	<-te.done
	plat.mu.Lock()
	defer plat.mu.Unlock()
	if len(plat.groSets) != 2 || !plat.groSets[1] || !plat.gro {
		t.Fatalf("GRO sets after stop = %v", plat.groSets)
	}
}

func TestUserspaceWithGROAlreadyOffDoesNotTouchIt(t *testing.T) {
	plat := newFakePlatform()
	plat.xdpErr = errBoom
	plat.gro = false
	te := newTestEngine(t, plat, func(c *Config) { c.Mode = ModeUserspace })
	te.start(t)
	te.waitRunning(t)
	te.stop()
	<-te.done
	if xdp, _ := plat.counts(); xdp != 0 || len(plat.groSets) != 0 {
		t.Fatalf("xdp=%d groSets=%v", xdp, plat.groSets)
	}
}

func TestModeXDPDoesNotFallBack(t *testing.T) {
	plat := newFakePlatform()
	plat.xdpErr = errBoom
	te := newTestEngine(t, plat, func(c *Config) { c.Mode = ModeXDP })
	te.start(t)
	waitFor(t, "unavailable", func() bool {
		s := te.Snapshot()
		return s.Phase == PhaseUnavailable && strings.Contains(s.Reason, "no fallback")
	})
	if _, relay := plat.counts(); relay != 0 {
		t.Fatal("mode=xdp must never start the userspace relay")
	}
}

func TestRefusesCleanlyWithoutCapabilitiesAndRetriesOnABackoff(t *testing.T) {
	plat := newFakePlatform()
	plat.senderErr = errBoom
	te := newTestEngine(t, plat, nil)
	id := te.addPhone(t)
	te.start(t)
	waitFor(t, "unavailable", func() bool { return te.Snapshot().Phase == PhaseUnavailable })
	snap := te.Snapshot()
	if !strings.Contains(snap.Reason, "raw socket") || snap.Relay != "" {
		t.Fatalf("snapshot = %+v", snap)
	}
	if ds := te.status(t, id); ds.State != StateUnavailable {
		t.Fatalf("device = %+v", ds)
	}
	waitFor(t, "a retry timer", func() bool { return te.clock.Pending() > 0 })
	// Fix the platform; the next retry (after the backoff) runs.
	plat.mu.Lock()
	plat.senderErr = nil
	plat.mu.Unlock()
	te.clock.Advance(restartBackoffMin)
	te.waitRunning(t)
	// The same failure reason is logged once, not once per retry.
	n := 0
	for _, l := range te.logs.all() {
		if strings.Contains(l, "not running") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("'not running' logged %d times: %v", n, te.logs.all())
	}
}

func TestUnsupportedPlatformReportsUnsupported(t *testing.T) {
	plat := newFakePlatform()
	plat.unsupported = true
	te := newTestEngine(t, plat, nil)
	te.start(t)
	waitFor(t, "unavailable", func() bool { return te.Snapshot().Phase == PhaseUnavailable })
	if !strings.Contains(te.Snapshot().Reason, "only supported on Linux") {
		t.Fatalf("reason = %q", te.Snapshot().Reason)
	}
}

func TestPolicyIsEnforcedAndFollowedLive(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, nil)
	id := te.addPhone(t)
	// A router, an excluded device and the gateway itself are never steered.
	routerMAC := mustMAC("02:00:5e:00:00:20")
	routerID := te.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: routerMAC.String(), IP: "192.0.2.20"})
	if err := te.reg.SetType(routerID, string(devices.TypeRouter)); err != nil {
		t.Fatal(err)
	}
	exclMAC := mustMAC("02:00:5e:00:00:21")
	exclID := te.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: exclMAC.String(), IP: "192.0.2.21"})
	if err := te.reg.SetExcluded(exclID, true); err != nil {
		t.Fatal(err)
	}
	gwID := te.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: gwMAC.String(), IP: gwIP.String()})
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	for _, m := range []arp.MAC{routerMAC, exclMAC, gwMAC} {
		if te.isSteered(m) {
			t.Fatalf("%s must never be steered", m)
		}
	}
	for id, want := range map[string]string{routerID: "infrastructure", exclID: "excluded", gwID: "gateway"} {
		if ds := te.status(t, id); ds.State != StateSkipped || !strings.Contains(ds.Reason, want) {
			t.Errorf("%s: %+v", want, ds)
		}
	}
	// The Controller's own Excluder agrees, even if asked directly.
	if !te.Excluded(routerMAC) || !te.Excluded(exclMAC) || te.Excluded(phoneMAC) || !te.Excluded(mustMAC("02:00:5e:00:00:99")) {
		t.Fatal("Excluder disagrees with the policy")
	}

	// Switching the phone's Watch off unsteers it; back to auto re-steers.
	if err := te.reg.SetWatch(id, devices.WatchOff); err != nil {
		t.Fatal(err)
	}
	te.waitSteered(t, phoneMAC, false)
	if ds := te.status(t, id); ds.State != StateSkipped || !strings.Contains(ds.Reason, "switched off") {
		t.Fatalf("device = %+v", ds)
	}
	if err := te.reg.SetWatch(id, devices.WatchAuto); err != nil {
		t.Fatal(err)
	}
	te.waitSteered(t, phoneMAC, true)

	// Watch "on" steers the router after all.
	if err := te.reg.SetWatch(routerID, devices.WatchOn); err != nil {
		t.Fatal(err)
	}
	te.waitSteered(t, routerMAC, true)

	// Excluding the phone unsteers it, and the history says why.
	if err := te.reg.SetExcluded(id, true); err != nil {
		t.Fatal(err)
	}
	te.waitSteered(t, phoneMAC, false)
	var found bool
	for _, h := range te.Snapshot().History {
		if h.MAC == phoneMAC.String() && h.Reason == "unsteered by caller" {
			found = true
		}
	}
	if !found {
		t.Fatalf("history = %+v", te.Snapshot().History)
	}
}

func TestWanderingAndQuarantinedDevicesAreSteered(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), nil)
	id := te.addPhone(t)
	if err := te.reg.SetWandering(id, true, time.Time{}); err != nil {
		t.Fatal(err)
	}
	te.reg.EnsureQuarantineGroup()
	if _, err := te.reg.BulkAssignGroup([]string{id}, devices.QuarantineGroupID); err != nil {
		t.Fatal(err)
	}
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
}

func TestResteersOnAddressChange(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), nil)
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	newIP := netip.MustParseAddr("192.0.2.77")
	te.clock.Advance(time.Second) // IPSeen must move forward for the new address to win
	te.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: phoneMAC.String(), IP: newIP.String()})
	waitFor(t, "re-steer with the new address", func() bool {
		te.poke(te.kick)
		te.mu.Lock()
		c := te.ctrl
		te.mu.Unlock()
		for _, d := range c.Status() {
			if d.MAC == phoneMAC && d.IP == newIP {
				return true
			}
		}
		return false
	})
	var changed bool
	for _, h := range te.Snapshot().History {
		if h.MAC == phoneMAC.String() {
			changed = true
		}
	}
	if !changed {
		t.Fatal("the address change should be in the history")
	}
}

// A device that goes quiet past the active window is unsteered by the
// policy, not by a health failure, so it carries no backoff and is steered
// again the moment it is seen. The grace windows here are long enough that
// the health loop cannot race the policy for the unsteer, which is what
// makes the "steered again at once" half of this deterministic.
func TestIdleDeviceIsUnsteeredAndSteeredAgainWhenSeen(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), func(c *Config) { c.StartupGrace = time.Hour; c.IdleGrace = time.Hour })
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	te.clock.Advance(DefaultActiveWindow + time.Minute)
	te.waitSteered(t, phoneMAC, false)
	ds := te.status(t, id)
	if ds.State != StateIdle || !strings.Contains(ds.Reason, "not seen") || ds.Failures != 0 {
		t.Fatalf("device = %+v", ds)
	}
	te.reg.Observe(devices.Observation{Source: devices.SourceDNS, MAC: phoneMAC.String(), IP: phoneIP.String()})
	te.waitSteered(t, phoneMAC, true)
}

func TestHealthFailureBacksOffThenRetries(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), func(c *Config) { c.StartupGrace = 10 * time.Second; c.HealthInterval = time.Second })
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	// Nothing ever relays for the phone: StartupGrace fails it open.
	te.clock.Advance(11 * time.Second)
	te.waitSteered(t, phoneMAC, false)
	te.waitFailures(t, id, 1)
	ds := te.status(t, id)
	if ds.State != StatePending || ds.Failures != 1 || ds.NextRetry.IsZero() || !strings.Contains(ds.Reason, "failed open 1 time") {
		t.Fatalf("device = %+v", ds)
	}
	// Still on the backoff: reconcile must not steer it.
	te.poke(te.kick)
	time.Sleep(20 * time.Millisecond)
	if te.isSteered(phoneMAC) {
		t.Fatal("re-steered inside the backoff")
	}
	// Keep the device "seen" so it stays eligible, then let the backoff pass.
	te.reg.Observe(devices.Observation{Source: devices.SourceDNS, MAC: phoneMAC.String(), IP: phoneIP.String()})
	te.clock.Advance(retryBase)
	te.waitSteered(t, phoneMAC, true)
	// A second failure doubles the backoff.
	te.clock.Advance(11 * time.Second)
	te.waitSteered(t, phoneMAC, false)
	te.waitFailures(t, id, 2)
	if ds := te.status(t, id); ds.Failures != 2 || ds.NextRetry.Sub(te.clock.Now()) > 2*retryBase || ds.NextRetry.Sub(te.clock.Now()) <= retryBase {
		t.Fatalf("device = %+v now=%s", ds, te.clock.Now())
	}
}

// relayFrame is a minimal IPv4 frame from the phone to Shepherd's MAC, the
// shape the Relay relays, so the FakeSender-backed relay path can credit
// the phone with traffic. Each call is a different packet (the IP ID
// moves), as a device's traffic is; echoFrame is the same packet every
// time, as a loop delivers it.
var relayFrameID atomic.Uint32

func relayFrame() []byte {
	f := echoFrame()
	id := uint16(relayFrameID.Add(1))
	f[14+4], f[14+5] = byte(id>>8), byte(id)
	return f
}

func echoFrame() []byte {
	f := make([]byte, 14+20+8)
	copy(f[0:6], shepherdMAC[:])
	copy(f[6:12], phoneMAC[:])
	f[12], f[13] = 0x08, 0x00
	ip := f[14:]
	ip[0] = 0x45
	ip[2], ip[3] = 0, 28
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], phoneIP.AsSlice())
	copy(ip[16:20], []byte{198, 51, 100, 1})
	return f
}

func TestRelayedTrafficFeedsRatesHealthAndTheRegistry(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), nil)
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	te.mu.Lock()
	c := te.ctrl
	te.mu.Unlock()
	for i := 0; i < 10; i++ {
		if relayed, err := c.HandleFrame(relayFrame()); err != nil || !relayed {
			t.Fatalf("relay: %v %v", relayed, err)
		}
	}
	before, _ := te.reg.Get(id)
	te.clock.Advance(time.Second) // one tick: sample() runs
	// Wait on the rate itself, not on the relayed total: the total comes
	// straight from the Controller and is there before sample() has run.
	waitFor(t, "rates", func() bool { return te.status(t, id).PacketsPerSecond > 0 })
	ds := te.status(t, id)
	if !ds.Healthy || ds.BytesRelayed != 10*42 || ds.PacketsPerSecond <= 0 || ds.BytesPerSecond <= 0 {
		t.Fatalf("device = %+v", ds)
	}
	snap := te.Snapshot()
	if snap.Stats.FramesRelayed != 10 || snap.Stats.BytesRelayed != 420 || snap.Stats.PacketsPerSecond <= 0 {
		t.Fatalf("stats = %+v", snap.Stats)
	}
	after, _ := te.reg.Get(id)
	if !after.LastSeen.After(before.LastSeen) {
		t.Fatalf("relayed traffic should count as a sighting: %s -> %s", before.LastSeen, after.LastSeen)
	}
}

func TestKillSwitchStopsEverythingPersistsAndRearms(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, nil)
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	if err := te.Kill(); err != nil {
		t.Fatal(err)
	}
	if te.isSteered(phoneMAC) || te.Armed() {
		t.Fatal("kill did not unsteer")
	}
	te.poke(te.kick)
	time.Sleep(20 * time.Millisecond)
	if te.isSteered(phoneMAC) {
		t.Fatal("re-steered while killed")
	}
	snap := te.Snapshot()
	if snap.Armed || snap.Phase != PhaseRunning {
		t.Fatalf("snapshot = %+v", snap)
	}
	if ds := te.status(t, id); ds.State != StateUnavailable {
		t.Fatalf("device while killed = %+v", ds)
	}
	var panicked bool
	for _, h := range snap.History {
		if h.Reason == "panic stop" && h.MAC == phoneMAC.String() {
			panicked = true
		}
	}
	if !panicked {
		t.Fatalf("history = %+v", snap.History)
	}
	b, err := os.ReadFile(te.cfg.StatePath)
	if err != nil || !strings.Contains(string(b), `"killed": true`) {
		t.Fatalf("state file: %q %v", b, err)
	}

	// A fresh engine over the same state file starts killed and steers nothing.
	te2 := newTestEngine(t, newFakePlatform(), func(c *Config) { c.StatePath = te.cfg.StatePath })
	te2.addPhone(t)
	te2.start(t)
	te2.waitRunning(t)
	time.Sleep(20 * time.Millisecond)
	if te2.isSteered(phoneMAC) || te2.Armed() {
		t.Fatal("a restart must not re-arm the kill switch")
	}
	if err := te2.Rearm(); err != nil {
		t.Fatal(err)
	}
	te2.waitSteered(t, phoneMAC, true)
	if !te2.Armed() {
		t.Fatal("not armed")
	}
	b, _ = os.ReadFile(te.cfg.StatePath)
	if !strings.Contains(string(b), `"killed": false`) {
		t.Fatalf("state file after rearm: %q", b)
	}
}

func TestRelayDeathPanicStopsAndRestarts(t *testing.T) {
	plat := newFakePlatform()
	plat.xdpDie = make(chan error, 1)
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	plat.xdpDie <- errBoom
	waitFor(t, "unavailable after relay death", func() bool {
		s := te.Snapshot()
		return s.Phase == PhaseUnavailable && strings.Contains(s.Reason, "boom")
	})
	if te.isSteered(phoneMAC) {
		t.Fatal("devices must be unsteered when the relay dies")
	}
	waitFor(t, "a retry timer", func() bool { return te.clock.Pending() > 0 })
	te.clock.Advance(restartBackoffMin)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	if xdp, _ := plat.counts(); xdp != 2 {
		t.Fatalf("xdp attached %d times, want 2", xdp)
	}
}

func TestGatewayMACChangeRestartsWithTheNewMAC(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	// A prompt with nothing behind it changes nothing.
	te.GatewayChanged()
	time.Sleep(20 * time.Millisecond)
	if s := te.Snapshot(); s.Phase != PhaseRunning || s.GatewayMAC != gwMAC.String() {
		t.Fatalf("snapshot = %+v", s)
	}
	// The kernel's table really moved: everything is unsteered and the
	// engine comes back with the new MAC.
	newGW := mustMAC("02:00:5e:00:00:ff")
	plat.setGatewayMAC(newGW)
	te.GatewayChanged()
	waitFor(t, "restart with the new gateway MAC", func() bool {
		if te.clock.Pending() > 0 {
			te.clock.Advance(2 * time.Second)
		}
		s := te.Snapshot()
		return s.Phase == PhaseRunning && s.GatewayMAC == newGW.String()
	})
	te.waitSteered(t, phoneMAC, true)
	var saw bool
	for _, l := range te.logs.all() {
		if strings.Contains(l, "gateway") && strings.Contains(l, "moved") {
			saw = true
		}
	}
	if !saw {
		t.Fatal("gateway move not logged")
	}
}

func TestGatewayWithShepherdsOwnMACIsRefused(t *testing.T) {
	plat := newFakePlatform()
	plat.setGatewayMAC(shepherdMAC)
	te := newTestEngine(t, plat, nil)
	te.start(t)
	waitFor(t, "unavailable", func() bool { return strings.Contains(te.Snapshot().Reason, "is Shepherd the gateway") })
}

// The registry keeps one current IPv4 per device (the rest move to its past
// addresses), so a device merged from two MACs is steered on the MAC the
// neighbour table pairs with that current address, and only that one.
func TestMultiMACDeviceSteersThePairTheNeighbourTableKnows(t *testing.T) {
	plat := newFakePlatform()
	other := mustMAC("02:00:5e:00:00:11")
	otherIP := netip.MustParseAddr("192.0.2.11")
	plat.neighbors = append(plat.neighbors, Neighbor{IP: phoneIP, MAC: phoneMAC}, Neighbor{IP: otherIP, MAC: other})
	te := newTestEngine(t, plat, nil)
	id := te.addPhone(t)
	otherID := te.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: other.String(), IP: otherIP.String()})
	if err := te.reg.Merge(id, otherID); err != nil {
		t.Fatal(err)
	}
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, other, true)
	if te.isSteered(phoneMAC) {
		t.Fatal("the MAC with no current address must not be steered")
	}
	ds := te.status(t, id)
	if len(ds.Steered) != 1 || ds.State != StateSteered || ds.Steered[0].MAC != other.String() || ds.Steered[0].IP != otherIP.String() {
		t.Fatalf("device = %+v", ds)
	}
	// Take the table away: the device stays eligible but nothing can be
	// paired, so it is unsteered with the reason shown.
	plat.mu.Lock()
	plat.neighbors = []Neighbor{{IP: gwIP, MAC: gwMAC}}
	plat.mu.Unlock()
	te.waitSteered(t, other, false)
	if ds := te.status(t, id); ds.State != StatePending || !strings.Contains(ds.Reason, "several MACs") {
		t.Fatalf("device = %+v", ds)
	}
}

func TestForgottenDeviceIsUnsteered(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), nil)
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	if err := te.reg.Delete(id); err != nil {
		t.Fatal(err)
	}
	te.waitSteered(t, phoneMAC, false)
}

func TestSnapshotOrdersSteeredFirstThenByName(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), nil)
	te.addPhone(t)
	zMAC := mustMAC("02:00:5e:00:00:30")
	zID := te.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: zMAC.String(), IP: "192.0.2.30", Hostname: "aardvark"})
	if err := te.reg.SetWatch(zID, devices.WatchOff); err != nil {
		t.Fatal(err)
	}
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	devs := te.Snapshot().Devices
	if len(devs) != 2 || devs[0].State != StateSteered || devs[1].DeviceID != zID {
		t.Fatalf("devices = %+v", devs)
	}
	byID := te.DeviceStatuses()
	if byID[zID].State != StateSkipped {
		t.Fatalf("by id = %+v", byID)
	}
}

func TestStateFileErrors(t *testing.T) {
	dir := t.TempDir()
	bad := dir + "/watch.json"
	if err := os.WriteFile(bad, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Registry: devices.New(devices.Options{}), StatePath: bad}); err == nil {
		t.Fatal("a corrupt state file must be reported, not ignored")
	}
	if st, err := loadState(dir + "/missing.json"); err != nil || st.Killed {
		t.Fatalf("missing file: %+v %v", st, err)
	}
	if err := saveState(dir+"/sub/none/watch.json", persisted{}); err == nil {
		t.Fatal("unwritable path must error")
	}
	if err := saveState("", persisted{Killed: true}); err != nil {
		t.Fatal(err)
	}
}

func TestXDPAttachTimeoutFallsBack(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, func(c *Config) { c.Platform = &silentXDP{fakePlatform: plat} })
	te.attachTimeout = 10 * time.Millisecond
	te.start(t)
	te.waitRunning(t)
	if s := te.Snapshot(); s.Relay != RelayUserspace {
		t.Fatalf("relay = %q, want userspace after the XDP timeout", s.Relay)
	}
}

// silentXDP is a fakePlatform whose AttachXDP never calls OnAttached.
type silentXDP struct{ *fakePlatform }

var _ Platform = (*silentXDP)(nil)

func (s *silentXDP) AttachXDP(ctx context.Context, c *intercept.Controller, iface string, opts intercept.XDPOptions) error {
	<-ctx.Done()
	return nil
}

// ---------------------------------------------------------------- IPv6

func TestIPv6SteeringIsOffUnlessAskedFor(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), nil)
	te.addPhoneV6(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	if fam := te.families(phoneMAC); fam != intercept.SteerV4 {
		t.Fatalf("families = %s, want v4 only", fam)
	}
	snap := te.Snapshot()
	if snap.IPv6 || snap.IPv6Wanted || snap.GatewayLinkLocal != "" {
		t.Fatalf("snapshot = %+v", snap)
	}
	if !strings.Contains(snap.IPv6Reason, "turned off") {
		t.Fatalf("reason = %q", snap.IPv6Reason)
	}
}

func TestIPv6SteeringSteersBothFamilies(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), func(c *Config) { c.IPv6 = true })
	id := te.addPhoneV6(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	waitFor(t, "both families", func() bool {
		te.poke(te.kick)
		return te.families(phoneMAC) == intercept.SteerV4|intercept.SteerV6
	})
	snap := te.Snapshot()
	if !snap.IPv6 || !snap.IPv6Wanted || snap.IPv6Reason != "" || snap.GatewayLinkLocal != gwLinkLocal.String() {
		t.Fatalf("snapshot = %+v", snap)
	}
	ds := te.status(t, id)
	if len(ds.Families) != 2 || ds.Families[0] != "ipv4" || ds.Families[1] != "ipv6" {
		t.Fatalf("device families = %v", ds.Families)
	}
	if len(ds.Steered) != 1 || len(ds.Steered[0].Families) != 2 {
		t.Fatalf("device = %+v", ds)
	}
}

// A device with no IPv6 address of its own is steered for IPv4 alone, and
// says so, rather than losing its IPv4 steering over it.
func TestIPv6SteeringSkipsADeviceWithNoIPv6Address(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), func(c *Config) { c.IPv6 = true })
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	if fam := te.families(phoneMAC); fam != intercept.SteerV4 {
		t.Fatalf("families = %s, want v4 only", fam)
	}
	if ds := te.status(t, id); !strings.Contains(ds.IPv6Reason, "no IPv6 address") {
		t.Fatalf("device = %+v", ds)
	}
}

// The network conditions the design gates IPv6 steering on, each reported
// in the owner's words instead of silently doing nothing.
func TestIPv6SteeringNeedsTheRightNetwork(t *testing.T) {
	cases := []struct {
		name string
		set  func(*fakePlatform)
		want string
	}{
		{"no IPv6 router", func(p *fakePlatform) { p.route6Err = ErrNoDefaultRoute6 }, "no IPv6 default route"},
		{"ULA only", func(p *fakePlatform) { p.link.IPv6s = []netip.Addr{uniqueLocal(0x02)} }, "no global IPv6 route"},
		{"next hop is not link-local", func(p *fakePlatform) { p.route6 = Route6{Iface: "eth0", NextHop: uniqueLocal(0x01)} }, "not a link-local address"},
		{"route on another interface", func(p *fakePlatform) { p.route6 = Route6{Iface: "eth9", NextHop: gwLinkLocal} }, "leaves through eth9"},
	}
	for _, c := range cases {
		plat := newFakePlatform()
		c.set(plat)
		te := newTestEngine(t, plat, func(cfg *Config) { cfg.IPv6 = true })
		te.addPhoneV6(t)
		te.start(t)
		te.waitRunning(t)
		te.waitSteered(t, phoneMAC, true)
		snap := te.Snapshot()
		if snap.IPv6 || !snap.IPv6Wanted || !strings.Contains(snap.IPv6Reason, c.want) {
			t.Errorf("%s: ipv6=%v reason=%q, want a reason naming %q", c.name, snap.IPv6, snap.IPv6Reason, c.want)
		}
		// IPv4 steering is unaffected by any of this.
		if fam := te.families(phoneMAC); fam != intercept.SteerV4 {
			t.Errorf("%s: families = %s, want v4", c.name, fam)
		}
		te.stop()
		<-te.done
	}
}

// The protection docs/IPV6.md exists for: a smart-home hub or a Thread or
// Matter device is never IPv6-steered, and unlike IPv4 the per-device
// "always watch" switch cannot override it.
func TestIPv6SteeringNeverTouchesSmartHomeGearEvenWhenForced(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), func(c *Config) { c.IPv6 = true })
	hubMAC := mustMAC("02:00:5e:00:00:40")
	hubID := te.reg.Observe(devices.Observation{Source: devices.SourceMDNS, MAC: hubMAC.String(), IP: "192.0.2.40",
		Hostname: "border-router", Services: []string{"_meshcop._udp"}})
	te.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: hubMAC.String(), IP: linkLocal(0x40).String()})
	// Forced on by hand: for IPv4 this is allowed, for IPv6 it is not.
	if err := te.reg.SetWatch(hubID, devices.WatchOn); err != nil {
		t.Fatal(err)
	}
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, hubMAC, true)
	if fam := te.families(hubMAC); fam != intercept.SteerV4 {
		t.Fatalf("families = %s: a Thread advertiser must never be IPv6-steered", fam)
	}
	ds := te.status(t, hubID)
	if !strings.Contains(ds.IPv6Reason, "never forced") {
		t.Fatalf("device = %+v", ds)
	}
	// And the Controller refuses it at the call, whoever asks.
	x := v6Excluder{te.Engine}
	if !x.Excluded(hubMAC) {
		t.Fatal("the V6Excluder must refuse a Thread advertiser")
	}
	if x.Excluded(mustMAC("02:00:5e:00:00:99")) != true {
		t.Fatal("an unknown MAC must be refused")
	}
}

// A device the registry merged from several MACs keeps IPv4 steering but
// is left out of IPv6: which MAC holds its IPv6 address is not knowable
// from the IPv4 neighbour table, and that is not something to guess.
func TestIPv6SteeringSkipsAMultiMACDevice(t *testing.T) {
	plat := newFakePlatform()
	other := mustMAC("02:00:5e:00:00:11")
	otherIP := netip.MustParseAddr("192.0.2.11")
	plat.neighbors = append(plat.neighbors, Neighbor{IP: phoneIP, MAC: phoneMAC}, Neighbor{IP: otherIP, MAC: other})
	te := newTestEngine(t, plat, func(c *Config) { c.IPv6 = true })
	id := te.addPhoneV6(t)
	otherID := te.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: other.String(), IP: otherIP.String()})
	if err := te.reg.Merge(id, otherID); err != nil {
		t.Fatal(err)
	}
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, other, true)
	if fam := te.families(other); fam != intercept.SteerV4 {
		t.Fatalf("families = %s, want v4 only", fam)
	}
	if ds := te.status(t, id); !strings.Contains(ds.IPv6Reason, "several MACs") {
		t.Fatalf("device = %+v", ds)
	}
}

// A host with a wired and a wireless interface on one subnet can briefly
// publish its default route through the wrong one. The engine must not drag
// a working relay onto that interface; it stays where it was.
func TestADefaultRouteThatMovesDoesNotMoveTheRelay(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	if snap := te.Snapshot(); snap.Interface != "eth0" {
		t.Fatalf("interface = %q", snap.Interface)
	}

	// The route moves to a second interface, and the session restarts.
	plat.mu.Lock()
	plat.iface = "wlan0"
	plat.mu.Unlock()
	plat.xdpDie <- errBoom
	waitFor(t, "a restart", func() bool { return te.Snapshot().Phase != PhaseRunning })
	waitFor(t, "running again", func() bool {
		if te.clock.Pending() > 0 {
			te.clock.Advance(restartBackoffMin)
		}
		return te.Snapshot().Phase == PhaseRunning
	})
	if snap := te.Snapshot(); snap.Interface != "eth0" {
		t.Fatalf("interface = %q, want eth0: a moving route must not move the relay", snap.Interface)
	}
	var said bool
	for _, l := range te.logs.all() {
		if strings.Contains(l, "default route moved") && strings.Contains(l, "staying on eth0") {
			said = true
		}
	}
	if !said {
		t.Fatalf("the engine should say it stayed put: %v", te.logs.all())
	}
}

// watch.interface overrides all of that, including the pin.
func TestConfiguredInterfaceWinsOverTheRoute(t *testing.T) {
	plat := newFakePlatform()
	plat.iface = "eth9" // the route says one thing
	te := newTestEngine(t, plat, func(c *Config) { c.Interface = "eth0" })
	te.start(t)
	te.waitRunning(t)
	if snap := te.Snapshot(); snap.Interface != "eth0" {
		t.Fatalf("interface = %q, want the configured eth0", snap.Interface)
	}
}

// relayFor credits the phone with relayed frames and waits until sample()
// has seen them, which is what makes the engine sure steering worked.
func (te *testEngine) relayFor(t *testing.T, id string, frames int) {
	t.Helper()
	te.mu.Lock()
	c := te.ctrl
	te.mu.Unlock()
	for i := 0; i < frames; i++ {
		if relayed, err := c.HandleFrame(relayFrame()); err != nil || !relayed {
			t.Fatalf("relay: %v %v", relayed, err)
		}
	}
	// Wait on the rate, not the total: the total comes straight from the
	// Controller and is there before sample() has run, and it is sample()
	// that records steering as having demonstrably worked.
	//
	// Advance repeatedly rather than once. A single fake-clock tick is not
	// enough to guarantee sample() ran: the engine may be in reconcile
	// when the timer fires, and under the race detector that reordering is
	// easy to hit. Advancing until the rate appears is idempotent, because
	// a device that has already been credited stays credited.
	waitFor(t, "relayed traffic credited", func() bool {
		if te.status(t, id).PacketsPerSecond > 0 {
			return true
		}
		te.clock.Advance(time.Second)
		return te.status(t, id).PacketsPerSecond > 0
	})
}

// A device that relayed and then went quiet is idle, not failing. Steering
// provably worked for it, so the silence is the device, and punishing it
// with the widening backoff is what left a waking phone unwatched for up to
// ten minutes.
func TestADeviceThatGoesQuietAfterRelayingIsIdleNotFailing(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), func(c *Config) {
		c.IdleGrace = 10 * time.Second
		c.StartupGrace = 10 * time.Second
		c.HealthInterval = time.Second
	})
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	te.relayFor(t, id, 10)

	// Now it goes quiet for longer than IdleGrace.
	te.clock.Advance(11 * time.Second)
	rs := te.waitFailOpen(t, phoneMAC)
	if rs.failures != 0 {
		t.Fatalf("idleness must not count as a failure: %+v", rs)
	}
	if !rs.idle {
		t.Fatalf("the fail-open should be recorded as idleness: %+v", rs)
	}
	if d := rs.until.Sub(te.clock.Now()); d > idleRecheck {
		t.Fatalf("want a flat recheck no longer than %s, got %s: %+v", idleRecheck, d, rs)
	}

	// Past the recheck it is still left alone: nothing has seen it, so it
	// is asleep and re-steering would only flip its ARP entry for nothing.
	te.clock.Advance(idleRecheck + time.Second)
	te.poke(te.kick)
	time.Sleep(20 * time.Millisecond)
	if te.isSteered(phoneMAC) {
		t.Fatal("re-steered a device nothing has seen since it went quiet")
	}
	if f := te.status(t, id).Failures; f != 0 {
		t.Fatalf("waiting to be seen is not failing: failures = %d", f)
	}

	// Seen again by something other than the relay: steered at once.
	te.reg.Observe(devices.Observation{Source: devices.SourceDNS, MAC: phoneMAC.String(), IP: phoneIP.String()})
	te.waitSteered(t, phoneMAC, true)
}

// A device that never relayed and has not been seen lately either is asleep,
// so that fail-open is idleness too.
func TestASleepingDeviceThatNeverRelayedIsIdleNotFailing(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), func(c *Config) {
		// Longer than awakeWithin, so its last sighting is already stale
		// by the time the grace runs out.
		c.StartupGrace = awakeWithin + 30*time.Second
		c.HealthInterval = time.Second
	})
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	te.clock.Advance(awakeWithin + 31*time.Second)
	te.waitSteered(t, phoneMAC, false)
	ds := te.status(t, id)
	if ds.Failures != 0 {
		t.Fatalf("a device nothing has seen is asleep, not failing: %+v", ds)
	}
	te.clock.Advance(idleRecheck + time.Second)
	te.poke(te.kick)
	time.Sleep(20 * time.Millisecond)
	if te.isSteered(phoneMAC) {
		t.Fatal("re-steered a sleeping device on a timer")
	}
	te.reg.Observe(devices.Observation{Source: devices.SourceDNS, MAC: phoneMAC.String(), IP: phoneIP.String()})
	te.waitSteered(t, phoneMAC, true)
}

// The distinction that makes the backoff worth keeping: a device something
// has seen lately, which never relayed a frame, is steering that did not
// take. That still counts as a failure, still widens, and still retries on
// the timer without needing a fresh sighting.
func TestAnAwakeDeviceThatNeverRelaysStillCountsAsAFailure(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), func(c *Config) {
		c.StartupGrace = 10 * time.Second
		c.HealthInterval = time.Second
	})
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	// Fails open while its sighting is still fresh: that is suspicious.
	te.clock.Advance(11 * time.Second)
	te.waitSteered(t, phoneMAC, false)
	te.waitFailures(t, id, 1)
	if ds := te.status(t, id); ds.NextRetry.Sub(te.clock.Now()) <= idleRecheck {
		t.Fatalf("a real failure should back off further than an idle recheck: %+v", ds)
	}
	// No new sighting, and it is steered again purely on the backoff.
	te.clock.Advance(retryBase)
	te.waitSteered(t, phoneMAC, true)
}

// Repeated idleness must not creep upwards the way failures do, or a device
// that sleeps and wakes all day drifts towards the retryMax blind window.
func TestRepeatedIdlenessDoesNotWidenThePause(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), func(c *Config) {
		c.IdleGrace = 10 * time.Second
		c.StartupGrace = 10 * time.Second
		c.HealthInterval = time.Second
	})
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)

	for round := 0; round < 3; round++ {
		te.waitSteered(t, phoneMAC, true)
		te.relayFor(t, id, 5)
		te.clock.Advance(11 * time.Second)
		rs := te.waitFailOpen(t, phoneMAC)
		if rs.failures != 0 {
			t.Fatalf("round %d: failures = %d, want 0", round, rs.failures)
		}
		if d := rs.until.Sub(te.clock.Now()); d > idleRecheck {
			t.Fatalf("round %d: pause %s grew past the flat %s", round, d, idleRecheck)
		}
		te.clock.Advance(idleRecheck + time.Second)
		te.reg.Observe(devices.Observation{Source: devices.SourceDNS, MAC: phoneMAC.String(), IP: phoneIP.String()})
	}
}

// The host's second interface on the same subnet. A NAS with wired and
// wireless both on the LAN is the ordinary case, and this is what Shepherd
// steered on the maintainer's network: wlan0 looked like a LAN device, so
// the relay carried Shepherd's own traffic back to itself at 9 Gbit/s on a
// 10 GbE link, for a million packets a second in each direction, while
// Shepherd itself showed 3% CPU because the loop ran in the kernel.
var (
	wifiMAC = mustMAC("02:00:5e:00:00:20")
	wifiIP  = netip.MustParseAddr("192.0.2.20")
)

func TestNeverSteersAnotherOfThisHostsInterfaces(t *testing.T) {
	plat := newFakePlatform()
	plat.extraMACs = []arp.MAC{wifiMAC}
	plat.extraIPs = []netip.Addr{wifiIP}
	te := newTestEngine(t, plat, nil)
	phone := te.addPhone(t)
	// The host's own wireless interface, indistinguishable from a device:
	// its own MAC, its own address, seen by the ARP monitor.
	self := te.reg.Observe(devices.Observation{Source: devices.SourceARP, MAC: wifiMAC.String(), IP: wifiIP.String(), Hostname: "nas-wifi"})
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	if te.isSteered(wifiMAC) {
		t.Fatal("steered this host's own second interface: that is the relay loop")
	}
	ds := te.status(t, self)
	if ds.State != StateSkipped || !strings.Contains(ds.Reason, "host") && !strings.Contains(ds.Reason, "own interface") {
		t.Fatalf("self interface = %+v, want skipped for being this host", ds)
	}
	// The ordinary device is unaffected.
	if !te.isSteered(phoneMAC) {
		t.Fatalf("the phone should still be steered; phone status %+v", te.status(t, phone))
	}
}

// The same host arriving under a MAC the registry has not tied to it. This
// is the shape the live registry actually had: the ARP monitor learned
// Shepherd's own steering frames, so a record ended up holding the wireless
// MAC together with the gateway's address. Matching on address catches it
// even when the MAC set does not.
func TestNeverSteersADeviceHoldingOneOfThisHostsAddresses(t *testing.T) {
	plat := newFakePlatform()
	plat.extraIPs = []netip.Addr{wifiIP}
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	odd := te.reg.Observe(devices.Observation{Source: devices.SourceARP, MAC: "02:00:5e:00:00:21", IP: wifiIP.String()})
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	if te.isSteered(mustMAC("02:00:5e:00:00:21")) {
		t.Fatal("steered a device holding one of this host's own addresses")
	}
	if ds := te.status(t, odd); ds.State != StateSkipped {
		t.Fatalf("decision = %+v, want skipped", ds)
	}
}

// The gateway's own address is refused the same way, not only its MAC.
func TestNeverSteersADeviceHoldingTheGatewaysAddress(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), nil)
	te.addPhone(t)
	gw := te.reg.Observe(devices.Observation{Source: devices.SourceARP, MAC: "02:00:5e:00:00:22", IP: gwIP.String()})
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	if te.isSteered(mustMAC("02:00:5e:00:00:22")) {
		t.Fatal("steered a device holding the gateway's address")
	}
	if ds := te.status(t, gw); ds.State != StateSkipped {
		t.Fatalf("decision = %+v, want skipped", ds)
	}
}

// If the host's own addresses cannot be read at all, nothing is steered.
// Refusing costs visibility; steering the host costs the network.
func TestSteersNothingWhenThisHostsAddressesCannotBeRead(t *testing.T) {
	plat := newFakePlatform()
	plat.localAddrsErr = errors.New("no interfaces for you")
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)

	te.poke(te.kick)
	time.Sleep(30 * time.Millisecond)
	te.poke(te.kick)
	time.Sleep(30 * time.Millisecond)
	if te.isSteered(phoneMAC) {
		t.Fatal("steered a device without knowing which addresses are this host's")
	}
	found := false
	for _, l := range te.logs.all() {
		if strings.Contains(l, "own addresses") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a log line saying why nothing is steered; got %v", te.logs.all())
	}
}

// The atlantic driver drops the link when a native XDP attach rebuilds its
// receive rings. That took the maintainer's wired interface off the network
// twice and cost it its DNS listener, so Shepherd must not try native there
// at all. Generic XDP runs in the kernel just the same and does not
// reinitialise the interface.
func TestADriverKnownToFlapGetsGenericXDPNotNative(t *testing.T) {
	plat := newFakePlatform()
	plat.driver = "atlantic"
	plat.xdpMode = intercept.XDPNative // native would succeed; we must not ask
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)

	if got := te.Snapshot().Relay; got != RelayXDPGeneric {
		t.Fatalf("relay = %q, want %q", got, RelayXDPGeneric)
	}
	if got := plat.requestedXDP(); got != intercept.XDPGeneric {
		t.Fatalf("asked for XDP mode %v, want generic: native must never be attempted on this driver", got)
	}
	var said bool
	for _, l := range te.logs.all() {
		if strings.Contains(l, "atlantic") && strings.Contains(l, "generic") {
			said = true
			break
		}
	}
	if !said {
		t.Fatalf("the reason should be in the log; got %v", te.logs.all())
	}
}

// Any other driver still gets the fast path.
func TestAnUnknownDriverStillGetsNativeXDP(t *testing.T) {
	plat := newFakePlatform()
	plat.driver = "igc"
	plat.xdpMode = intercept.XDPNative
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)

	if got := te.Snapshot().Relay; got != RelayXDPNative {
		t.Fatalf("relay = %q, want %q", got, RelayXDPNative)
	}
	if got := plat.requestedXDP(); got != intercept.XDPAuto {
		t.Fatalf("asked for XDP mode %v, want auto", got)
	}
}

// A driver not in the seed list that turns out to flap is learned from the
// kernel's own carrier counter and remembered, so the cost is paid once
// ever rather than once per restart.
func TestANativeAttachThatDropsTheLinkIsLearnedAndRemembered(t *testing.T) {
	dir := t.TempDir()
	statePath := dir + "/watch.json"
	plat := newFakePlatform()
	plat.driver = "mystery"
	plat.xdpMode = intercept.XDPNative
	te := newTestEngine(t, plat, func(c *Config) { c.StatePath = statePath })
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	if got := te.Snapshot().Relay; got != RelayXDPNative {
		t.Fatalf("first run relay = %q, want native", got)
	}

	// The attach took the link down and up, the way atlantic does.
	plat.flapOnNativeAttach()
	te.clock.Advance(nativeSettle + time.Second)
	waitFor(t, "the flap to be remembered", func() bool {
		st, err := loadState(statePath)
		return err == nil && st.hasDriver("mystery")
	})
	var said bool
	for _, l := range te.logs.all() {
		if strings.Contains(l, "took the link down and up") {
			said = true
			break
		}
	}
	if !said {
		t.Fatalf("the flap should be logged plainly; got %v", te.logs.all())
	}

	// A fresh engine on the same state file does not try native again.
	plat2 := newFakePlatform()
	plat2.driver = "mystery"
	plat2.xdpMode = intercept.XDPNative
	te2 := newTestEngine(t, plat2, func(c *Config) { c.StatePath = statePath })
	te2.addPhone(t)
	te2.start(t)
	te2.waitRunning(t)
	if got := te2.Snapshot().Relay; got != RelayXDPGeneric {
		t.Fatalf("second run relay = %q, want %q", got, RelayXDPGeneric)
	}
	if got := plat2.requestedXDP(); got != intercept.XDPGeneric {
		t.Fatalf("second run asked for %v, want generic", got)
	}
}

// Kill used to write a fresh persisted{}, which would have erased the
// learned driver list. Both facts have to survive each other.
func TestTheKillSwitchDoesNotEraseTheLearnedDriverList(t *testing.T) {
	statePath := t.TempDir() + "/watch.json"
	plat := newFakePlatform()
	plat.driver = "mystery"
	plat.xdpMode = intercept.XDPNative
	te := newTestEngine(t, plat, func(c *Config) { c.StatePath = statePath })
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	plat.flapOnNativeAttach()
	te.clock.Advance(nativeSettle + time.Second)
	waitFor(t, "the flap to be remembered", func() bool {
		st, err := loadState(statePath)
		return err == nil && st.hasDriver("mystery")
	})

	if err := te.Kill(); err != nil {
		t.Fatal(err)
	}
	st, err := loadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Killed {
		t.Fatal("the kill switch should be persisted")
	}
	if !st.hasDriver("mystery") {
		t.Fatalf("the kill switch erased the learned driver list: %+v", st)
	}
	// And the other way round.
	if err := te.Rearm(); err != nil {
		t.Fatal(err)
	}
	st, err = loadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Killed || !st.hasDriver("mystery") {
		t.Fatalf("re-arming lost something: %+v", st)
	}
}

// loopTick advances one second and feeds the relay n frames, then makes the
// interface counters show exactly that traffic mirrored: received and
// transmitted the same, with the relay accounting for all of it. That is
// the shape both live incidents had.
// loopTickUnrelayed moves the interface counters without feeding the relay:
// mirrored counters with nothing circulating, which is what a device's
// upload through the relay looks like. Below the hard floor the brake must
// leave it alone; above it, it trips on the counters alone.
func (te *testEngine) loopTickUnrelayed(t *testing.T, plat *fakePlatform, rx, tx uint64) {
	t.Helper()
	plat.addCounters(rx*42, rx, tx*42, tx)
	te.clock.Advance(time.Second)
}

// loopTickEcho is a loop with the measured counters: the relay sees the
// same frame over and over while the interface shows rx and tx.
func (te *testEngine) loopTickEcho(t *testing.T, plat *fakePlatform, rx, tx uint64) {
	t.Helper()
	te.mu.Lock()
	c := te.ctrl
	te.mu.Unlock()
	for i := 0; i < 200; i++ {
		if _, err := c.HandleFrame(echoFrame()); err != nil {
			t.Fatal(err)
		}
	}
	plat.addCounters(rx*42, rx, tx*42, tx)
	te.clock.Advance(time.Second)
}

// uploadTick is a device uploading through the relay: the relay carries n
// distinct frames and the interface mirrors them exactly. Indistinguishable
// from a loop by the counters, and not one.
func (te *testEngine) uploadTick(t *testing.T, plat *fakePlatform, n uint64) {
	t.Helper()
	te.mu.Lock()
	c := te.ctrl
	te.mu.Unlock()
	for i := uint64(0); i < n; i++ {
		if _, err := c.HandleFrame(relayFrame()); err != nil {
			t.Fatal(err)
		}
	}
	plat.addCounters(n*1400, n, n*1400, n)
	te.clock.Advance(time.Second)
}

func (te *testEngine) loopTick(t *testing.T, plat *fakePlatform, n uint64, mirrored bool) {
	t.Helper()
	te.mu.Lock()
	c := te.ctrl
	te.mu.Unlock()
	for i := uint64(0); i < n; i++ {
		// A loop is the same frame coming round; busy is distinct frames.
		f := relayFrame()
		if mirrored {
			f = echoFrame()
		}
		if _, err := c.HandleFrame(f); err != nil {
			t.Fatal(err)
		}
	}
	tx := n
	if !mirrored {
		tx = n * 3 // transmit far more than received: ordinary busy host
	}
	plat.addCounters(n*42, n, tx*42, tx)
	te.clock.Advance(time.Second)
}

// The brake stops a relay that is carrying its own output back to itself,
// and latches so a restart does not resume it.
func TestTheLoopBrakeStopsARelayCarryingItsOwnOutput(t *testing.T) {
	statePath := t.TempDir() + "/watch.json"
	plat := newFakePlatform()
	te := newTestEngine(t, plat, func(c *Config) { c.StatePath = statePath })
	te.loopFloor = 100
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	for i := 0; i < loopHits+2; i++ {
		te.loopTick(t, plat, 200, true)
	}
	waitFor(t, "the loop brake to trip", func() bool { return !te.Snapshot().Armed })

	snap := te.Snapshot()
	if snap.Armed {
		t.Fatal("the brake should have disarmed steering")
	}
	if !strings.Contains(snap.Reason, "round in a loop") {
		t.Fatalf("reason = %q, want it to say what happened", snap.Reason)
	}
	if te.isSteered(phoneMAC) {
		t.Fatalf("nothing should still be steered; phone %+v", te.status(t, id))
	}
	st, err := loadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Killed {
		t.Fatal("the stop must persist, or a restart resumes the loop")
	}
	var saidWhy, namedSuspect bool
	for _, l := range te.logs.all() {
		if strings.Contains(l, "LOOP BRAKE") {
			saidWhy = true
		}
		if strings.Contains(l, "loop brake:") && strings.Contains(l, "had relayed") {
			namedSuspect = true
		}
	}
	if !saidWhy || !namedSuspect {
		t.Fatalf("the brake must log what it saw and what was relaying; got %v", te.logs.all())
	}
}

// Genuinely busy is not looping. The healthy live run had the interface
// transmitting far more than it received, with the relay a fraction of it.
func TestTheLoopBrakeLeavesHeavyLopsidedTrafficAlone(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, nil)
	te.loopFloor = 100
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	for i := 0; i < loopHits+4; i++ {
		te.loopTick(t, plat, 400, false)
	}
	if !te.Snapshot().Armed {
		t.Fatal("the brake tripped on ordinary busy traffic")
	}
	if !te.isSteered(phoneMAC) {
		t.Fatal("steering should be untouched")
	}
}

// A quiet network never trips it, however mirrored the counters look.
func TestTheLoopBrakeHasAFloor(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, nil)
	te.loopFloor = 100_000 // production-like floor, tiny traffic
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	for i := 0; i < loopHits+4; i++ {
		te.loopTick(t, plat, 50, true)
	}
	if !te.Snapshot().Armed {
		t.Fatal("the brake tripped below its floor")
	}
}

// Mirrored counters are what a device uploading through the relay looks
// like: every frame received is one transmitted. The brake once stopped an
// overnight iCloud upload at 24,000 packets a second on that reading alone
// (the sampled frames all carried IP ID 0 and TTL 64, as macOS sends
// don't-fragment packets, and were taken for one frame going round). With
// every frame distinct and nothing coming back, it must leave steering
// alone and say so, once.
func TestTheLoopBrakeLeavesAnUploadAlone(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, nil)
	te.loopFloor = 100
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	for i := 0; i < loopHits*3; i++ {
		te.uploadTick(t, plat, 400)
	}
	if !te.Snapshot().Armed {
		t.Fatal("the brake stopped a device's upload")
	}
	if !te.isSteered(phoneMAC) {
		t.Fatal("steering should be untouched")
	}
	var noted int
	for _, l := range te.logs.all() {
		if strings.Contains(l, "not a loop, so steering continues") {
			noted++
		}
	}
	if noted != 1 {
		t.Fatalf("the mirrored-but-distinct note should be logged exactly once an hour; got %d in %v", noted, te.logs.all())
	}
}

// Mirrored counters with the relay silent, below the hard floor, are not a
// loop either: the measured 26,994 against 24,492 was an upload.
func TestTheLoopBrakeLeavesMirroredCountersAloneBelowTheHardFloor(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, nil)
	te.loopFloor = loopFloorPPS
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	for i := 0; i < loopHits*2; i++ {
		te.loopTickUnrelayed(t, plat, 26994, 24492)
	}
	if !te.Snapshot().Armed || !te.isSteered(phoneMAC) {
		t.Fatal("the brake tripped on mirrored counters with nothing circulating")
	}
}

// The earlier single-device run was about 465,000 packets a second received
// against 517,000 transmitted: 10.06% apart, which the original 0.10
// symmetry threshold excluded by six hundredths of a percent. A threshold
// that only just misses a real incident is the wrong threshold.
func TestTheLoopBrakeCatchesATenPercentAsymmetricLoop(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, nil)
	te.loopFloor = loopFloorPPS
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	waitFor(t, "the loop brake to trip on a 10.06% asymmetric loop", func() bool {
		te.loopTickUnrelayed(t, plat, 465000, 517000)
		return !te.Snapshot().Armed
	})
}

// Healthy but genuinely busy stays untouched even above the floor: the live
// host transmitted 800 to 1000 Mbit/s against 600 received, 25 to 40% apart,
// which is well outside loopSymmetry. The floor alone would not have saved
// it -- that run reached roughly 83,000 packets a second.
func TestTheLoopBrakeLeavesBusyLopsidedTrafficAloneAboveTheFloor(t *testing.T) {
	plat := newFakePlatform()
	te := newTestEngine(t, plat, nil)
	te.loopFloor = loopFloorPPS
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	// The live host's own background with nothing steered, measured in clean
	// two-second samples: receive far above the floor, transmit a tenth of
	// it, 90% apart. The brake has to sit beside this every second of every
	// day without firing, which is why the floor cannot be the test.
	for i := 0; i < (loopHits+4)*4; i++ {
		te.loopTickUnrelayed(t, plat, 39521, 3008)
		time.Sleep(2 * time.Millisecond)
	}
	if !te.Snapshot().Armed {
		t.Fatal("the brake tripped on heavy lopsided traffic above the floor")
	}
	if !te.isSteered(phoneMAC) {
		t.Fatal("steering should be untouched")
	}
}

// This host's own Docker containers arrive in the registry looking like
// ordinary LAN devices: a 172.x address from the host's neighbour table and
// several MACs each. They are not on the relay interface's segment, so an
// ARP reply there cannot reach them and steering them is meaningless.
func TestNeverSteersADeviceThatIsNotOnTheRelaysOwnSegment(t *testing.T) {
	plat := newFakePlatform()
	plat.link.IPv4Nets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	te := newTestEngine(t, plat, nil)
	te.addPhone(t) // 192.0.2.10, on the segment
	container := te.reg.Observe(devices.Observation{
		Source: devices.SourceNeighbor, MAC: "02:00:5e:00:00:40", IP: "172.18.0.2",
	})
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	if te.isSteered(mustMAC("02:00:5e:00:00:40")) {
		t.Fatal("steered a device that is not on the relay interface's segment")
	}
	ds := te.status(t, container)
	if ds.State != StateSkipped || !strings.Contains(ds.Reason, "cannot reach it") {
		t.Fatalf("decision = %+v, want skipped with a reason that explains it", ds)
	}
}

// With no prefixes known, nothing is refused on that basis: the check must
// never turn missing information into a refusal.
func TestAnUnknownSegmentRefusesNothing(t *testing.T) {
	plat := newFakePlatform()
	plat.link.IPv4Nets = nil
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
}

// A host that both forwards IPv4 and has a second interface on the relay's
// own subnet is routing the segment Watch mode would steer. On the one host
// with that shape, steering a single ordinary device took the interface to
// ~465k packets/s in and ~517k out, mirrored, in about ten seconds -- with
// the relay accounting for under a tenth of it. So Shepherd refuses rather
// than relay into it. See routingOwnSegment.
func TestRefusesToRelayOnAHostRoutingItsOwnSegment(t *testing.T) {
	plat := newFakePlatform()
	plat.ipForward = true
	plat.link.IPv4Nets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	// A second interface of this host, on the same subnet as the relay's.
	plat.extraIPs = []netip.Addr{netip.MustParseAddr("192.0.2.77")}
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	te.start(t)

	waitFor(t, "the refusal", func() bool { return te.Snapshot().Phase == PhaseUnavailable })
	snap := te.Snapshot()
	if !strings.Contains(snap.Reason, "routing the segment") {
		t.Fatalf("reason = %q, want it to explain the refusal", snap.Reason)
	}
	if te.isSteered(phoneMAC) {
		t.Fatal("nothing should be steered on such a host")
	}
	if x, _ := plat.counts(); x != 0 {
		t.Fatalf("the relay should never have been attached; attaches = %d", x)
	}
}

// Rule 4 of the relay ("not for Shepherd itself") is driven by the
// local_ips map, and the relay interface's own addresses are not the whole
// of this host. A second interface on the same segment -- the maintainer's
// NAS answers DNS on one -- is an address steered devices legitimately
// talk to, and those frames must reach the stack, not the gateway. The
// gateway's own address must stay out: it is not this host's.
func TestLocalIPsCoverEveryHostAddressButNotTheGateway(t *testing.T) {
	plat := newFakePlatform()
	second := netip.MustParseAddr("192.0.2.77")
	plat.extraIPs = []netip.Addr{second}
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)

	plat.mu.Lock()
	got := append([]netip.Addr(nil), plat.xdpLocalIPs...)
	plat.mu.Unlock()
	if !slices.Contains(got, second) {
		t.Errorf("local_ips = %v, want it to include this host's other address %v", got, second)
	}
	if !slices.Contains(got, shepherdIP) {
		t.Errorf("local_ips = %v, want it to include the relay interface's own %v", got, shepherdIP)
	}
	if slices.Contains(got, gwIP) {
		t.Errorf("local_ips = %v, must not include the gateway %v", got, gwIP)
	}
}

// Forwarding alone is fine. Plenty of hosts forward; what matters is
// forwarding plus a second interface on the relay's own segment.
func TestForwardingAloneDoesNotRefuse(t *testing.T) {
	plat := newFakePlatform()
	plat.ipForward = true
	plat.link.IPv4Nets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	plat.extraIPs = []netip.Addr{netip.MustParseAddr("10.9.9.9")} // elsewhere
	te := newTestEngine(t, plat, nil)
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
}

// The brake's evidence has to survive a restart, because a container
// rebuild takes the logs with it -- which destroyed this very evidence
// twice during the investigation that produced the brake.
func TestTheLoopBrakeRecordsItsEvidenceWhereARestartCannotLoseIt(t *testing.T) {
	statePath := t.TempDir() + "/watch.json"
	plat := newFakePlatform()
	te := newTestEngine(t, plat, func(c *Config) { c.StatePath = statePath })
	te.loopFloor = loopFloorPPS
	te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)

	waitFor(t, "the loop brake to trip", func() bool {
		te.loopTickEcho(t, plat, 26994, 24492)
		return !te.Snapshot().Armed
	})

	// Read it back from disk, as a restart would.
	st, err := loadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.LastLoopStop == nil {
		t.Fatal("the brake tripped and left nothing on disk, so a redeploy loses the evidence again")
	}
	ls := st.LastLoopStop
	if ls.RxPackets != 26994 || ls.TxPackets != 24492 {
		t.Errorf("recorded rates = rx %.0f tx %.0f, want the measured 26994 and 24492", ls.RxPackets, ls.TxPackets)
	}
	if ls.ApartPercent < 9 || ls.ApartPercent > 10 {
		t.Errorf("recorded apart = %.2f%%, want about 9.3%%", ls.ApartPercent)
	}
	if ls.At.IsZero() {
		t.Error("the record has no timestamp, so it cannot be tied to anything else that happened")
	}
	// The devices that were relaying most are the whole point of the
	// record: that list is what the unexplained incident lacked.
	if len(ls.Devices) == 0 {
		t.Error("no device was named, which is the evidence the first unexplained loop was missing")
	}

	// And the engine reports it, so the portal and the API can show it
	// without anyone reading a log file.
	if snap := te.Snapshot(); snap.LastLoopStop == nil {
		t.Error("Snapshot() does not carry the record, so nothing can display it")
	} else if snap.LastLoopStop.RxPackets != 26994 {
		t.Errorf("Snapshot()'s record disagrees with the one on disk: rx %.0f", snap.LastLoopStop.RxPackets)
	}
}

// The echo warning's thresholds. It must stay silent about a stray
// duplicate or a near-idle relay, and speak up when most of what the relay
// relays is coming back -- which is what the live host does.
func TestTheEchoWarningThresholds(t *testing.T) {
	cases := []struct {
		name          string
		relayed, dups uint64
		want          bool
	}{
		{"a healthy relay, nothing coming back", 100000, 0, false},
		{"one stray duplicate in heavy traffic", 100000, 1, false},
		{"just under the ratio", 10000, 2499, false},
		{"exactly at the ratio", 10000, 2500, true},
		{"the live host's measured 0.8", 18361, 16196, true},
		{"a high ratio but far too few frames to conclude from", 100, 99, false},
		{"just under the frame floor", echoWarnMinFrames - 1, echoWarnMinFrames - 1, false},
		{"exactly at the frame floor, ratio met", echoWarnMinFrames, echoWarnMinFrames, true},
		{"no traffic at all", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := echoing(tc.relayed, tc.dups); got != tc.want {
				t.Fatalf("echoing(%d relayed, %d duplicates) = %v, want %v", tc.relayed, tc.dups, got, tc.want)
			}
		})
	}
	// It must never divide by zero or treat silence as an echo.
	if echoing(0, 5) {
		t.Error("duplicates with no relayed frames must not warn")
	}
}

// The relay's evidence lines: what gets reported, in what order, and what
// is left out. Gathering the evidence needs an in-kernel relay, which no
// test can attach, so the wording and the choices are tested here instead
// of going unverified.
func TestRelayEvidenceLines(t *testing.T) {
	names := func(m arp.MAC) string { return "dev-" + m.String() }
	a := arp.MAC{2, 0, 0, 0, 0, 1}
	b := arp.MAC{2, 0, 0, 0, 0, 2}
	c := arp.MAC{2, 0, 0, 0, 0, 3}
	d := arp.MAC{2, 0, 0, 0, 0, 4}

	t.Run("a healthy relay says only that there is nothing to show", func(t *testing.T) {
		got := relayEvidence{}.lines(names)
		if len(got) != 1 || got[0] != "no relayed-frame samples available" {
			t.Fatalf("lines = %q, want just the no-samples line", got)
		}
	})

	t.Run("zero counters are left out rather than printed as zeroes", func(t *testing.T) {
		got := relayEvidence{Flows: []string{"a flow"}}.lines(names)
		if len(got) != 1 || got[0] != "a flow" {
			t.Fatalf("lines = %q, want only the flow", got)
		}
	})

	t.Run("everything present, busiest device first", func(t *testing.T) {
		got := relayEvidence{
			Echo:          intercept.EchoDelays{Under100us: 900, Under1ms: 100},
			Duplicates:    1000,
			OursReturning: 2,
			ToGateway:     3,
			ByDevice:      map[arp.MAC]uint64{a: 10, b: 500, c: 100},
			Flows:         []string{"flow one", "flow two"},
			Interface:     "eth0",
		}.lines(names)
		joined := strings.Join(got, "\n")
		for _, want := range []string{
			"how long the echoed frames took to come back",
			"consistent with a wired switch sending it straight back",
			"1000 frames were not relayed",
			"2 frames arrived with Shepherd's own source MAC and 3",
			"eth0",
			"flow one", "flow two",
		} {
			if !strings.Contains(joined, want) {
				t.Errorf("lines missing %q:\n%s", want, joined)
			}
		}
		// Busiest device first, and only three named.
		iB := strings.Index(joined, "500 of dev-"+b.String())
		iC := strings.Index(joined, "100 of dev-"+c.String())
		iA := strings.Index(joined, "10 of dev-"+a.String())
		if iB < 0 || iC < 0 || iA < 0 || !(iB < iC && iC < iA) {
			t.Errorf("devices not ordered busiest first (%d, %d, %d):\n%s", iB, iC, iA, joined)
		}
	})

	t.Run("at most three devices are named", func(t *testing.T) {
		got := relayEvidence{
			ByDevice: map[arp.MAC]uint64{a: 4, b: 3, c: 2, d: 1},
			Flows:    []string{"f"},
		}.lines(names)
		n := 0
		for _, l := range got {
			if strings.Contains(l, "frames came back and were dropped") {
				n++
			}
		}
		if n != 3 {
			t.Fatalf("named %d devices, want at most 3: %q", n, got)
		}
	})

	t.Run("devices with equal counts keep a stable order", func(t *testing.T) {
		ev := relayEvidence{ByDevice: map[arp.MAC]uint64{a: 5, b: 5, c: 5}, Flows: []string{"f"}}
		first := strings.Join(ev.lines(names), "\n")
		for i := 0; i < 20; i++ {
			if again := strings.Join(ev.lines(names), "\n"); again != first {
				t.Fatalf("the order changed between digests:\n%s\n---\n%s", first, again)
			}
		}
	})

	t.Run("the echo verdict is omitted when there is too little to say", func(t *testing.T) {
		got := relayEvidence{Echo: intercept.EchoDelays{Under10us: 3}, Flows: []string{"f"}}.lines(names)
		joined := strings.Join(got, "\n")
		if !strings.Contains(joined, "how long the echoed frames took") {
			t.Error("the histogram itself should still be reported")
		}
		if strings.Contains(joined, "look at the host") || strings.Contains(joined, "consistent with") {
			t.Errorf("a verdict was drawn from 3 samples:\n%s", joined)
		}
	})
}

// tcpAckFrame is a TCP segment from the phone to a remote, carrying the
// given acknowledgement number, the shape the download meter credits.
func tcpAckFrame(port uint16, ack uint32) []byte {
	f := make([]byte, 14+20+20)
	copy(f[0:6], shepherdMAC[:])
	copy(f[6:12], phoneMAC[:])
	f[12], f[13] = 0x08, 0x00
	ip := f[14:]
	ip[0] = 0x45
	ip[2], ip[3] = 0, 40
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], phoneIP.AsSlice())
	copy(ip[16:20], []byte{198, 51, 100, 1})
	tcp := ip[20:]
	tcp[0], tcp[1] = byte(port>>8), byte(port)
	tcp[2], tcp[3] = 0x01, 0xbb
	tcp[8], tcp[9], tcp[10], tcp[11] = byte(ack>>24), byte(ack>>16), byte(ack>>8), byte(ack)
	tcp[12] = 5 << 4
	tcp[13] = 0x10 // ACK
	return f
}

// recordingTraffic is a TrafficRecorder that remembers every call.
type recordingTraffic struct {
	mu    sync.Mutex
	calls []map[string]traffic.Delta
}

func (r *recordingTraffic) Record(_ time.Time, rows map[string]traffic.Delta) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make(map[string]traffic.Delta, len(rows))
	for k, v := range rows {
		cp[k] = v
	}
	r.calls = append(r.calls, cp)
}

func (r *recordingTraffic) total(id string) traffic.Delta {
	r.mu.Lock()
	defer r.mu.Unlock()
	var d traffic.Delta
	for _, c := range r.calls {
		d.Up += c[id].Up
		d.Down += c[id].Down
	}
	return d
}

func TestDownloadEstimateFeedsRatesAndTheTrafficRecorder(t *testing.T) {
	rec := &recordingTraffic{}
	te := newTestEngine(t, newFakePlatform(), func(c *Config) { c.Traffic = rec })
	id := te.addPhone(t)
	te.start(t)
	te.waitRunning(t)
	te.waitSteered(t, phoneMAC, true)
	te.mu.Lock()
	c := te.ctrl
	te.mu.Unlock()
	// A download of 3000 bytes as the phone's ACKs describe it: a
	// baseline, then two advances.
	for _, ack := range []uint32{1000, 2000, 4000} {
		if relayed, err := c.HandleFrame(tcpAckFrame(50000, ack)); err != nil || !relayed {
			t.Fatalf("relay: %v %v", relayed, err)
		}
	}
	te.clock.Advance(time.Second)
	waitFor(t, "download rate", func() bool { return te.status(t, id).RxBytesPerSecond > 0 })
	ds := te.status(t, id)
	if ds.BytesReceivedEst != 3000 || ds.BytesRelayed != 3*54 {
		t.Fatalf("device = %+v, want 3000 received (est.) and 162 relayed", ds)
	}
	snap := te.Snapshot()
	if snap.Stats.BytesReceivedEst != 3000 || snap.Stats.RxBytesPerSecond <= 0 {
		t.Fatalf("stats = %+v", snap.Stats)
	}
	// The recorder got one row for the phone, by registry ID, with both
	// directions, and nothing for a quiet second.
	waitFor(t, "traffic row", func() bool { return rec.total(id).Down == 3000 })
	if got := rec.total(id); got.Up != 162 {
		t.Fatalf("recorded %+v, want 162 up", got)
	}
	rec.mu.Lock()
	n := len(rec.calls)
	rec.mu.Unlock()
	te.clock.Advance(time.Second)
	time.Sleep(20 * time.Millisecond)
	rec.mu.Lock()
	after := len(rec.calls)
	rec.mu.Unlock()
	if after != n {
		t.Fatalf("a quiet second produced %d extra rows", after-n)
	}
	// Movement after that is a fresh delta, not a repeat of the total.
	if relayed, err := c.HandleFrame(tcpAckFrame(50000, 4100)); err != nil || !relayed {
		t.Fatalf("relay: %v %v", relayed, err)
	}
	te.clock.Advance(time.Second)
	waitFor(t, "second row", func() bool { return rec.total(id).Down == 3100 })
}

func TestTrafficRecorderIsOptionalAndSkipsUnknownMACs(t *testing.T) {
	te := newTestEngine(t, newFakePlatform(), nil)
	// No recorder: a no-op, not a panic.
	te.recordTraffic(t0, map[arp.MAC]traffic.Delta{phoneMAC: {Up: 1}})
	rec := &recordingTraffic{}
	te.cfg.Traffic = rec
	te.recordTraffic(t0, nil)
	te.recordTraffic(t0, map[arp.MAC]traffic.Delta{mustMAC("02:00:5e:00:00:99"): {Up: 1}})
	if len(rec.calls) != 0 {
		t.Fatalf("unknown MAC or empty rows reached the recorder: %v", rec.calls)
	}
	// Two MACs of one merged device make one row.
	id := te.addPhone(t)
	other := mustMAC("02:00:5e:00:00:11")
	otherID := te.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: other.String(), IP: "192.0.2.11"})
	if err := te.reg.Merge(id, otherID); err != nil {
		t.Fatal(err)
	}
	te.recordTraffic(t0, map[arp.MAC]traffic.Delta{phoneMAC: {Up: 1, Down: 10}, other: {Up: 2, Down: 20}})
	if len(rec.calls) != 1 || len(rec.calls[0]) != 1 || rec.calls[0][id] != (traffic.Delta{Up: 3, Down: 30}) {
		t.Fatalf("rows = %v", rec.calls)
	}
}

// Ethernet is always preferred; Wi-Fi is only a fallback. A host with both
// on one subnet can publish its default route through either, and a relay
// on Wi-Fi shares the air with the devices it relays.
func TestPrefersAWiredInterfaceOverTheWirelessDefaultRoute(t *testing.T) {
	plat := newFakePlatform()
	plat.iface = "wlan0" // the default route is through Wi-Fi
	wired := plat.link
	wired.Name = "eth0"
	wired.IPv4Nets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	wireless := plat.link
	wireless.Name = "wlan0"
	wireless.Wireless = true
	wireless.MAC = mustMAC("02:00:5e:00:00:77")
	wireless.IPv4Nets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	plat.links = []Link{wired, wireless}
	te := newTestEngine(t, plat, nil)
	te.start(t)
	te.waitRunning(t)
	if snap := te.Snapshot(); snap.Interface != "eth0" {
		t.Fatalf("interface = %q, want the wired eth0", snap.Interface)
	}
	var said bool
	for _, l := range te.logs.all() {
		if strings.Contains(l, "using the wired eth0") {
			said = true
		}
	}
	if !said {
		t.Fatalf("the preference should be logged; got %v", te.logs.all())
	}
}

func TestWirelessIsUsedWhenNothingWiredReachesTheGateway(t *testing.T) {
	plat := newFakePlatform()
	plat.iface = "wlan0"
	wireless := plat.link
	wireless.Name = "wlan0"
	wireless.Wireless = true
	wireless.IPv4Nets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	elsewhere := plat.link
	elsewhere.Name = "eth1"
	elsewhere.MAC = mustMAC("02:00:5e:00:00:78")
	elsewhere.IPv4Nets = []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")} // another network
	plat.links = []Link{wireless, elsewhere}
	te := newTestEngine(t, plat, nil)
	te.start(t)
	te.waitRunning(t)
	if snap := te.Snapshot(); snap.Interface != "wlan0" {
		t.Fatalf("interface = %q, want the wireless fallback", snap.Interface)
	}
	// And a configured interface is never second-guessed.
	plat2 := newFakePlatform()
	plat2.iface = "wlan0"
	plat2.links = []Link{wireless, wired(plat2.link)}
	te2 := newTestEngine(t, plat2, func(c *Config) { c.Interface = "wlan0" })
	te2.start(t)
	te2.waitRunning(t)
	if snap := te2.Snapshot(); snap.Interface != "wlan0" {
		t.Fatalf("interface = %q, want the configured wlan0", snap.Interface)
	}
	// Interfaces() failing leaves the route's choice alone.
	plat3 := newFakePlatform()
	plat3.iface = "wlan0"
	e3 := newTestEngine(t, plat3, nil)
	plat3.mu.Lock()
	plat3.link.Wireless = true
	plat3.mu.Unlock()
	if got := e3.preferWired("wlan0", gwIP); got != "wlan0" {
		t.Fatalf("with no wired alternative preferWired = %q", got)
	}
}

func wired(l Link) Link {
	l.Name = "eth0"
	l.IPv4Nets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	return l
}
