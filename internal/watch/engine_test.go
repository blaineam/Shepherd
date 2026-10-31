// SPDX-License-Identifier: AGPL-3.0-or-later

package watch

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"shepherd/internal/arp"
	"shepherd/internal/devices"
	"shepherd/internal/intercept"
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
// the phone with traffic.
func relayFrame() []byte {
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
