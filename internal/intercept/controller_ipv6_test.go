// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"net/netip"
	"testing"
	"time"

	"shepherd/internal/arp"
)

// gwLL is the gateway's link-local address used by the IPv6 tests, built
// from a byte array to keep address literals out of the source. devIP6
// (the device's link-local) is defined in relay_ipv6_test.go.
var gwLL = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})

// naType reads the ICMPv6 type byte, naTLLA the Target Link-Layer Address
// option's MAC, from a raw NA frame (eth 14 + ipv6 40 + NA header 24 +
// option 8).
func naType(f []byte) byte     { return f[54] }
func naTLLA(f []byte) arp.MAC  { return arp.MAC(f[80:86]) }
func naTarget(f []byte) []byte { return f[62:78] }

func v6Config(cfg *ControllerConfig) {
	cfg.IPv6SteeringEnabled = true
	cfg.GatewayLinkLocal = gwLL
}

func TestSteerV6DisabledByDefault(t *testing.T) {
	c, _, _ := newTestController(t, nil) // IPv6SteeringEnabled stays false
	err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP, IP6: devIP6}, SteerOptions{Family: SteerV6})
	if err != ErrIPv6Disabled {
		t.Fatalf("Steer v6 with the master switch off: err = %v, want ErrIPv6Disabled", err)
	}
}

func TestSteerV6NeedsGatewayLinkLocalAndDeviceIP6(t *testing.T) {
	// Enabled but no gateway link-local.
	c1, _, _ := newTestController(t, func(cfg *ControllerConfig) { cfg.IPv6SteeringEnabled = true })
	if err := c1.Steer(DeviceRef{MAC: devMAC, IP: devIP, IP6: devIP6}, SteerOptions{Family: SteerV6}); err != ErrNoGatewayLinkLocal {
		t.Fatalf("no gateway link-local: err = %v, want ErrNoGatewayLinkLocal", err)
	}
	// Enabled, gateway link-local set, but no device IPv6.
	c2, _, _ := newTestController(t, v6Config)
	if err := c2.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{Family: SteerV6}); err != ErrInvalidV6Device {
		t.Fatalf("no device IPv6: err = %v, want ErrInvalidV6Device", err)
	}
}

// excluderFunc adapts a func to the Excluder interface for tests.
type excluderFunc func(arp.MAC) bool

func (f excluderFunc) Excluded(m arp.MAC) bool { return f(m) }

func TestSteerV6HonorsV6Excluder(t *testing.T) {
	c, _, _ := newTestController(t, func(cfg *ControllerConfig) {
		v6Config(cfg)
		cfg.V6Excluder = excluderFunc(func(m arp.MAC) bool { return m == devMAC })
	})
	// IPv4 steering of the same device is still allowed: the v6 excluder
	// gates only v6.
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{Family: SteerV4}); err != nil {
		t.Fatalf("v4 steer should be allowed despite the v6 excluder: %v", err)
	}
	c.Unsteer(devMAC)
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP, IP6: devIP6}, SteerOptions{Family: SteerV6}); err != ErrExcluded {
		t.Fatalf("v6 steer of an excluded device: err = %v, want ErrExcluded", err)
	}
}

func TestSteerV6SendsClaimThenCorrective(t *testing.T) {
	c, sender, _ := newTestController(t, v6Config)
	ch, stop := sender.Watch()
	defer stop()

	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP, IP6: devIP6}, SteerOptions{Family: SteerV6}); err != nil {
		t.Fatalf("Steer v6: %v", err)
	}
	claim := waitForFrame(t, ch, time.Second)
	if naType(claim) != 136 {
		t.Fatalf("claim ICMPv6 type = %d, want 136 (NA)", naType(claim))
	}
	if arp.MAC(claim[0:6]) != devMAC {
		t.Fatalf("claim eth dst = %v, want device", arp.MAC(claim[0:6]))
	}
	if naTLLA(claim) != shepherdMAC {
		t.Fatalf("claim TLLA = %v, want Shepherd's MAC", naTLLA(claim))
	}
	gw16 := gwLL.As16()
	if string(naTarget(claim)) != string(gw16[:]) {
		t.Fatal("claim target is not the gateway's link-local")
	}

	if err := c.Unsteer(devMAC); err != nil {
		t.Fatalf("Unsteer: %v", err)
	}
	corr := waitForFrame(t, ch, time.Second)
	if naType(corr) != 136 {
		t.Fatalf("corrective ICMPv6 type = %d, want 136", naType(corr))
	}
	if naTLLA(corr) != gwMAC {
		t.Fatalf("corrective TLLA = %v, want the gateway's real MAC", naTLLA(corr))
	}
}

// TestV6HealthStartupFlipDidNotTake: a device steered for IPv6 that never
// relays a single frame is reverted once StartupGrace elapses — the one
// IPv6 health check.
func TestV6HealthStartupFlipDidNotTake(t *testing.T) {
	onUnsteer, unsteers := onUnsteerChan()
	c, _, clk := newTestController(t, func(cfg *ControllerConfig) {
		v6Config(cfg)
		cfg.HealthInterval = time.Second
		cfg.StartupGrace = 2 * time.Second
		cfg.OnUnsteer = onUnsteer
	})
	tick := waitHealthTick(t, c)
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP, IP6: devIP6}, SteerOptions{Family: SteerV6}); err != nil {
		t.Fatalf("Steer v6: %v", err)
	}
	clk.Advance(time.Second) // tick at +1s: age 1s < 2s, still within startup grace
	tick()
	if len(c.Status()) != 1 {
		t.Fatal("device should still be steered within startup grace")
	}
	clk.Advance(time.Second) // tick at +2s: age 2s, not < 2s: flip did not take
	tick()
	rec := waitUnsteer(t, unsteers)
	if rec.MAC != devMAC {
		t.Fatalf("unsteered %v, want device", rec.MAC)
	}
	if len(c.Status()) != 0 {
		t.Fatal("device should be unsteered after the startup grace")
	}
}

// TestV6IdleAfterFirstRelayIsNotFailed: once IPv6 has relayed even once,
// arbitrary idle silence never unsteers it — the whole point of the
// lenient v6 rule (an idle v4 device in the same spot would be failed).
func TestV6IdleAfterFirstRelayIsNotFailed(t *testing.T) {
	c, _, clk := newTestController(t, func(cfg *ControllerConfig) {
		v6Config(cfg)
		cfg.HealthInterval = time.Second
		cfg.IdleGrace = 2 * time.Second
		cfg.StartupGrace = 2 * time.Second
	})
	tick := waitHealthTick(t, c)
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP, IP6: devIP6}, SteerOptions{Family: SteerV6}); err != nil {
		t.Fatalf("Steer v6: %v", err)
	}
	// Relay one IPv6 frame so the family is marked verified.
	raw := ipv6Frame(shepherdMAC, devMAC, devIP6, someV6, 64, []byte("hi"))
	if ok, err := c.HandleFrame(raw); !ok || err != nil {
		t.Fatalf("HandleFrame v6 = %v, %v", ok, err)
	}
	// Advance well past any grace with no further traffic.
	for i := 0; i < 5; i++ {
		clk.Advance(time.Second)
		tick()
	}
	if len(c.Status()) != 1 {
		t.Fatal("an IPv6 device that relayed once must not be unsteered on idle silence")
	}
}

// TestV6FailureKeepsV4: a device steered for both families whose IPv6 flip
// never takes loses only IPv6; its IPv4 steering, kept alive by real IPv4
// traffic, stays up.
func TestV6FailureKeepsV4(t *testing.T) {
	c, _, clk := newTestController(t, func(cfg *ControllerConfig) {
		v6Config(cfg)
		cfg.HealthInterval = time.Second
		cfg.IdleGrace = 10 * time.Second
		cfg.StartupGrace = 2 * time.Second
	})
	tick := waitHealthTick(t, c)
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP, IP6: devIP6}, SteerOptions{Family: SteerV4 | SteerV6}); err != nil {
		t.Fatalf("Steer v4+v6: %v", err)
	}
	extV4 := netip.AddrFrom4([4]byte{198, 51, 100, 7})
	for i := 0; i < 3; i++ {
		// Keep IPv4 alive with real traffic; never relay any IPv6.
		if ok, _ := c.HandleFrame(ipv4Frame(shepherdMAC, devMAC, devIP, extV4, []byte("x"))); !ok {
			t.Fatal("expected IPv4 relay")
		}
		clk.Advance(time.Second)
		tick()
	}
	st := c.Status()
	if len(st) != 1 {
		t.Fatalf("device should still be steered for IPv4, got %d entries", len(st))
	}
	if st[0].Family != SteerV4 {
		t.Fatalf("remaining family = %v, want SteerV4 only (v6 should have been dropped)", st[0].Family)
	}
}
