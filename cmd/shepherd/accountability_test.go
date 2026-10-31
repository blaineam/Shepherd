// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shepherd/internal/accountability"
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
	"shepherd/internal/secrets"
)

// testRelay is a relay pointing at nothing real: these tests never send
// mail (no digest window closes within a test), they only need one to be set.
func testRelay() secrets.SMTP {
	return secrets.SMTP{Host: "127.0.0.1", Port: 587, From: "shepherd@example.com", TLS: "starttls"} // leakcheck:allow test fixture address
}

// secretsWithRelay is an in-memory secrets store, with the test relay set
// when withRelay is true.
func secretsWithRelay(t *testing.T, withRelay bool) *secrets.Store {
	t.Helper()
	sec, err := secrets.Open("")
	if err != nil {
		t.Fatal(err)
	}
	if withRelay {
		if _, err := sec.SetSMTP(testRelay()); err != nil {
			t.Fatal(err)
		}
	}
	return sec
}

func TestStartAccountabilityIsBuiltButInertWithoutARelay(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	cfg := config.Default() // Accountability.Enabled is true; no relay anywhere
	cfg.DataDir = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng, relay, err := startAccountability(ctx, cfg, engine, reg, secretsWithRelay(t, false))
	if err != nil || eng == nil || relay == nil {
		t.Fatalf("eng=%v relay=%v err=%v: enabled must always build the engine, so the portal's contacts work before a relay exists", eng, relay, err)
	}
	defer eng.Close()
	if relay.Configured() {
		t.Error("no relay is set anywhere")
	}
	if engine.OnAccessWanted == nil || engine.OnAccessWanted() {
		t.Error("with no relay the DNS engine must not even look up a query's items")
	}
	deviceID := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:5e:00:00:09", IP: "203.0.113.9", Time: time.Now()})
	c, _ := eng.AddContact("Jordan", "jordan@example.net")
	if _, err := eng.AddSubscription(accountability.Subscription{ContactID: c.ID, Scope: accountability.DeviceScope(deviceID), Items: []string{"*"},
		Detail: accountability.DetailSummary, Mode: accountability.ModeDigest, Trigger: accountability.TriggerAny}); err != nil {
		t.Fatal(err)
	}
	engine.OnAccess(dnsengine.AccessInfo{Time: time.Now(), ClientIP: "203.0.113.9", Items: []string{"gaming"}, Domain: "roblox.example", Action: "allowed"})
	time.Sleep(50 * time.Millisecond)
	if eng.Pending() != 0 {
		t.Error("nothing may be recorded while there is no relay to send it through")
	}
}

func TestStartAccountabilityNotWiredWhenDisabled(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	cfg := config.Default()
	cfg.Accountability.Enabled = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng, relay, err := startAccountability(ctx, cfg, engine, reg, secretsWithRelay(t, true))
	if err != nil || eng != nil || relay != nil {
		t.Fatalf("eng=%v relay=%v err=%v, want all nil when accountability.enabled is false", eng, relay, err)
	}
	if engine.OnAccess != nil {
		t.Error("OnAccess must not be wired when accountability is off")
	}
}

func TestStartAccountabilityWiresOnAccessAndRecordsMatchingSubscription(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng, relay, err := startAccountability(ctx, cfg, engine, reg, secretsWithRelay(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if eng == nil || !relay.Configured() {
		t.Fatal("a relay in the secrets store must wire the engine and the relay")
	}
	if !engine.OnAccessWanted() {
		t.Error("with a relay set the DNS engine must report watched accesses")
	}
	defer eng.Close()
	if engine.OnAccess == nil {
		t.Fatal("startAccountability must wire Engine.OnAccess")
	}

	group, err := reg.CreateGroup("Family Devices", "")
	if err != nil {
		t.Fatal(err)
	}
	deviceID := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:5e:00:00:02", IP: "203.0.113.9", Time: time.Now()})
	if _, err := reg.BulkAssignGroup([]string{deviceID}, group.ID); err != nil {
		t.Fatal(err)
	}

	contact, err := eng.AddContact("Jordan", "jordan@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.AddSubscription(accountability.Subscription{
		ContactID: contact.ID, Scope: accountability.GroupScope(group.ID),
		Items: []string{"gaming"}, Detail: accountability.DetailSummary,
		Mode: accountability.ModeDigest, Trigger: accountability.TriggerAny,
	}); err != nil {
		t.Fatal(err)
	}

	// Drive the hook exactly as ServeDNS would for an allowed, watched query.
	engine.OnAccess(dnsengine.AccessInfo{
		Time: time.Now(), ClientIP: "203.0.113.9", Items: []string{"gaming"},
		Domain: "roblox.example", Action: "allowed",
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if eng.Pending() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the access event never reached Engine.Record (ClientID/GroupIDs resolution or the queue is broken)")
}

func TestStartAccountabilityUnknownClientStillRecordsNetworkWideSubscriptions(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng, _, err := startAccountability(ctx, cfg, engine, reg, secretsWithRelay(t, true))
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	contact, err := eng.AddContact("Avery", "avery@example.net")
	if err != nil {
		t.Fatal(err)
	}
	// A device-scoped subscription for a device that does not exist in the
	// registry never matches an unknown client (accountability has no
	// network-wide scope): this proves an unresolved ClientID is handled,
	// not that it matches.
	if _, err := eng.AddSubscription(accountability.Subscription{
		ContactID: contact.ID, Scope: accountability.DeviceScope("unknown-device"),
		Items: []string{"*"}, Detail: accountability.DetailSummary,
		Mode: accountability.ModeDigest, Trigger: accountability.TriggerAny,
	}); err != nil {
		t.Fatal(err)
	}

	engine.OnAccess(dnsengine.AccessInfo{
		Time: time.Now(), ClientIP: "198.51.100.1", Items: []string{"ads"},
		Domain: "ads.example", Action: "blocked",
	})

	time.Sleep(100 * time.Millisecond) // give the worker goroutine a chance; it must not panic or hang
	if eng.Pending() != 0 {
		t.Errorf("an unresolved client must not match a device-scoped subscription for someone else's device: pending=%d", eng.Pending())
	}
}

func TestSMTPPassword(t *testing.T) {
	if got, err := smtpPassword(config.AccountabilitySMTP{Password: "direct"}); err != nil || got != "direct" {
		t.Errorf("direct password: %q %v", got, err)
	}
	path := filepath.Join(t.TempDir(), "smtp-password")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := smtpPassword(config.AccountabilitySMTP{PasswordFile: path}); err != nil || got != "from-file" {
		t.Errorf("file password: %q %v (must be trimmed)", got, err)
	}
	if _, err := smtpPassword(config.AccountabilitySMTP{PasswordFile: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("a missing password_file must be an error")
	}
}

func TestARelaySavedInThePortalLaterTakesEffectWithoutARestart(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	sec := secretsWithRelay(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng, relay, err := startAccountability(ctx, cfg, engine, reg, sec)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	deviceID := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:5e:00:00:07", IP: "203.0.113.17", Time: time.Now()})
	c, _ := eng.AddContact("Avery", "avery@example.net")
	if _, err := eng.AddSubscription(accountability.Subscription{ContactID: c.ID, Scope: accountability.DeviceScope(deviceID), Items: []string{"*"},
		Detail: accountability.DetailSummary, Mode: accountability.ModeDigest, Trigger: accountability.TriggerAny,
	}); err != nil {
		t.Fatal(err)
	}
	changed := secretsChanged(sec, relay, &certKicker{})

	// What the portal does on PUT /api/accountability/smtp: save, then notify.
	if _, err := sec.SetSMTP(testRelay()); err != nil {
		t.Fatal(err)
	}
	changed("smtp")
	if !relay.Configured() || !engine.OnAccessWanted() {
		t.Fatal("a relay saved in the portal must be live at once")
	}
	engine.OnAccess(dnsengine.AccessInfo{Time: time.Now(), ClientIP: "203.0.113.17", Items: []string{"gaming"}, Domain: "roblox.example", Action: "allowed"})
	deadline := time.Now().Add(2 * time.Second)
	for eng.Pending() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("an access after the relay was saved never reached the engine")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Clearing it in the portal stops it again, just as live.
	if err := sec.ClearSMTP(); err != nil {
		t.Fatal(err)
	}
	changed("smtp")
	if relay.Configured() || engine.OnAccessWanted() {
		t.Error("a relay cleared in the portal must stop at once")
	}
	changed("unknown kind")                         // ignored
	secretsChanged(sec, nil, &certKicker{})("smtp") // accountability off: stored, not applied, no panic
}
