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
)

func accountabilitySMTPConfig() config.AccountabilitySMTP {
	return config.AccountabilitySMTP{Host: "127.0.0.1", Port: 587, From: "shepherd@example.com", TLS: "starttls"} // leakcheck:allow test fixture address
}

func TestStartAccountabilityNotWiredWithoutSMTPHost(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	cfg := config.Default() // Accountability.Enabled is true, but SMTP.Host is empty
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng, err := startAccountability(ctx, cfg, engine, reg)
	if err != nil || eng != nil {
		t.Fatalf("eng=%v err=%v, want (nil, nil): an unconfigured relay must leave the feature inert", eng, err)
	}
	if engine.OnAccess != nil {
		t.Error("OnAccess must not be wired when accountability is not configured")
	}
}

func TestStartAccountabilityNotWiredWhenDisabled(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	cfg := config.Default()
	cfg.Accountability.Enabled = false
	cfg.Accountability.SMTP = accountabilitySMTPConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng, err := startAccountability(ctx, cfg, engine, reg)
	if err != nil || eng != nil {
		t.Fatalf("eng=%v err=%v, want (nil, nil) when accountability.enabled is false", eng, err)
	}
}

func TestStartAccountabilityWiresOnAccessAndRecordsMatchingSubscription(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Accountability.SMTP = accountabilitySMTPConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng, err := startAccountability(ctx, cfg, engine, reg)
	if err != nil {
		t.Fatal(err)
	}
	if eng == nil {
		t.Fatal("a configured SMTP relay must wire the engine")
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
	cfg.Accountability.SMTP = accountabilitySMTPConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng, err := startAccountability(ctx, cfg, engine, reg)
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
