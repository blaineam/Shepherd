// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"shepherd/internal/config"
	"shepherd/internal/dnsengine"
	"shepherd/internal/webpush"
)

func pushConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	return cfg
}

func TestPushContactPicksSomethingAPushServiceCanUse(t *testing.T) {
	cfg := pushConfig(t)
	if got := pushContact(cfg); got != defaultPushContact {
		t.Fatalf("no contact, no TLS: %q", got)
	}
	cfg.TLS.Enabled, cfg.TLS.Hostname = true, "shepherd.example.com"
	if got := pushContact(cfg); got != "https://shepherd.example.com" {
		t.Fatalf("TLS hostname: %q", got)
	}
	cfg.Alarms.Push.Contact = "admin@example.com"
	if got := pushContact(cfg); got != "mailto:admin@example.com" {
		t.Fatalf("email: %q", got)
	}
	cfg.Alarms.Push.Contact = "mailto:ops@example.com"
	if got := pushContact(cfg); got != "mailto:ops@example.com" {
		t.Fatalf("mailto: %q", got)
	}
	cfg.Alarms.Push.Contact = "https://example.com/contact"
	if got := pushContact(cfg); got != "https://example.com/contact" {
		t.Fatalf("https: %q", got)
	}
	cfg.Alarms.Push.Contact = "example.com/contact"
	if got := pushContact(cfg); got != "https://example.com/contact" {
		t.Fatalf("bare host: %q", got)
	}
}

func TestStartPushKeepsItsKeysAndSubscriptionsAcrossRestarts(t *testing.T) {
	cfg := pushConfig(t)
	ps, pusher, err := startPush(cfg)
	if err != nil || ps == nil || pusher == nil {
		t.Fatalf("startPush: %v %v %v", ps, pusher, err)
	}
	key := ps.PublicKey()
	if key == "" {
		t.Fatal("no public key")
	}
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var sub webpush.BrowserSubscription
	sub.Endpoint = "https://push.example.net/send/abcdef"
	sub.Keys.P256dh = base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
	sub.Keys.Auth = "tBHItJI5svbpez7KI4CCXg"
	d, err := ps.Subscribe(sub, "Phone", "UA")
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.Rename(d.ID, "Tablet"); err != nil {
		t.Fatal(err)
	}
	if err := ps.Rename("nope", "x"); err == nil {
		t.Fatal("renaming an unknown device should fail")
	}

	// A second start finds the same key and the subscription.
	again, _, err := startPush(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if again.PublicKey() != key {
		t.Fatal("the VAPID key changed across restarts, which invalidates every subscription")
	}
	devs := again.Devices()
	if len(devs) != 1 || devs[0].Name != "Tablet" {
		t.Fatalf("devices after restart = %+v", devs)
	}
	if err := again.Remove(devs[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := again.Remove(devs[0].ID); err == nil {
		t.Fatal("removing twice should fail")
	}
	sub.Keys.P256dh = "AAAA"
	if _, err := again.Subscribe(sub, "x", "ua"); err == nil {
		t.Fatal("a bad key should be refused")
	}
	if n := len(again.Devices()); n != 0 {
		t.Fatalf("devices after remove = %d", n)
	}

	// A corrupt subscription file is moved aside, not fatal.
	path := filepath.Join(cfg.DataDir, "alarms", "push.json")
	if err := os.WriteFile(path, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	third, _, err := startPush(cfg)
	if err != nil || len(third.Devices()) != 0 {
		t.Fatalf("corrupt store: %v %v", err, third)
	}
	if _, err := os.Stat(path + ".unreadable"); err != nil {
		t.Fatalf("corrupt file not moved aside: %v", err)
	}

	// Off in the configuration: nothing.
	cfg.Alarms.Push.Enabled = false
	if ps, pusher, err := startPush(cfg); ps != nil || pusher != nil || err != nil {
		t.Fatalf("disabled: %v %v %v", ps, pusher, err)
	}
	// A data directory that cannot be created is an error.
	cfg.Alarms.Push.Enabled = true
	cfg.DataDir = filepath.Join(tempDir(t), "file")
	if err := os.WriteFile(cfg.DataDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := startPush(cfg); err == nil {
		t.Fatal("an unwritable data dir should fail")
	}
}

func TestStartAlarmsWiresPush(t *testing.T) {
	cfg := pushConfig(t)
	pool, err := dnsengine.NewPool([]string{"192.0.2.53"})
	if err != nil {
		t.Fatal(err)
	}
	eng, push, stop, err := startAlarms(context.Background(), cfg, pool)
	if err != nil || eng == nil || push == nil {
		t.Fatalf("startAlarms: %v %v %v", eng, push, err)
	}
	stop()
	// And with push off, the engine still starts without a service.
	cfg.Alarms.Push.Enabled = false
	eng, push, stop, err = startAlarms(context.Background(), cfg, pool)
	if err != nil || eng == nil || push != nil {
		t.Fatalf("startAlarms without push: %v %v %v", eng, push, err)
	}
	stop()
}
