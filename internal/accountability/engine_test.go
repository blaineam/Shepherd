// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestEngine(t *testing.T, dir string, clock Clock, sender Sender) *Engine {
	t.Helper()
	if clock == nil {
		clock = NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	}
	if sender == nil {
		sender = &FakeSender{Default: Result{Outcome: OutcomeOK}}
	}
	e, err := New(Options{
		Dir: dir, Clock: clock, Sender: sender, From: "shepherd@example.com",
		// A very long TickEvery keeps the background loop from racing with
		// this test's own explicit Tick() calls: every test in this file
		// that wants deterministic timing drives the engine by hand.
		// TestBackgroundLoopSendsOnTick below builds its own Engine to
		// exercise the background loop itself.
		TickEvery: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func TestNewRequiresSenderButNotFrom(t *testing.T) {
	if _, err := New(Options{From: "a@example.com"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("New() without Sender = %v, want ErrInvalid", err)
	}
	// From is optional: SMTPSender and RelaySender use their relay's own
	// From address, which can change at runtime (set in the portal).
	e, err := New(Options{Sender: &FakeSender{}})
	if err != nil {
		t.Fatalf("New() without From = %v, want nil", err)
	}
	e.Close()
}

func TestContactCRUD(t *testing.T) {
	e := newTestEngine(t, "", nil, nil)
	c, err := e.AddContact("  Jordan  ", "jordan@example.com")
	if err != nil {
		t.Fatalf("AddContact: %v", err)
	}
	if c.Name != "Jordan" {
		t.Errorf("Name = %q, want trimmed %q", c.Name, "Jordan")
	}
	if c.ID == "" {
		t.Error("expected a generated ID")
	}
	got, err := e.Contact(c.ID)
	if err != nil || got != c {
		t.Errorf("Contact(%q) = %+v, %v, want %+v, nil", c.ID, got, err, c)
	}
	if _, err := e.Contact("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Contact(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := e.AddContact("", "jordan@example.com"); !errors.Is(err, ErrInvalid) {
		t.Errorf("AddContact(blank name) = %v, want ErrInvalid", err)
	}

	c2, _ := e.AddContact("Avery", "avery@example.com")
	all := e.Contacts()
	if len(all) != 2 {
		t.Fatalf("Contacts() = %d, want 2", len(all))
	}

	if err := e.RemoveContact(c2.ID); err != nil {
		t.Fatalf("RemoveContact: %v", err)
	}
	if _, err := e.Contact(c2.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Contact(removed) = %v, want ErrNotFound", err)
	}
	if err := e.RemoveContact(c2.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("RemoveContact(already removed) = %v, want ErrNotFound", err)
	}
}

func TestRemoveContactCascadesSubscriptions(t *testing.T) {
	e := newTestEngine(t, "", nil, nil)
	c, _ := e.AddContact("Jordan", "jordan@example.com")
	sub, err := e.AddSubscription(Subscription{
		ContactID: c.ID, Scope: GroupScope("g1"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeDigest, Trigger: TriggerAny,
	})
	if err != nil {
		t.Fatalf("AddSubscription: %v", err)
	}
	e.Record(AccessEvent{GroupIDs: []string{"g1"}, Item: "gaming", Action: "allowed"})
	if e.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1 before removing the contact", e.Pending())
	}

	if err := e.RemoveContact(c.ID); err != nil {
		t.Fatalf("RemoveContact: %v", err)
	}
	if _, err := e.Subscription(sub.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Subscription(cascaded) = %v, want ErrNotFound", err)
	}
	if e.Pending() != 0 {
		t.Errorf("Pending() = %d, want 0 after the owning contact was removed", e.Pending())
	}
}

func TestSubscriptionCRUD(t *testing.T) {
	e := newTestEngine(t, "", nil, nil)
	c, _ := e.AddContact("Jordan", "jordan@example.com")

	if _, err := e.AddSubscription(Subscription{ContactID: "unknown", Scope: GroupScope("g1"), Items: []string{"x"}}); !errors.Is(err, ErrNotFound) {
		t.Errorf("AddSubscription(unknown contact) = %v, want ErrNotFound", err)
	}

	sub, err := e.AddSubscription(Subscription{
		ID: "ignored-client-supplied-id", ContactID: c.ID, Scope: GroupScope("g1"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeDigest, Trigger: TriggerAny,
	})
	if err != nil {
		t.Fatalf("AddSubscription: %v", err)
	}
	if sub.ID == "ignored-client-supplied-id" || sub.ID == "" {
		t.Errorf("subscription ID should be engine-assigned, got %q", sub.ID)
	}

	if _, err := e.AddSubscription(Subscription{ContactID: c.ID, Scope: GroupScope(""), Items: []string{"x"}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("AddSubscription(invalid) = %v, want ErrInvalid", err)
	}

	got, err := e.Subscription(sub.ID)
	if err != nil || got.ID != sub.ID {
		t.Fatalf("Subscription(%q) = %+v, %v", sub.ID, got, err)
	}

	byContact := e.SubscriptionsFor(c.ID)
	if len(byContact) != 1 || byContact[0].ID != sub.ID {
		t.Fatalf("SubscriptionsFor() = %+v", byContact)
	}
	if other := e.SubscriptionsFor("someone-else"); len(other) != 0 {
		t.Fatalf("SubscriptionsFor(stranger) = %+v, want empty", other)
	}

	all := e.Subscriptions()
	if len(all) != 1 {
		t.Fatalf("Subscriptions() = %d, want 1", len(all))
	}

	if err := e.RemoveSubscription(sub.ID); err != nil {
		t.Fatalf("RemoveSubscription: %v", err)
	}
	if _, err := e.Subscription(sub.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Subscription(removed) = %v, want ErrNotFound", err)
	}
	if err := e.RemoveSubscription(sub.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("RemoveSubscription(already removed) = %v, want ErrNotFound", err)
	}
}

func TestRecordDropsInvalidEvent(t *testing.T) {
	e := newTestEngine(t, "", nil, nil)
	e.Record(AccessEvent{}) // no Item: dropped, must not panic
	if e.Pending() != 0 {
		t.Errorf("Pending() = %d, want 0", e.Pending())
	}
}

func TestRecordOnlyMatchingSubscriptionsAccumulate(t *testing.T) {
	clock := NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	sender := &FakeSender{Default: Result{Outcome: OutcomeOK}}
	e := newTestEngine(t, "", clock, sender)
	c, _ := e.AddContact("Jordan", "jordan@example.com")
	gamingSub, _ := e.AddSubscription(Subscription{
		ContactID: c.ID, Scope: GroupScope("tommy"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeDigest, Trigger: TriggerAny,
	})
	_ = gamingSub

	e.Record(AccessEvent{GroupIDs: []string{"other-group"}, Item: "gaming", Action: "allowed"})
	if e.Pending() != 0 {
		t.Fatalf("Pending() = %d, want 0 (wrong group)", e.Pending())
	}
	e.Record(AccessEvent{GroupIDs: []string{"tommy"}, Item: "streaming", Action: "allowed"})
	if e.Pending() != 0 {
		t.Fatalf("Pending() = %d, want 0 (wrong item)", e.Pending())
	}
	e.Record(AccessEvent{GroupIDs: []string{"tommy"}, Item: "gaming", Action: "allowed"})
	if e.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1", e.Pending())
	}
}

// TestDigestSendTiming exercises the maintainer's own worked example: a
// device in a watched group accesses a watched category, allowed (never
// blocked at all), and an external accountability partner is notified once
// the digest window closes - not before, and not more than once for a
// burst within the window.
func TestDigestSendTiming(t *testing.T) {
	clock := NewFakeClock(time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC))
	sender := &FakeSender{Default: Result{Outcome: OutcomeOK}}
	e := newTestEngine(t, "", clock, sender)
	contact, _ := e.AddContact("Avery", "avery@example.com")
	sub, _ := e.AddSubscription(Subscription{
		ContactID: contact.ID, Scope: GroupScope("family-devices"), Items: []string{"roblox"},
		Detail: DetailDetailed, Mode: ModeDigest, DigestInterval: 24 * time.Hour, Trigger: TriggerAny,
	})

	e.Record(AccessEvent{Time: clock.Now(), GroupIDs: []string{"family-devices"}, ClientID: "console-1",
		Item: "roblox", Domain: "play.example.com", Action: "allowed"})
	clock.Advance(time.Hour)
	e.Record(AccessEvent{Time: clock.Now(), GroupIDs: []string{"family-devices"}, ClientID: "console-1",
		Item: "roblox", Domain: "play.example.com", Action: "allowed"})

	e.Tick()
	if len(sender.Sent()) != 0 {
		t.Fatalf("sent %d emails before the digest window closed, want 0", len(sender.Sent()))
	}

	clock.Advance(23 * time.Hour) // total elapsed since the first event: 24h
	e.Tick()
	if len(sender.Sent()) != 1 {
		t.Fatalf("sent %d emails, want exactly 1 once the window closed", len(sender.Sent()))
	}
	msg := sender.Sent()[0]
	if msg.To != "avery@example.com" {
		t.Errorf("To = %q, want avery@example.com", msg.To)
	}
	if !strings.Contains(msg.Body, "Roblox") {
		t.Errorf("body missing item label:\n%s", msg.Body)
	}
	if !strings.Contains(msg.Body, "play.example.com") {
		t.Errorf("detailed body missing domain:\n%s", msg.Body)
	}
	if e.Pending() != 0 {
		t.Errorf("Pending() = %d, want 0 after the digest was sent", e.Pending())
	}

	log := e.SendLog()
	if len(log) != 1 || log[0].SubscriptionID != sub.ID || !log[0].Result.OK() {
		t.Fatalf("SendLog() = %+v", log)
	}

	// A fresh event after the window closed opens a new window.
	e.Record(AccessEvent{Time: clock.Now(), GroupIDs: []string{"family-devices"}, Item: "roblox", Action: "allowed"})
	if e.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1 for the new window", e.Pending())
	}
}

func TestImmediateModeDedupeWindow(t *testing.T) {
	clock := NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	sender := &FakeSender{Default: Result{Outcome: OutcomeOK}}
	e := newTestEngine(t, "", clock, sender)
	contact, _ := e.AddContact("Jordan", "jordan@example.com")
	e.AddSubscription(Subscription{
		ContactID: contact.ID, Scope: DeviceScope("laptop-1"), Items: []string{"adult-content"},
		Detail: DetailSummary, Mode: ModeImmediate, Trigger: TriggerBlockedOnly,
	})

	// Five occurrences at minutes 0, 1, 2, 3 and 4. The first one opens a
	// 5-minute window (closing at minute 5), so checking at minute 4 must
	// still be too early.
	e.Record(AccessEvent{Time: clock.Now(), ClientID: "laptop-1", Item: "adult-content", Action: "blocked"})
	for i := 0; i < 4; i++ {
		clock.Advance(time.Minute)
		e.Record(AccessEvent{Time: clock.Now(), ClientID: "laptop-1", Item: "adult-content", Action: "blocked"})
	}
	e.Tick()
	if len(sender.Sent()) != 0 {
		t.Fatalf("sent %d before the 5-minute window closed, want 0", len(sender.Sent()))
	}

	clock.Advance(2 * time.Minute) // minute 6: past the window
	e.Tick()
	if len(sender.Sent()) != 1 {
		t.Fatalf("sent %d, want exactly 1 (a burst is one email)", len(sender.Sent()))
	}
	if !strings.Contains(sender.Sent()[0].Body, "5 times") {
		t.Errorf("body should report all 5 occurrences in one line:\n%s", sender.Sent()[0].Body)
	}
}

func TestTriggerBlockedOnlyIgnoresAllowed(t *testing.T) {
	clock := NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	e := newTestEngine(t, "", clock, nil)
	contact, _ := e.AddContact("Jordan", "jordan@example.com")
	e.AddSubscription(Subscription{
		ContactID: contact.ID, Scope: GroupScope("g1"), Items: []string{"gambling"},
		Detail: DetailSummary, Mode: ModeImmediate, Trigger: TriggerBlockedOnly,
	})
	e.Record(AccessEvent{GroupIDs: []string{"g1"}, Item: "gambling", Action: "allowed"})
	if e.Pending() != 0 {
		t.Fatalf("Pending() = %d, want 0 (blocked_only must ignore an allowed access)", e.Pending())
	}
	e.Record(AccessEvent{GroupIDs: []string{"g1"}, Item: "gambling", Action: "blocked"})
	if e.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1", e.Pending())
	}
}

func TestDeliverSkipsRemovedContact(t *testing.T) {
	clock := NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	sender := &FakeSender{Default: Result{Outcome: OutcomeOK}}
	e := newTestEngine(t, "", clock, sender)
	contact, _ := e.AddContact("Jordan", "jordan@example.com")
	sub, _ := e.AddSubscription(Subscription{
		ContactID: contact.ID, Scope: GroupScope("g1"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeImmediate, Trigger: TriggerAny,
	})
	e.Record(AccessEvent{GroupIDs: []string{"g1"}, Item: "gaming", Action: "allowed"})

	// Directly delete the subscription's contact out from under it without
	// the normal cascade, to exercise deliver()'s own defensive check.
	e.mu.Lock()
	delete(e.contacts, contact.ID)
	e.mu.Unlock()

	clock.Advance(time.Hour)
	e.Tick()
	if len(sender.Sent()) != 0 {
		t.Fatalf("sent %d emails for a removed contact, want 0", len(sender.Sent()))
	}
	_ = sub
}

func TestTickSkipsRemovedSubscription(t *testing.T) {
	clock := NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	sender := &FakeSender{Default: Result{Outcome: OutcomeOK}}
	e := newTestEngine(t, "", clock, sender)
	contact, _ := e.AddContact("Jordan", "jordan@example.com")
	sub, _ := e.AddSubscription(Subscription{
		ContactID: contact.ID, Scope: GroupScope("g1"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeImmediate, Trigger: TriggerAny,
	})
	e.Record(AccessEvent{GroupIDs: []string{"g1"}, Item: "gaming", Action: "allowed"})

	// Remove the subscription directly (bypassing RemoveSubscription, which
	// would also clear its pending digest) so Tick must defend for itself.
	e.mu.Lock()
	delete(e.subs, sub.ID)
	e.mu.Unlock()

	clock.Advance(time.Hour)
	e.Tick()
	if len(sender.Sent()) != 0 {
		t.Fatalf("sent %d emails for a removed subscription, want 0", len(sender.Sent()))
	}
	if e.Pending() != 0 {
		t.Errorf("Pending() = %d, want 0", e.Pending())
	}
}

func TestBackgroundLoopSendsOnTick(t *testing.T) {
	clock := NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	sender := &FakeSender{Default: Result{Outcome: OutcomeOK}}
	e, err := New(Options{Clock: clock, Sender: sender, From: "shepherd@example.com", TickEvery: time.Minute, ImmediateWindow: time.Minute})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()
	contact, _ := e.AddContact("Jordan", "jordan@example.com")
	e.AddSubscription(Subscription{
		ContactID: contact.ID, Scope: GroupScope("g1"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeImmediate, Trigger: TriggerAny,
	})
	e.Record(AccessEvent{GroupIDs: []string{"g1"}, Item: "gaming", Action: "allowed"})

	deadline := time.Now().Add(5 * time.Second)
	for len(sender.Sent()) == 0 {
		clock.Advance(time.Minute)
		if time.Now().After(deadline) {
			t.Fatal("background loop never sent the digest")
		}
	}
}

func TestPersistenceSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	clock := NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	sender := &FakeSender{Default: Result{Outcome: OutcomeOK}}
	e1 := newTestEngine(t, dir, clock, sender)

	contact, err := e1.AddContact("Jordan", "jordan@example.com")
	if err != nil {
		t.Fatalf("AddContact: %v", err)
	}
	sub, err := e1.AddSubscription(Subscription{
		ContactID: contact.ID, Scope: GroupScope("g1"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeDigest, DigestInterval: 24 * time.Hour, Trigger: TriggerAny,
	})
	if err != nil {
		t.Fatalf("AddSubscription: %v", err)
	}
	e1.Record(AccessEvent{Time: clock.Now(), GroupIDs: []string{"g1"}, Item: "gaming", Action: "allowed"})
	e1.Record(AccessEvent{Time: clock.Now(), GroupIDs: []string{"g1"}, Item: "gaming", Action: "allowed"})
	if err := e1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Simulate a restart: a fresh engine loading the same directory, well
	// before the digest window would have closed.
	clock2 := NewFakeClock(clock.Now().Add(time.Hour))
	sender2 := &FakeSender{Default: Result{Outcome: OutcomeOK}}
	e2 := newTestEngine(t, dir, clock2, sender2)

	if _, err := e2.Contact(contact.ID); err != nil {
		t.Fatalf("contact did not survive restart: %v", err)
	}
	if _, err := e2.Subscription(sub.ID); err != nil {
		t.Fatalf("subscription did not survive restart: %v", err)
	}
	if e2.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1 (the in-progress digest must survive restart)", e2.Pending())
	}

	// A third event after the restart must fold into the SAME window
	// (no double count, no lost count): advancing to the original
	// 24h-from-first-event deadline should still produce exactly one email
	// reporting all three accesses.
	e2.Record(AccessEvent{Time: clock2.Now(), GroupIDs: []string{"g1"}, Item: "gaming", Action: "allowed"})
	clock2.Set(clock.Now().Add(24 * time.Hour))
	e2.Tick()
	if len(sender2.Sent()) != 1 {
		t.Fatalf("sent %d emails after restart, want exactly 1", len(sender2.Sent()))
	}
	if !strings.Contains(sender2.Sent()[0].Body, "3 accesses") {
		t.Errorf("expected all 3 accesses (2 before + 1 after restart) counted once:\n%s", sender2.Sent()[0].Body)
	}
}

func TestLoadRejectsCorruptStore(t *testing.T) {
	dir := t.TempDir()
	if err := writeFileAtomic(filepath.Join(dir, ContactsFile), []byte("{not json")); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	_, err := New(Options{Dir: dir, Sender: &FakeSender{}, From: "shepherd@example.com"})
	if !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("New() = %v, want ErrBadSnapshot", err)
	}
}

func TestLoadRejectsCorruptPending(t *testing.T) {
	dir := t.TempDir()
	if err := writeFileAtomic(filepath.Join(dir, PendingFile), []byte("{not json")); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	_, err := New(Options{Dir: dir, Sender: &FakeSender{}, From: "shepherd@example.com"})
	if !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("New() = %v, want ErrBadSnapshot", err)
	}
}

func TestSaveWritesBothFiles(t *testing.T) {
	dir := t.TempDir()
	e := newTestEngine(t, dir, nil, nil)
	if _, err := e.AddContact("Jordan", "jordan@example.com"); err != nil {
		t.Fatalf("AddContact: %v", err)
	}
	if err := e.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ContactsFile)); err != nil {
		t.Errorf("ContactsFile missing after Save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, PendingFile)); err != nil {
		t.Errorf("PendingFile missing after Save: %v", err)
	}
}

func TestMutationsPropagateSaveErrors(t *testing.T) {
	dir := t.TempDir()
	e := newTestEngine(t, dir, nil, nil)
	contact, err := e.AddContact("Jordan", "jordan@example.com")
	if err != nil {
		t.Fatalf("AddContact: %v", err)
	}
	sub, err := e.AddSubscription(Subscription{
		ContactID: contact.ID, Scope: GroupScope("g1"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeDigest, Trigger: TriggerAny,
	})
	if err != nil {
		t.Fatalf("AddSubscription: %v", err)
	}

	// Make the directory read-only so every subsequent atomic write fails
	// at the temp-file-creation step, and confirm each mutating method
	// surfaces that failure instead of silently losing the change.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make %s read-only on this system: %v", dir, err)
	}
	defer os.Chmod(dir, 0o700)

	if _, err := e.AddContact("Avery", "avery@example.com"); err == nil {
		t.Error("AddContact succeeded despite a read-only directory")
	}
	if _, err := e.AddSubscription(Subscription{
		ContactID: contact.ID, Scope: DeviceScope("d1"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeDigest, Trigger: TriggerAny,
	}); err == nil {
		t.Error("AddSubscription succeeded despite a read-only directory")
	}
	if err := e.RemoveSubscription(sub.ID); err == nil {
		t.Error("RemoveSubscription succeeded despite a read-only directory")
	}
	if err := e.RemoveContact(contact.ID); err == nil {
		t.Error("RemoveContact succeeded despite a read-only directory")
	}
	if err := e.Save(); err == nil {
		t.Error("Save succeeded despite a read-only directory")
	}
}

func TestScopeLabelAndItemLabelOverrides(t *testing.T) {
	clock := NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	sender := &FakeSender{Default: Result{Outcome: OutcomeOK}}
	e, err := New(Options{
		Clock: clock, Sender: sender, From: "shepherd@example.com",
		ScopeLabel: func(s Scope) string { return "custom label for " + s.String() },
		ItemLabel:  func(id string) string { return "custom-" + id },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()
	contact, _ := e.AddContact("Jordan", "jordan@example.com")
	e.AddSubscription(Subscription{
		ContactID: contact.ID, Scope: GroupScope("g1"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeImmediate, Trigger: TriggerAny,
	})
	e.Record(AccessEvent{GroupIDs: []string{"g1"}, Item: "gaming", Action: "allowed"})
	clock.Advance(6 * time.Minute) // past the default 5-minute immediate window
	e.Tick()
	if len(sender.Sent()) != 1 {
		t.Fatalf("sent %d, want 1", len(sender.Sent()))
	}
	body := sender.Sent()[0].Body
	if !strings.Contains(body, "custom label for group:g1") {
		t.Errorf("ScopeLabel override not used:\n%s", body)
	}
	if !strings.Contains(body, "custom-gaming") {
		t.Errorf("ItemLabel override not used:\n%s", body)
	}
}

// TestSendFailureIsLoggedAndWindowCleared covers the "store-and-forget"
// design choice from docs/ACCOUNTABILITY.md: a failed send is recorded in
// SendLog with its real outcome, but is not retried, and the digest window
// it belonged to is still cleared rather than kept forever.
func TestSendFailureIsLoggedAndWindowCleared(t *testing.T) {
	clock := NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	sender := &FakeSender{Default: Result{Outcome: OutcomeConnectionFailed, Err: errExampleConnection}}
	e := newTestEngine(t, "", clock, sender)
	contact, _ := e.AddContact("Jordan", "jordan@example.com")
	e.AddSubscription(Subscription{
		ContactID: contact.ID, Scope: GroupScope("g1"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeImmediate, Trigger: TriggerAny,
	})
	e.Record(AccessEvent{GroupIDs: []string{"g1"}, Item: "gaming", Action: "allowed"})
	clock.Advance(6 * time.Minute) // past the default 5-minute immediate window
	e.Tick()
	log := e.SendLog()
	if len(log) != 1 || log[0].Result.Outcome != OutcomeConnectionFailed {
		t.Fatalf("SendLog() = %+v", log)
	}
	// Store-and-forget: the window is cleared even on failure (design
	// choice documented in docs/ACCOUNTABILITY.md).
	if e.Pending() != 0 {
		t.Errorf("Pending() = %d, want 0 even after a failed send", e.Pending())
	}
}

var errExampleConnection = errors.New("dial tcp 127.0.0.1:1234: connection refused (example)")
