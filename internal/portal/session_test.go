// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"testing"
	"time"
)

func TestSessionStoreValidAndTouch(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s := newSessionStore()
	sess := s.create("", now)
	if sess.id == "" {
		t.Fatal("session has no id")
	}
	if !s.valid(sess.id, 10, now) {
		t.Fatal("fresh session should be valid")
	}
	// A read-only check must not itself extend the idle window.
	later := now.Add(9 * time.Minute)
	if !s.valid(sess.id, 10, later) {
		t.Fatal("session within the idle window should still be valid")
	}
	past10 := now.Add(11 * time.Minute)
	if s.valid(sess.id, 10, past10) {
		t.Fatal("valid() extended the session even though it never touched it")
	}
	if s.count() != 0 {
		t.Error("an idle-expired session should have been removed")
	}
}

func TestSessionStoreTouchExtendsIdleWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s := newSessionStore()
	sess := s.create("", now)
	later := now.Add(9 * time.Minute)
	if !s.touch(sess.id, later) {
		t.Fatal("touch on a live session should succeed")
	}
	stillOK := later.Add(9 * time.Minute) // 18 min after creation, but only 9 after the touch
	if !s.valid(sess.id, 10, stillOK) {
		t.Fatal("touch should have slid the idle window forward")
	}
	if s.touch("no-such-id", now) {
		t.Error("touch on an unknown session should fail")
	}
}

func TestSessionStoreIdleZeroNeverExpires(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s := newSessionStore()

	expired := s.create("", now)
	farFuture := now.Add(365 * 24 * time.Hour)
	if s.valid(expired.id, 0, farFuture) {
		t.Fatal("idle=0 must still respect the absolute session-age cap")
	}

	fresh := s.create("", now)
	stillWithinCap := now.Add(maxSessionAge - time.Minute)
	if !s.valid(fresh.id, 0, stillWithinCap) {
		t.Error("idle=0 with no idle time elapsed should stay valid within the age cap")
	}
}

func TestSessionStoreDeleteAndDeleteByTrustedDevice(t *testing.T) {
	now := time.Now()
	s := newSessionStore()
	a := s.create("dev-1", now)
	b := s.create("dev-1", now)
	c := s.create("dev-2", now)
	s.delete(a.id)
	if s.valid(a.id, 0, now) {
		t.Error("deleted session should be gone")
	}
	s.deleteByTrustedDevice("dev-1")
	if s.valid(b.id, 0, now) {
		t.Error("deleteByTrustedDevice should have ended every session for that device")
	}
	if !s.valid(c.id, 0, now) {
		t.Error("deleteByTrustedDevice should not touch other devices' sessions")
	}
	s.deleteByTrustedDevice("") // must be a no-op, never nuking token-only sessions
	if !s.valid(c.id, 0, now) {
		t.Error("deleteByTrustedDevice(\"\") must not delete token-login sessions")
	}
}

func TestSessionStoreUnknownIDIsInvalid(t *testing.T) {
	s := newSessionStore()
	if s.valid("nope", 10, time.Now()) {
		t.Error("an unknown session id must never be valid")
	}
}

func TestSessionStoreDeleteByPasskey(t *testing.T) {
	now := time.Now()
	s := newSessionStore()
	token := s.create("", now)
	pin := s.create("dev-1", now)
	a := s.createForPasskey("pk-1", now)
	b := s.createForPasskey("pk-1", now)
	other := s.createForPasskey("pk-2", now)
	if !s.valid(a.id, 10, now) {
		t.Fatal("a passkey session is an ordinary session: it must be valid")
	}
	s.deleteByPasskey("pk-1")
	if s.valid(a.id, 0, now) || s.valid(b.id, 0, now) {
		t.Error("revoking a passkey must end every session it opened")
	}
	if !s.valid(other.id, 0, now) || !s.valid(token.id, 0, now) || !s.valid(pin.id, 0, now) {
		t.Error("revoking a passkey must not touch sessions opened any other way")
	}
	s.deleteByPasskey("") // a no-op, never every non-passkey session
	if !s.valid(token.id, 0, now) || !s.valid(pin.id, 0, now) {
		t.Error(`deleteByPasskey("") must not delete token or PIN sessions`)
	}
	s.deleteByTrustedDevice("pk-2") // the two kinds of id never cross
	if !s.valid(other.id, 0, now) {
		t.Error("deleteByTrustedDevice must not end a passkey session")
	}
}
