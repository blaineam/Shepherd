// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLockStoreIdleLockMinutesOverride(t *testing.T) {
	s := openLockStore("", "hash-a")
	if got := s.idleLockMinutes(10); got != 10 {
		t.Fatalf("no override yet: got %d, want fallback 10", got)
	}
	if err := s.setIdleLockMinutes(30); err != nil {
		t.Fatal(err)
	}
	if got := s.idleLockMinutes(10); got != 30 {
		t.Fatalf("override: got %d, want 30", got)
	}
	if err := s.setIdleLockMinutes(0); err != nil {
		t.Fatal(err)
	}
	if got := s.idleLockMinutes(10); got != 0 {
		t.Fatalf("override of 0 (never) must stick: got %d", got)
	}
	if err := s.setIdleLockMinutes(-1); err == nil {
		t.Error("a negative idle_lock_minutes must be rejected")
	}
}

func TestLockStorePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "locking.json")
	now := time.Now()

	s1 := openLockStore(path, "hash-a")
	if err := s1.setIdleLockMinutes(45); err != nil {
		t.Fatal(err)
	}
	if err := s1.setPIN(pinRecord{Salt: []byte("s"), Hash: []byte("h"), ArgonTime: 1, ArgonMem: 8}); err != nil {
		t.Fatal(err)
	}
	id, secret, err := s1.addTrustedDevice("Test Browser", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) == 0 {
		t.Fatal("addTrustedDevice returned no secret")
	}

	s2 := openLockStore(path, "hash-a") // same token: nothing should be wiped
	if got := s2.idleLockMinutes(10); got != 45 {
		t.Fatalf("idle_lock_minutes did not survive reopen: %d", got)
	}
	if _, ok := s2.pin(); !ok {
		t.Fatal("PIN did not survive reopen")
	}
	if _, ok := s2.findTrustedDevice(id); !ok {
		t.Fatal("trusted device did not survive reopen")
	}
}

func TestLockStoreTokenRotationRevokesPINAndTrustedDevices(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "locking.json")
	now := time.Now()

	s1 := openLockStore(path, "hash-a")
	if err := s1.setIdleLockMinutes(45); err != nil {
		t.Fatal(err)
	}
	if err := s1.setPIN(pinRecord{Salt: []byte("s"), Hash: []byte("h")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s1.addTrustedDevice("Test Browser", now); err != nil {
		t.Fatal(err)
	}

	s2 := openLockStore(path, "hash-b") // the token changed
	if _, ok := s2.pin(); ok {
		t.Error("rotating the token must clear the PIN")
	}
	if len(s2.trustedDevices()) != 0 {
		t.Error("rotating the token must clear every trusted device")
	}
	if got := s2.idleLockMinutes(10); got != 45 {
		t.Error("rotating the token must not clear unrelated preferences like idle_lock_minutes")
	}
}

func TestLockStoreIgnoresCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "locking.json")
	if err := writeFileAtomic(path, []byte("not json")); err != nil {
		t.Fatal(err)
	}
	s := openLockStore(path, "hash-a") // must not panic, and must still be usable
	if err := s.setIdleLockMinutes(5); err != nil {
		t.Fatal(err)
	}
	if got := s.idleLockMinutes(10); got != 5 {
		t.Errorf("got %d, want 5", got)
	}
}

func TestLockStoreTrustedDeviceLifecycle(t *testing.T) {
	now := time.Now()
	s := openLockStore("", "hash-a")

	id, secret, err := s.addTrustedDevice("Firefox", now)
	if err != nil || id == "" || len(secret) != 32 {
		t.Fatalf("addTrustedDevice: id=%q secret_len=%d err=%v", id, len(secret), err)
	}
	dev, ok := s.findTrustedDevice(id)
	if !ok || dev.Name != "Firefox" {
		t.Fatalf("findTrustedDevice: %+v ok=%v", dev, ok)
	}
	if len(s.trustedDevices()) != 1 {
		t.Fatalf("trustedDevices: %v", s.trustedDevices())
	}

	if err := s.revokeTrustedDevice(id); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.findTrustedDevice(id); ok {
		t.Error("revoked device should no longer be found")
	}
	if err := s.revokeTrustedDevice(id); err == nil {
		t.Error("revoking an already-revoked device should fail")
	}
}

func TestLockStoreTrustedDeviceCap(t *testing.T) {
	now := time.Now()
	s := openLockStore("", "hash-a")
	for i := 0; i < maxTrustedDevices; i++ {
		if _, _, err := s.addTrustedDevice("dev", now); err != nil {
			t.Fatalf("device %d: %v", i, err)
		}
	}
	if _, _, err := s.addTrustedDevice("one too many", now); err != errTooManyTrustedDevices {
		t.Fatalf("got %v, want errTooManyTrustedDevices", err)
	}
}

func TestLockStorePINFailureLockoutAndRevoke(t *testing.T) {
	now := time.Now()
	s := openLockStore("", "hash-a")
	id, _, err := s.addTrustedDevice("dev", now)
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i < pinFailsLockout; i++ {
		fails, revoked, err := s.recordPINFailure(id, now)
		if err != nil || revoked {
			t.Fatalf("failure %d: fails=%d revoked=%v err=%v", i, fails, revoked, err)
		}
		if locked, _ := s.lockedUntil(id, now); locked {
			t.Fatalf("should not be locked out before %d failures", pinFailsLockout)
		}
	}

	// The pinFailsLockout-th failure should trigger the lockout window.
	fails, revoked, err := s.recordPINFailure(id, now)
	if err != nil || revoked || fails != pinFailsLockout {
		t.Fatalf("fails=%d revoked=%v err=%v", fails, revoked, err)
	}
	locked, until := s.lockedUntil(id, now)
	if !locked || !until.After(now) {
		t.Fatalf("expected a lockout window, got locked=%v until=%v", locked, until)
	}
	if locked, _ := s.lockedUntil(id, now.Add(pinLockoutFor+time.Minute)); locked {
		t.Error("lockout should expire after pinLockoutFor")
	}

	// Keep failing until the device is revoked outright.
	for i := fails; i < pinFailsRevoke-1; i++ {
		if _, revoked, err := s.recordPINFailure(id, now); err != nil || revoked {
			t.Fatalf("i=%d revoked=%v err=%v", i, revoked, err)
		}
	}
	_, revoked, err = s.recordPINFailure(id, now)
	if err != nil || !revoked {
		t.Fatalf("expected revoke at the %d-th failure, revoked=%v err=%v", pinFailsRevoke, revoked, err)
	}
	if _, ok := s.findTrustedDevice(id); ok {
		t.Error("device should have been removed once revoked")
	}
	if _, _, err := s.recordPINFailure(id, now); err != errTrustedDeviceNotFound {
		t.Errorf("recording a failure for a gone device: %v", err)
	}
}

func TestLockStoreRecordPINSuccessClearsFailures(t *testing.T) {
	now := time.Now()
	s := openLockStore("", "hash-a")
	id, _, err := s.addTrustedDevice("dev", now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < pinFailsLockout; i++ {
		if _, _, err := s.recordPINFailure(id, now); err != nil {
			t.Fatal(err)
		}
	}
	if locked, _ := s.lockedUntil(id, now); !locked {
		t.Fatal("expected to be locked out before success")
	}
	if err := s.recordPINSuccess(id, now); err != nil {
		t.Fatal(err)
	}
	if locked, _ := s.lockedUntil(id, now); locked {
		t.Error("a successful unlock should clear the lockout")
	}
	dev, _ := s.findTrustedDevice(id)
	if dev.Fails != 0 {
		t.Errorf("Fails = %d, want 0", dev.Fails)
	}
	if err := s.recordPINSuccess("no-such-id", now); err != errTrustedDeviceNotFound {
		t.Errorf("got %v", err)
	}
}

func TestLockStoreClearPINRevokesTrustedDevices(t *testing.T) {
	now := time.Now()
	s := openLockStore("", "hash-a")
	if err := s.setPIN(pinRecord{Salt: []byte("s"), Hash: []byte("h")}); err != nil {
		t.Fatal(err)
	}
	id1, _, _ := s.addTrustedDevice("a", now)
	id2, _, _ := s.addTrustedDevice("b", now)

	ids, err := s.clearPIN()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("clearPIN returned %v, want 2 ids", ids)
	}
	for _, want := range []string{id1, id2} {
		found := false
		for _, got := range ids {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("clearPIN did not report revoking %s", want)
		}
	}
	if _, ok := s.pin(); ok {
		t.Error("PIN should be cleared")
	}
	if len(s.trustedDevices()) != 0 {
		t.Error("every trusted device should be gone")
	}
}

func TestValidatePIN(t *testing.T) {
	cases := []struct {
		pin string
		ok  bool
	}{
		{"12345", false},         // too short
		{"1234567890123", false}, // too long
		{"111111", false},        // all one character
		{"123456", false},        // ascending run
		{"654321", false},        // descending run
		{"a1b2c3", true},         // not a simple run
		{"correct9", true},       // letters and digits
		{"has space", false},     // not alnum
		{"üñïçödé1", false},      // non-ASCII
		{"aaaaaa", false},        // all one letter
		{"abcdef", true},         // letters only, but not a digit run, so allowed
		{"024680", true},         // even digits, not a simple +1/-1 run
	}
	for _, c := range cases {
		err := validatePIN(c.pin)
		if (err == nil) != c.ok {
			t.Errorf("validatePIN(%q) error = %v, want ok=%v", c.pin, err, c.ok)
		}
	}
}

func TestWriteFileAtomicCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "locking.json")
	if err := writeFileAtomic(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
}

func TestLockStoreEditRollsBackOnSaveFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "locking.json")
	s := openLockStore(path, "hash-a")
	if err := s.setIdleLockMinutes(20); err != nil {
		t.Fatal(err)
	}
	// Replace the data file's parent with something writeFileAtomic cannot
	// create a temp file inside: a file where a directory is expected.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(dir) })
	if err := s.setIdleLockMinutes(99); err == nil {
		t.Fatal("expected setIdleLockMinutes to fail when the data directory cannot be written")
	}
	if got := s.idleLockMinutes(0); got != 20 {
		t.Errorf("a failed edit should roll back in memory: got %d, want 20", got)
	}
}

func TestLockStoreLoadRejectsVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "locking.json")
	if err := writeFileAtomic(path, []byte(`{"version":99,"token_hash":"hash-a"}`)); err != nil {
		t.Fatal(err)
	}
	s := openLockStore(path, "hash-a") // must not panic; falls back to fresh state
	if got := s.idleLockMinutes(7); got != 7 {
		t.Errorf("an unsupported version should be ignored, got %d", got)
	}
}

func TestLockedUntilUnknownDeviceIsNotLocked(t *testing.T) {
	s := openLockStore("", "hash-a")
	if locked, until := s.lockedUntil("no-such-device", time.Now()); locked || !until.IsZero() {
		t.Errorf("locked=%v until=%v, want false/zero", locked, until)
	}
}
