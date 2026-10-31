// SPDX-License-Identifier: AGPL-3.0-or-later

package passkeys

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shepherd/internal/passkeys/passkeystest"
)

const testOrigin = "https://shepherd.example.com:8443"

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newService(t *testing.T) (*Service, *Store, *clock) {
	t.Helper()
	rp, err := NewRelyingParty("shepherd.example.com", ":8443")
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "passkeys.json"), "tokenhash")
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{now: t0}
	svc, err := NewService(rp, store, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store, c
}

func register(t *testing.T, svc *Service, a *passkeystest.Authenticator, name string) Passkey {
	t.Helper()
	id, opts, err := svc.BeginRegistration(name)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Register(opts)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := svc.FinishRegistration(id, resp)
	if err != nil {
		t.Fatalf("registration: %v", err)
	}
	return pk
}

func login(t *testing.T, svc *Service, a *passkeystest.Authenticator) (Passkey, error) {
	t.Helper()
	id, opts, err := svc.BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Login(opts)
	if err != nil {
		t.Fatal(err)
	}
	return svc.FinishLogin(id, resp)
}

func TestRegisterThenLogIn(t *testing.T) {
	svc, store, c := newService(t)
	a := passkeystest.New(testOrigin)
	pk := register(t, svc, a, "My phone")
	if pk.Name != "My phone" || store.Len() != 1 || !pk.Created.Equal(t0) {
		t.Fatalf("registered %+v, store has %d", pk, store.Len())
	}
	c.Advance(time.Minute)
	got, err := login(t, svc, a)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if got.ID != pk.ID || !got.LastUsed.Equal(t0.Add(time.Minute)) {
		t.Errorf("logged in as %+v", got)
	}
	// A second login works too (the counter keeps rising), and the stored
	// counter follows it.
	if _, err := login(t, svc, a); err != nil {
		t.Fatalf("second login: %v", err)
	}
	if n := store.List()[0].Credential.Authenticator.SignCount; n != 1 {
		t.Errorf("stored sign count = %d, want the last one the authenticator reported (1)", n)
	}
}

func TestSyncedPasskeyWithAZeroCounterLogsInRepeatedly(t *testing.T) {
	svc, _, _ := newService(t)
	a := passkeystest.New(testOrigin)
	// iCloud Keychain, Google Password Manager and similar always report 0.
	a.Increment, a.BackupEligible, a.BackedUp = false, true, true
	register(t, svc, a, "")
	for i := range 3 {
		if _, err := login(t, svc, a); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}
}

func TestStandardPortOriginIsAccepted(t *testing.T) {
	svc, _, _ := newService(t)
	a := passkeystest.New("https://shepherd.example.com")
	register(t, svc, a, "")
	if _, err := login(t, svc, a); err != nil {
		t.Fatalf("login from the standard-port origin: %v", err)
	}
}

func TestCreationOptionsAskForWhatThePortalNeeds(t *testing.T) {
	svc, _, _ := newService(t)
	register(t, svc, passkeystest.New(testOrigin), "first")
	_, opts, err := svc.BeginRegistration("second")
	if err != nil {
		t.Fatal(err)
	}
	var o struct {
		PublicKey struct {
			RP struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
			Attestation string `json:"attestation"`
			Selection   struct {
				ResidentKey      string `json:"residentKey"`
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
			Exclude []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
			Timeout int `json:"timeout"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(opts, &o); err != nil {
		t.Fatal(err)
	}
	p := o.PublicKey
	if p.RP.ID != "shepherd.example.com" || p.RP.Name != "Shepherd" {
		t.Errorf("rp = %+v", p.RP)
	}
	if p.Selection.UserVerification != "required" {
		t.Errorf("userVerification = %q: a passkey stands in for a PIN plus a trusted browser, so the authenticator must verify the user", p.Selection.UserVerification)
	}
	if p.Selection.ResidentKey != "preferred" {
		t.Errorf("residentKey = %q", p.Selection.ResidentKey)
	}
	if p.Attestation != "none" {
		t.Errorf("attestation = %q", p.Attestation)
	}
	if len(p.Exclude) != 1 {
		t.Errorf("excludeCredentials = %v, want the already-registered passkey so it is not registered twice", p.Exclude)
	}
	if p.User.ID == "" || p.Timeout <= 0 {
		t.Errorf("user id %q, timeout %d", p.User.ID, p.Timeout)
	}

	_, lopts, err := svc.BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	var l struct {
		PublicKey struct {
			RPID  string `json:"rpId"`
			UV    string `json:"userVerification"`
			Allow []any  `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	json.Unmarshal(lopts, &l)
	if l.PublicKey.RPID != "shepherd.example.com" || l.PublicKey.UV != "required" || len(l.PublicKey.Allow) != 1 {
		t.Errorf("request options = %+v", l.PublicKey)
	}
}

type tamperCase struct {
	tamper func(a *passkeystest.Authenticator)
	// why is the library's own explanation that must appear, proving the
	// response failed the intended check and not some incidental one.
	why string
}

func TestRegistrationRejectsATamperedOrWrongResponse(t *testing.T) {
	cases := map[string]tamperCase{
		"the LAN IP over plain HTTP": {func(a *passkeystest.Authenticator) { a.Origin = "http://192.0.2.10:8787" }, "Error validating origin"},
		"another HTTPS origin":       {func(a *passkeystest.Authenticator) { a.Origin = "https://evil.example.net" }, "Error validating origin"},
		"a different RP ID":          {func(a *passkeystest.Authenticator) { a.RPID = "evil.example.net" }, "RP Hash mismatch"},
		"no user verification":       {func(a *passkeystest.Authenticator) { a.UserVerified = false }, "User verification required"},
		"the wrong ceremony type":    {func(a *passkeystest.Authenticator) { a.Type = "webauthn.get" }, "Error validating ceremony type"},
		"a different challenge":      {func(a *passkeystest.Authenticator) { a.Challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }, "Error validating challenge"},
		"backed up but not eligible": {func(a *passkeystest.Authenticator) { a.BackedUp = true }, "Backup State Flag is true"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			svc, store, _ := newService(t)
			a := passkeystest.New(testOrigin)
			c.tamper(a)
			id, opts, err := svc.BeginRegistration("x")
			if err != nil {
				t.Fatal(err)
			}
			resp, _ := a.Register(opts)
			_, err = svc.FinishRegistration(id, resp)
			if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), c.why) {
				t.Errorf("err = %v, want ErrRejected for %q", err, c.why)
			}
			if store.Len() != 0 {
				t.Error("a rejected registration must store nothing")
			}
		})
	}
}

func TestLoginRejectsATamperedOrWrongResponse(t *testing.T) {
	cases := map[string]tamperCase{
		"the LAN IP over plain HTTP": {func(a *passkeystest.Authenticator) { a.Origin = "http://192.0.2.10:8787" }, "Error validating origin"},
		"localhost":                  {func(a *passkeystest.Authenticator) { a.Origin = "http://localhost:8787" }, "Error validating origin"},
		"another HTTPS origin":       {func(a *passkeystest.Authenticator) { a.Origin = "https://evil.example.net" }, "Error validating origin"},
		"a different RP ID":          {func(a *passkeystest.Authenticator) { a.RPID = "evil.example.net" }, "RP Hash mismatch"},
		"no user verification":       {func(a *passkeystest.Authenticator) { a.UserVerified = false }, "User verification required"},
		"the wrong ceremony type":    {func(a *passkeystest.Authenticator) { a.Type = "webauthn.create" }, "Error validating ceremony type"},
		"a different challenge":      {func(a *passkeystest.Authenticator) { a.Challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }, "Error validating challenge"},
		"someone else's user handle": {func(a *passkeystest.Authenticator) { a.UserHandle = []byte("someone-else") }, "User handle and User ID do not match"},
		"a backup-flag change":       {func(a *passkeystest.Authenticator) { a.BackupEligible = true }, "Backup Eligible flag inconsistency"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			svc, _, _ := newService(t)
			a := passkeystest.New(testOrigin)
			register(t, svc, a, "x")
			c.tamper(a)
			_, err := login(t, svc, a)
			if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), c.why) {
				t.Errorf("err = %v, want ErrRejected for %q", err, c.why)
			}
		})
	}
}

func TestLoginRejectsTheRightCredentialSignedByTheWrongKey(t *testing.T) {
	svc, _, _ := newService(t)
	a := passkeystest.New(testOrigin)
	register(t, svc, a, "x")
	_, err := login(t, svc, a.Impostor())
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "signature") {
		t.Errorf("err = %v, want a signature failure", err)
	}
}

func TestLoginRejectsAnUnregisteredOrRevokedPasskey(t *testing.T) {
	svc, store, _ := newService(t)
	a := passkeystest.New(testOrigin)
	pk := register(t, svc, a, "x")

	stranger := passkeystest.New(testOrigin)
	if _, err := login(t, svc, stranger); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "not owned") {
		t.Errorf("an unregistered authenticator: err = %v", err)
	}

	// Begin while it is registered, revoke, then finish: still refused.
	id, opts, err := svc.BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(pk.ID); err != nil {
		t.Fatal(err)
	}
	resp, _ := a.Login(opts)
	if _, err := svc.FinishLogin(id, resp); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "does not own") {
		t.Errorf("revoked mid-ceremony: err = %v", err)
	}
	if _, _, err := svc.BeginLogin(); !errors.Is(err, ErrNoPasskeys) {
		t.Errorf("with nothing registered, BeginLogin err = %v, want ErrNoPasskeys", err)
	}
}

func TestCeremoniesAreSingleUse(t *testing.T) {
	svc, _, _ := newService(t)
	a := passkeystest.New(testOrigin)
	register(t, svc, a, "x")
	id, opts, err := svc.BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := a.Login(opts)
	if _, err := svc.FinishLogin(id, resp); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.FinishLogin(id, resp); !errors.Is(err, ErrNoCeremony) {
		t.Errorf("replaying a finished ceremony: err = %v, want ErrNoCeremony", err)
	}
	// The same signed response replayed into a fresh ceremony fails the
	// challenge check.
	id2, _, _ := svc.BeginLogin()
	if _, err := svc.FinishLogin(id2, resp); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "challenge") {
		t.Errorf("replaying a response into a new ceremony: err = %v, want ErrRejected", err)
	}
	// And a failed attempt burns the ceremony too.
	if _, err := svc.FinishLogin(id2, resp); !errors.Is(err, ErrNoCeremony) {
		t.Errorf("retrying a failed ceremony: err = %v", err)
	}
}

func TestCeremonyKindsCannotBeSwapped(t *testing.T) {
	svc, _, _ := newService(t)
	a := passkeystest.New(testOrigin)
	register(t, svc, a, "x")
	lid, _, _ := svc.BeginLogin()
	rid, ropts, _ := svc.BeginRegistration("y")
	resp, _ := passkeystest.New(testOrigin).Register(ropts)
	if _, err := svc.FinishRegistration(lid, resp); !errors.Is(err, ErrNoCeremony) {
		t.Errorf("finishing a registration with a login ceremony: err = %v", err)
	}
	if _, err := svc.FinishLogin(rid, resp); !errors.Is(err, ErrNoCeremony) {
		t.Errorf("finishing a login with a registration ceremony: err = %v", err)
	}
	if _, err := svc.FinishLogin("", resp); !errors.Is(err, ErrNoCeremony) {
		t.Errorf("no ceremony id: err = %v", err)
	}
}

func TestCeremoniesExpire(t *testing.T) {
	svc, _, c := newService(t)
	a := passkeystest.New(testOrigin)
	id, opts, _ := svc.BeginRegistration("x")
	c.Advance(CeremonyTTL + time.Second)
	resp, _ := a.Register(opts)
	if _, err := svc.FinishRegistration(id, resp); !errors.Is(err, ErrNoCeremony) {
		t.Errorf("an expired ceremony: err = %v, want ErrNoCeremony", err)
	}
}

func TestPendingCeremoniesAreBounded(t *testing.T) {
	svc, _, _ := newService(t)
	a := passkeystest.New(testOrigin)
	register(t, svc, a, "x")
	first, opts, _ := svc.BeginLogin()
	for range maxPending {
		if _, _, err := svc.BeginLogin(); err != nil {
			t.Fatal(err)
		}
	}
	if n := svc.pendingCount(); n != maxPending {
		t.Errorf("pending = %d, want the cap %d", n, maxPending)
	}
	resp, _ := a.Login(opts)
	if _, err := svc.FinishLogin(first, resp); !errors.Is(err, ErrNoCeremony) {
		t.Errorf("the oldest ceremony should have been evicted: err = %v", err)
	}
}

func TestExpiredCeremoniesAreSweptBeforeEvictingLiveOnes(t *testing.T) {
	svc, _, c := newService(t)
	for range maxPending {
		svc.BeginRegistration("x")
	}
	c.Advance(CeremonyTTL + time.Second)
	svc.BeginRegistration("x")
	if n := svc.pendingCount(); n != 1 {
		t.Errorf("pending = %d, want only the live one", n)
	}
}

func TestClonedAuthenticatorIsRefused(t *testing.T) {
	svc, store, _ := newService(t)
	a := passkeystest.New(testOrigin)
	register(t, svc, a, "x")
	clone := a.Clone()
	if _, err := login(t, svc, a); err != nil { // counter 0 -> stored 0, then 1
		t.Fatal(err)
	}
	if _, err := login(t, svc, a); err != nil { // stored 1
		t.Fatal(err)
	}
	// The clone still reports the counter the original had when copied.
	clone.SignCount = 1
	if _, err := login(t, svc, clone); !errors.Is(err, ErrCloned) {
		t.Errorf("a counter that went backwards: err = %v, want ErrCloned", err)
	}
	if n := store.List()[0].Credential.Authenticator.SignCount; n != 1 {
		t.Errorf("a refused login must not move the stored counter: %d", n)
	}
}

func TestRegistrationRefusesDuplicatesAndTheCapEarly(t *testing.T) {
	svc, store, _ := newService(t)
	a := passkeystest.New(testOrigin)
	register(t, svc, a, "x")
	// A browser that ignored excludeCredentials still cannot register the
	// same credential twice.
	id, opts, _ := svc.BeginRegistration("again")
	resp, _ := a.Register(opts)
	if _, err := svc.FinishRegistration(id, resp); !errors.Is(err, ErrDuplicate) {
		t.Errorf("err = %v, want ErrDuplicate", err)
	}
	if _, _, err := svc.BeginRegistration(strings.Repeat("x", 65)); !errors.Is(err, ErrInvalid) {
		t.Errorf("a bad name must be refused before the ceremony starts: %v", err)
	}
	for store.Len() < MaxPasskeys {
		register(t, svc, passkeystest.New(testOrigin), "k")
	}
	if _, _, err := svc.BeginRegistration("one more"); !errors.Is(err, ErrTooMany) {
		t.Errorf("at the cap, BeginRegistration err = %v, want ErrTooMany before any ceremony", err)
	}
}

func TestMalformedResponsesAreRejected(t *testing.T) {
	svc, _, _ := newService(t)
	register(t, svc, passkeystest.New(testOrigin), "x")
	id, _, _ := svc.BeginRegistration("y")
	if _, err := svc.FinishRegistration(id, []byte("{not json")); !errors.Is(err, ErrRejected) {
		t.Errorf("registration: %v", err)
	}
	lid, _, _ := svc.BeginLogin()
	if _, err := svc.FinishLogin(lid, []byte(`{"id":"x"}`)); !errors.Is(err, ErrRejected) {
		t.Errorf("login: %v", err)
	}
}

func TestNewServiceNeedsARelyingParty(t *testing.T) {
	store, _ := Open("", "h")
	if _, err := NewService(RelyingParty{}, store, nil); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want ErrNotConfigured", err)
	}
	rp, _ := NewRelyingParty("shepherd.example.com", ":8443")
	svc, err := NewService(rp, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if svc.RP().ID != "shepherd.example.com" {
		t.Errorf("RP = %+v", svc.RP())
	}
	if _, _, err := svc.BeginRegistration("default clock works"); err != nil {
		t.Error(err)
	}
}

func TestAnUnwritableStoreFailsCeremoniesCleanly(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "data")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(sub, "passkeys.json"), "h")
	if err != nil {
		t.Fatal(err)
	}
	rp, _ := NewRelyingParty("shepherd.example.com", ":8443")
	svc, _ := NewService(rp, store, nil)
	os.Chmod(sub, 0o500)
	t.Cleanup(func() { os.Chmod(sub, 0o700) })
	if _, _, err := svc.BeginRegistration("x"); err == nil {
		t.Skip("running with permissions that ignore directory modes")
	}
	if _, _, err := svc.BeginLogin(); err == nil {
		t.Error("BeginLogin must fail when the user handle cannot be saved")
	}
	if store.Len() != 0 || svc.pendingCount() != 0 {
		t.Error("a failed begin must leave nothing behind")
	}
}
