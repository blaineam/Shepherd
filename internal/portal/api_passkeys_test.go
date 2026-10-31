// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shepherd/internal/passkeys/passkeystest"
)

const (
	pkHost   = "shepherd.example.com"
	pkOrigin = "https://shepherd.example.com:8443"
)

// pkHarness is a portal configured as if [tls] were on for pkHost, served
// over a real TLS listener (httptest.NewTLSServer). Requests carry pkHost
// as their Host, the way a browser at pkOrigin would, so the portal sees
// exactly what it sees in production: r.TLS set and the right name.
type pkHarness struct {
	*harness
	clock   *fakeClock
	tls     *httptest.Server
	dataDir string
}

func passkeyHarness(t *testing.T, adjust func(*Deps)) *pkHarness {
	t.Helper()
	dataDir := t.TempDir()
	h := newHarnessWith(t, func(d *Deps) {
		d.TLSHostname, d.TLSListen, d.DataDir = pkHost, "0.0.0.0:8443", dataDir
		d.IdleLockMinutes = 10 // the shipped default
		if adjust != nil {
			adjust(d)
		}
	})
	fc := newFakeClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	h.srv.clock = fc.Now
	h.srv.sleep = func(time.Duration) {}
	h.srv.pinArgonTime, h.srv.pinArgonMem = 1, 8
	ts := httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(ts.Close)
	return &pkHarness{harness: h, clock: fc, tls: ts, dataDir: dataDir}
}

// browser is one browser at pkOrigin: its own cookie jar, over TLS.
func (p *pkHarness) browser() *http.Client {
	c := jarClient(p.t)
	c.Transport = p.tls.Client().Transport
	return c
}

// send makes a request to the TLS listener addressed to pkHost.
func (p *pkHarness) send(c *http.Client, method, path, body string) *http.Response {
	p.t.Helper()
	return p.sendHost(c, pkHost+":8443", method, path, body)
}

func (p *pkHarness) sendHost(c *http.Client, host, method, path, body string) *http.Response {
	p.t.Helper()
	r, err := http.NewRequest(method, p.tls.URL+path, strings.NewReader(body))
	if err != nil {
		p.t.Fatal(err)
	}
	r.Host = host
	r.Header.Set("X-Shepherd", "1")
	res, err := c.Do(r)
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { res.Body.Close() })
	return res
}

func (p *pkHarness) unlockWithToken(c *http.Client) {
	p.t.Helper()
	if res := p.send(c, "POST", "/api/login", `{"token":"`+strings.Repeat("t", 64)+`"}`); res.StatusCode != http.StatusOK {
		p.t.Fatalf("token login = %d", res.StatusCode)
	}
}

func readAll(t *testing.T, res *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// registerPasskey runs the whole registration through the API from an
// already-unlocked browser c.
func (p *pkHarness) registerPasskey(c *http.Client, a *passkeystest.Authenticator, name string) map[string]any {
	p.t.Helper()
	begin := p.send(c, "POST", "/api/passkeys/register/begin", `{"name":"`+name+`"}`)
	if begin.StatusCode != http.StatusOK {
		p.t.Fatalf("register begin = %d: %s", begin.StatusCode, mustBody(p.t, begin))
	}
	resp, err := a.Register(readAll(p.t, begin))
	if err != nil {
		p.t.Fatal(err)
	}
	finish := p.send(c, "POST", "/api/passkeys/register/finish", string(resp))
	if finish.StatusCode != http.StatusOK {
		p.t.Fatalf("register finish = %d: %s", finish.StatusCode, mustBody(p.t, finish))
	}
	return decodeJSON(p.t, finish)
}

// passkeyLogin runs the login ceremony from browser c and returns the
// finish response.
func (p *pkHarness) passkeyLogin(c *http.Client, a *passkeystest.Authenticator) *http.Response {
	p.t.Helper()
	begin := p.send(c, "POST", "/api/login/passkey/begin", "")
	if begin.StatusCode != http.StatusOK {
		p.t.Fatalf("login begin = %d: %s", begin.StatusCode, mustBody(p.t, begin))
	}
	resp, err := a.Login(readAll(p.t, begin))
	if err != nil {
		p.t.Fatal(err)
	}
	return p.send(c, "POST", "/api/login/passkey/finish", string(resp))
}

func (p *pkHarness) unlocked(c *http.Client) bool {
	p.t.Helper()
	return p.send(c, "GET", "/api/trusted-devices", "").StatusCode == http.StatusOK
}

func TestPasskeyRegisterThenUnlockWithIt(t *testing.T) {
	p := passkeyHarness(t, nil)
	c := p.browser()
	p.unlockWithToken(c)
	a := passkeystest.New(pkOrigin)
	got := p.registerPasskey(c, a, "My phone")
	if got["name"] != "My phone" || got["id"] == nil || got["id"] == "" {
		t.Fatalf("registered = %v", got)
	}

	// Lock, then come back to the lock screen: the passkey option is on.
	if res := p.send(c, "POST", "/api/lock", ""); res.StatusCode != http.StatusOK {
		t.Fatal("lock failed")
	}
	if p.unlocked(c) {
		t.Fatal("still unlocked after Lock")
	}
	avail := decodeJSON(t, p.send(c, "GET", "/api/login/passkey", ""))
	if avail["available"] != true {
		t.Fatalf("lock screen availability = %v", avail)
	}

	res := p.passkeyLogin(c, a)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("passkey login = %d: %s", res.StatusCode, mustBody(t, res))
	}
	if !p.unlocked(c) {
		t.Fatal("a passkey login must unlock exactly like a token or PIN login")
	}

	// It is the same session as any other: idle relock applies to it.
	p.clock.Advance(11 * time.Minute)
	if p.unlocked(c) {
		t.Error("a passkey session must go idle like any other session")
	}

	// The list shows when it was last used.
	list := p.ok("GET", "/api/passkeys", "", http.StatusOK)
	pks := list["passkeys"].([]any)
	if len(pks) != 1 || pks[0].(map[string]any)["last_used"] == nil {
		t.Errorf("passkeys = %v", pks)
	}
}

func TestPasskeysNeedTLSAndSayWhyBeforeAnyCeremony(t *testing.T) {
	h := newHarness(t) // no [tls]
	st := h.ok("GET", "/api/passkeys", "", http.StatusOK)
	if st["configured"] != false || !strings.Contains(st["problem"].(string), "[tls]") {
		t.Errorf("status without [tls] = %v", st)
	}
	code, body := h.call("POST", "/api/passkeys/register/begin", `{"name":"x"}`)
	if code != http.StatusConflict || !strings.Contains(body, "[tls]") {
		t.Errorf("register begin without [tls] = %d %q, want 409 naming [tls]", code, body)
	}
	if h.ok("GET", "/api/login/passkey", "", http.StatusOK)["available"] != false {
		t.Error("the lock screen must not offer passkeys without [tls]")
	}
	if code, _ := h.call("POST", "/api/login/passkey/begin", ""); code != http.StatusConflict {
		t.Errorf("login begin without [tls] = %d, want 409", code)
	}
}

func TestPasskeyRegistrationOverPlainHTTPIsRefusedWithWhereToGo(t *testing.T) {
	p := passkeyHarness(t, nil)
	// The plain-HTTP listener (the LAN IP), unlocked with the token.
	code, body := p.call("POST", "/api/passkeys/register/begin", `{"name":"x"}`)
	if code != http.StatusConflict {
		t.Fatalf("register begin over plain HTTP = %d, want 409", code)
	}
	if !strings.Contains(body, pkOrigin) || !strings.Contains(body, "http://127.0.0.1") {
		t.Errorf("the refusal must say where you are and where passkeys work: %q", body)
	}
	st := p.ok("GET", "/api/passkeys", "", http.StatusOK)
	if st["configured"] != true || st["here"] != false || st["origin"] != pkOrigin || !strings.Contains(st["problem"].(string), pkOrigin) {
		t.Errorf("status over plain HTTP = %v", st)
	}
	// Over HTTPS but at the IP rather than the name (a browser that
	// clicked through the certificate warning): refused the same way.
	ip := p.browser()
	if res := p.sendHost(ip, "192.0.2.10:8443", "POST", "/api/login", `{"token":"`+strings.Repeat("t", 64)+`"}`); res.StatusCode != http.StatusOK {
		t.Fatal("token login at the IP failed")
	}
	res := p.sendHost(ip, "192.0.2.10:8443", "POST", "/api/passkeys/register/begin", `{"name":"x"}`)
	if b := mustBody(t, res); res.StatusCode != http.StatusConflict || !strings.Contains(b, "https://192.0.2.10:8443") {
		t.Errorf("register begin at the IP over HTTPS = %d %q, want 409 naming this page", res.StatusCode, b)
	}
	c := p.browser()
	p.unlockWithToken(c)
	// And at the right place, it is "here".
	if st := decodeJSON(t, p.send(c, "GET", "/api/passkeys", "")); st["here"] != true || st["problem"] != "" {
		t.Errorf("status at the right origin = %v", st)
	}
}

func TestPasskeyLoginOffSiteRevealsNothing(t *testing.T) {
	p := passkeyHarness(t, nil)
	c := p.browser()
	p.unlockWithToken(c)
	p.registerPasskey(c, passkeystest.New(pkOrigin), "x")
	// A visitor on the plain-HTTP listener sees no passkey option and no
	// hostname, even though passkeys exist.
	anon := jarClient(t)
	av := decodeJSON(t, req(t, anon, "GET", p.ts.URL+"/api/login/passkey", "", nil))
	if av["available"] != false {
		t.Errorf("availability over plain HTTP = %v", av)
	}
	res := req(t, anon, "POST", p.ts.URL+"/api/login/passkey/begin", "", nil)
	if b := mustBody(t, res); res.StatusCode != http.StatusConflict || strings.Contains(b, pkHost) {
		t.Errorf("login begin over plain HTTP = %d %q: want 409 without the hostname", res.StatusCode, b)
	}
}

func TestPasskeyRegistrationNeedsAnUnlockedSession(t *testing.T) {
	p := passkeyHarness(t, nil)
	c := p.browser() // never unlocked
	if res := p.send(c, "POST", "/api/passkeys/register/begin", `{"name":"x"}`); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("register begin while locked = %d, want 401: a passkey is never how first access is gained", res.StatusCode)
	}
	if res := p.send(c, "GET", "/api/passkeys", ""); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("listing passkeys while locked = %d, want 401", res.StatusCode)
	}
	// Even with no passkeys at all, the lock screen login cannot be used
	// to get in.
	if res := p.send(c, "POST", "/api/login/passkey/begin", ""); res.StatusCode != http.StatusConflict {
		t.Errorf("login begin with nothing registered = %d, want 409", res.StatusCode)
	}
	if av := decodeJSON(t, p.send(c, "GET", "/api/login/passkey", "")); av["available"] != false {
		t.Errorf("available with nothing registered = %v", av)
	}
}

func TestPasskeyLoginRefusals(t *testing.T) {
	p := passkeyHarness(t, nil)
	owner := p.browser()
	p.unlockWithToken(owner)
	a := passkeystest.New(pkOrigin)
	p.registerPasskey(owner, a, "x")

	t.Run("no ceremony cookie", func(t *testing.T) {
		c := p.browser()
		begin := p.send(c, "POST", "/api/login/passkey/begin", "")
		resp, _ := a.Login(readAll(t, begin))
		other := p.browser() // a different browser finishing it
		if res := p.send(other, "POST", "/api/login/passkey/finish", string(resp)); res.StatusCode != http.StatusUnauthorized {
			t.Errorf("finish from another browser = %d, want 401", res.StatusCode)
		}
		if p.unlocked(other) {
			t.Error("no session may result")
		}
	})
	t.Run("replayed response", func(t *testing.T) {
		c := p.browser()
		begin := p.send(c, "POST", "/api/login/passkey/begin", "")
		resp, _ := a.Login(readAll(t, begin))
		if res := p.send(c, "POST", "/api/login/passkey/finish", string(resp)); res.StatusCode != http.StatusOK {
			t.Fatalf("first finish = %d", res.StatusCode)
		}
		c2 := p.browser()
		p.send(c2, "POST", "/api/login/passkey/begin", "")
		if res := p.send(c2, "POST", "/api/login/passkey/finish", string(resp)); res.StatusCode != http.StatusUnauthorized {
			t.Errorf("replay into a new ceremony = %d, want 401", res.StatusCode)
		}
		if p.unlocked(c2) {
			t.Error("a replay must not unlock")
		}
	})
	t.Run("wrong origin", func(t *testing.T) {
		c := p.browser()
		evil := a.Clone()
		evil.Origin = "https://evil.example.net"
		res := p.passkeyLogin(c, evil)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("wrong origin = %d, want 401", res.StatusCode)
		}
		for _, ck := range res.Cookies() {
			if ck.Name == cookieName && ck.Value != "" {
				t.Error("a refused login must not set a session cookie")
			}
		}
		if p.unlocked(c) {
			t.Error("a wrong origin must not unlock")
		}
	})
	t.Run("unknown authenticator", func(t *testing.T) {
		c := p.browser()
		if res := p.passkeyLogin(c, passkeystest.New(pkOrigin)); res.StatusCode != http.StatusUnauthorized {
			t.Errorf("unregistered authenticator = %d, want 401", res.StatusCode)
		}
	})
	t.Run("expired ceremony", func(t *testing.T) {
		c := p.browser()
		begin := p.send(c, "POST", "/api/login/passkey/begin", "")
		resp, _ := a.Login(readAll(t, begin))
		p.clock.Advance(6 * time.Minute)
		res := p.send(c, "POST", "/api/login/passkey/finish", string(resp))
		if b := mustBody(t, res); res.StatusCode != http.StatusUnauthorized || !strings.Contains(b, "expired") {
			t.Errorf("expired ceremony = %d %q", res.StatusCode, b)
		}
	})
	t.Run("oversized body", func(t *testing.T) {
		c := p.browser()
		p.send(c, "POST", "/api/login/passkey/begin", "")
		if res := p.send(c, "POST", "/api/login/passkey/finish", strings.Repeat("x", 1<<17)); res.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("oversized finish = %d, want 413", res.StatusCode)
		}
	})
}

func TestPasskeyLoginRefusesAClonedAuthenticator(t *testing.T) {
	p := passkeyHarness(t, nil)
	owner := p.browser()
	p.unlockWithToken(owner)
	a := passkeystest.New(pkOrigin)
	p.registerPasskey(owner, a, "key")
	clone := a.Clone()
	for range 2 {
		if res := p.passkeyLogin(p.browser(), a); res.StatusCode != http.StatusOK {
			t.Fatal("login with the original failed")
		}
	}
	clone.SignCount = 1
	res := p.passkeyLogin(p.browser(), clone)
	if b := mustBody(t, res); res.StatusCode != http.StatusUnauthorized || !strings.Contains(b, "cloned") {
		t.Errorf("clone = %d %q, want 401 explaining the counter", res.StatusCode, b)
	}
}

func TestPasskeyRegistrationErrors(t *testing.T) {
	p := passkeyHarness(t, nil)
	c := p.browser()
	p.unlockWithToken(c)
	a := passkeystest.New(pkOrigin)
	p.registerPasskey(c, a, "first")

	if res := p.send(c, "POST", "/api/passkeys/register/begin", `{"name":"`+strings.Repeat("x", 65)+`"}`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("a bad name = %d, want 400", res.StatusCode)
	}
	if res := p.send(c, "POST", "/api/passkeys/register/begin", `{"name":`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", res.StatusCode)
	}
	// The same authenticator again: 409.
	begin := p.send(c, "POST", "/api/passkeys/register/begin", `{"name":"again"}`)
	resp, _ := a.Register(readAll(t, begin))
	if res := p.send(c, "POST", "/api/passkeys/register/finish", string(resp)); res.StatusCode != http.StatusConflict {
		t.Errorf("duplicate = %d, want 409", res.StatusCode)
	}
	// A response from the wrong origin: 400, with the library's reason.
	evil := passkeystest.New("http://192.0.2.10:8787")
	begin = p.send(c, "POST", "/api/passkeys/register/begin", `{"name":"evil"}`)
	resp, _ = evil.Register(readAll(t, begin))
	res := p.send(c, "POST", "/api/passkeys/register/finish", string(resp))
	if b := mustBody(t, res); res.StatusCode != http.StatusBadRequest || !strings.Contains(b, "origin") {
		t.Errorf("wrong origin = %d %q", res.StatusCode, b)
	}
	// No ceremony at all.
	if res := p.send(p.browserUnlocked(), "POST", "/api/passkeys/register/finish", string(resp)); res.StatusCode != http.StatusBadRequest {
		t.Errorf("finish without a ceremony = %d, want 400", res.StatusCode)
	}
	// A login ceremony cannot finish a registration.
	p.send(c, "POST", "/api/login/passkey/begin", "")
	if res := p.send(c, "POST", "/api/passkeys/register/finish", string(resp)); res.StatusCode != http.StatusBadRequest {
		t.Errorf("finish with a login ceremony = %d, want 400", res.StatusCode)
	}
	// The cap.
	for len(p.srv.passkeyStore.List()) < 20 {
		p.registerPasskey(c, passkeystest.New(pkOrigin), "k")
	}
	if res := p.send(c, "POST", "/api/passkeys/register/begin", `{"name":"21st"}`); res.StatusCode != http.StatusConflict {
		t.Errorf("past the cap = %d, want 409", res.StatusCode)
	}
}

func (p *pkHarness) browserUnlocked() *http.Client {
	c := p.browser()
	p.unlockWithToken(c)
	return c
}

func TestPasskeyRenameAndRevoke(t *testing.T) {
	p := passkeyHarness(t, nil)
	owner := p.browserUnlocked()
	a := passkeystest.New(pkOrigin)
	id := p.registerPasskey(owner, a, "old")["id"].(string)

	got := p.ok("PATCH", "/api/passkeys/"+id, `{"name":"Laptop"}`, http.StatusOK)
	if got["name"] != "Laptop" {
		t.Errorf("renamed = %v", got)
	}
	p.expect("PATCH", "/api/passkeys/"+id, `{"name":"`+strings.Repeat("x", 65)+`"}`, http.StatusBadRequest)
	p.expect("PATCH", "/api/passkeys/nope", `{"name":"x"}`, http.StatusNotFound)
	p.expect("PATCH", "/api/passkeys/"+id, `{"name":`, http.StatusBadRequest)

	// Sign in with it, then revoke it from another session: that session
	// ends and the passkey cannot sign in again.
	c := p.browser()
	if res := p.passkeyLogin(c, a); res.StatusCode != http.StatusOK {
		t.Fatal("passkey login failed")
	}
	p.ok("DELETE", "/api/passkeys/"+id, "", http.StatusOK)
	if p.unlocked(c) {
		t.Error("revoking a passkey must end the sessions it opened")
	}
	if !p.unlocked(owner) {
		t.Error("revoking a passkey must not end the token session that revoked it")
	}
	p.expect("DELETE", "/api/passkeys/"+id, "", http.StatusNotFound)
	if av := decodeJSON(t, p.send(c, "GET", "/api/login/passkey", "")); av["available"] != false {
		t.Error("with its only passkey revoked, the lock screen stops offering passkeys")
	}
}

func TestPasskeysNeverWeakenTheTokenOrPIN(t *testing.T) {
	p := passkeyHarness(t, nil)
	c := p.browserUnlocked()
	// A PIN on this browser first.
	if res := p.send(c, "POST", "/api/pin", `{"pin":"a1b2c3"}`); res.StatusCode != http.StatusOK {
		t.Fatalf("set PIN = %d", res.StatusCode)
	}
	p.registerPasskey(c, passkeystest.New(pkOrigin), "x")

	// The PIN still unlocks this browser.
	p.send(c, "POST", "/api/lock", "")
	if res := p.send(c, "POST", "/api/login/pin", `{"pin":"a1b2c3"}`); res.StatusCode != http.StatusOK {
		t.Errorf("PIN login after registering a passkey = %d", res.StatusCode)
	}
	// The token still unlocks a fresh browser, and still works as a bearer.
	p.browserUnlocked()
	p.ok("GET", "/api/passkeys", "", http.StatusOK)
	// Turning the PIN off leaves passkeys alone, and vice versa.
	if res := p.send(c, "DELETE", "/api/pin", ""); res.StatusCode != http.StatusOK {
		t.Fatal("clear PIN failed")
	}
	if n := len(p.srv.passkeyStore.List()); n != 1 {
		t.Errorf("turning the PIN off removed passkeys: %d left", n)
	}
	st := p.ok("GET", "/api/settings", "", http.StatusOK)
	if st["locking"].(map[string]any)["pin_set"] != false {
		t.Error("expected the PIN to be off")
	}
}

func TestPasskeysAreWipedWhenTheTokenRotates(t *testing.T) {
	p := passkeyHarness(t, nil)
	p.registerPasskey(p.browserUnlocked(), passkeystest.New(pkOrigin), "x")
	if _, err := os.Stat(filepath.Join(p.dataDir, "passkeys.json")); err != nil {
		t.Fatalf("passkeys.json not written: %v", err)
	}
	h2 := newHarnessWith(t, func(d *Deps) {
		d.TLSHostname, d.TLSListen, d.DataDir = pkHost, ":8443", p.dataDir
		d.Token = strings.Repeat("u", 64)
	})
	if n := len(h2.srv.passkeyStore.List()); n != 0 {
		t.Errorf("a rotated token must revoke every passkey; %d survived", n)
	}
}

func TestACorruptPasskeyFileDisablesOnlyPasskeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")
	if err := os.WriteFile(path, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarnessWith(t, func(d *Deps) { d.TLSHostname, d.TLSListen, d.DataDir = pkHost, ":8443", dir })
	code, body := h.call("GET", "/api/passkeys", "")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "passkeys.json") {
		t.Errorf("list with a corrupt file = %d %q, want 503 naming the file", code, body)
	}
	for _, path := range []string{"/api/passkeys/register/begin", "/api/passkeys/register/finish", "/api/login/passkey/begin", "/api/login/passkey/finish"} {
		if code, _ := h.call("POST", path, "{}"); code != http.StatusServiceUnavailable {
			t.Errorf("POST %s with a corrupt file = %d, want 503", path, code)
		}
	}
	h.expect("PATCH", "/api/passkeys/x", `{"name":"y"}`, http.StatusServiceUnavailable)
	h.expect("DELETE", "/api/passkeys/x", "", http.StatusServiceUnavailable)
	if h.ok("GET", "/api/login/passkey", "", http.StatusOK)["available"] != false {
		t.Error("a corrupt file must hide the lock screen option")
	}
	// The token still works, and the file was not overwritten.
	loginWithToken(t, h, jarClient(t))
	if b, _ := os.ReadFile(path); string(b) != "{corrupt" {
		t.Errorf("the corrupt file was touched: %q", b)
	}
}

func TestPasskeyListShowsNothingSecret(t *testing.T) {
	p := passkeyHarness(t, nil)
	p.registerPasskey(p.browserUnlocked(), passkeystest.New(pkOrigin), "x")
	_, body := p.call("GET", "/api/passkeys", "")
	for _, leak := range []string{"publicKey", "user_handle", "credential", "signCount"} {
		if strings.Contains(body, leak) {
			t.Errorf("the list exposes %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, `"max":20`) {
		t.Errorf("the list should say how many passkeys fit: %s", body)
	}
}

func TestPasskeyFinishRoutesRefuseOffSiteAndOversized(t *testing.T) {
	p := passkeyHarness(t, nil)
	// Over the plain-HTTP listener, both finishes refuse before looking
	// at any ceremony.
	if code, _ := p.call("POST", "/api/passkeys/register/finish", "{}"); code != http.StatusConflict {
		t.Errorf("register finish over plain HTTP = %d, want 409", code)
	}
	anon := jarClient(t)
	if res := req(t, anon, "POST", p.ts.URL+"/api/login/passkey/finish", "{}", nil); res.StatusCode != http.StatusConflict {
		t.Errorf("login finish over plain HTTP = %d, want 409", res.StatusCode)
	}
	c := p.browserUnlocked()
	if res := p.send(c, "POST", "/api/passkeys/register/finish", strings.Repeat("x", 1<<17)); res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized register finish = %d, want 413", res.StatusCode)
	}
}

func TestPasskeyRoutesWhenTheDiskRefusesASave(t *testing.T) {
	p := passkeyHarness(t, nil)
	c := p.browserUnlocked()
	a := passkeystest.New(pkOrigin)
	id := p.registerPasskey(c, a, "x")["id"].(string)

	// Start a registration and a login while the disk still works.
	begin := p.send(c, "POST", "/api/passkeys/register/begin", `{"name":"y"}`)
	regResp, _ := passkeystest.New(pkOrigin).Register(readAll(t, begin))
	lc := p.browser()
	lbegin := p.send(lc, "POST", "/api/login/passkey/begin", "")
	loginResp, _ := a.Login(readAll(t, lbegin))

	os.Chmod(p.dataDir, 0o500)
	t.Cleanup(func() { os.Chmod(p.dataDir, 0o700) })
	probe := filepath.Join(p.dataDir, "probe")
	if err := os.WriteFile(probe, nil, 0o600); err == nil {
		t.Skip("running with permissions that ignore directory modes")
	}

	if res := p.send(c, "POST", "/api/passkeys/register/finish", string(regResp)); res.StatusCode != http.StatusInternalServerError {
		t.Errorf("register finish with a read-only disk = %d, want 500", res.StatusCode)
	}
	if res := p.send(lc, "POST", "/api/login/passkey/finish", string(loginResp)); res.StatusCode != http.StatusInternalServerError {
		t.Errorf("login finish with a read-only disk = %d, want 500", res.StatusCode)
	}
	if p.unlocked(lc) {
		t.Error("a login whose counter could not be saved must not unlock: the next clone check would be blind")
	}
	p.expect("PATCH", "/api/passkeys/"+id, `{"name":"z"}`, http.StatusInternalServerError)
	p.expect("DELETE", "/api/passkeys/"+id, "", http.StatusInternalServerError)
}

func TestPasskeyBeginFailsCleanlyWhenTheUserHandleCannotBeSaved(t *testing.T) {
	p := passkeyHarness(t, nil)
	c := p.browserUnlocked()
	os.Chmod(p.dataDir, 0o500)
	t.Cleanup(func() { os.Chmod(p.dataDir, 0o700) })
	if err := os.WriteFile(filepath.Join(p.dataDir, "probe"), nil, 0o600); err == nil {
		t.Skip("running with permissions that ignore directory modes")
	}
	if res := p.send(c, "POST", "/api/passkeys/register/begin", `{"name":"x"}`); res.StatusCode != http.StatusInternalServerError {
		t.Errorf("register begin with a read-only disk = %d, want 500", res.StatusCode)
	}
	if res := p.send(p.browser(), "POST", "/api/login/passkey/begin", ""); res.StatusCode != http.StatusInternalServerError {
		t.Errorf("login begin with a read-only disk = %d, want 500", res.StatusCode)
	}
}

func TestPasskeysFromAnOldHostnameAreListedButNotOffered(t *testing.T) {
	p := passkeyHarness(t, nil)
	p.registerPasskey(p.browserUnlocked(), passkeystest.New(pkOrigin), "old phone")
	// [tls].hostname changes; same data directory, same token.
	h2 := newHarnessWith(t, func(d *Deps) {
		d.TLSHostname, d.TLSListen, d.DataDir = "portal.example.com", ":8443", p.dataDir
	})
	st := h2.ok("GET", "/api/passkeys", "", http.StatusOK)
	pks := st["passkeys"].([]any)
	if len(pks) != 1 || pks[0].(map[string]any)["rp_id"] != pkHost || st["rp_id"] != "portal.example.com" {
		t.Errorf("status after a hostname change = %v", st)
	}
	ts := httptest.NewTLSServer(h2.srv.Handler())
	t.Cleanup(ts.Close)
	r, _ := http.NewRequest("GET", ts.URL+"/api/login/passkey", nil)
	r.Host = "portal.example.com:8443"
	res, err := ts.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	if av := decodeJSON(t, res); av["available"] != false {
		t.Errorf("with only a passkey for the old hostname, availability = %v, want false", av)
	}
}
