// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a goroutine-safe, manually advanced clock: the server runs its
// handlers on the test's httptest goroutine, which races with the test
// advancing time unless this is synchronized.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }
func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}
func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

// lockingHarness wraps newHarness with a fake clock, a no-op sleep (so PIN
// lockout delays do not actually slow the tests down) and a cheap Argon2id
// cost (matching how internal/history's tests lower PassphraseKey's cost).
func lockingHarness(t *testing.T) (*harness, *fakeClock) {
	t.Helper()
	h := newHarness(t)
	fc := newFakeClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	h.srv.clock = fc.Now
	h.srv.sleep = func(time.Duration) {}
	h.srv.pinArgonTime, h.srv.pinArgonMem = 1, 8
	return h, fc
}

func jarClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func req(t *testing.T, client *http.Client, method, url, body string, headers map[string]string) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func decodeJSON(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if len(b) > 0 {
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("bad JSON %q: %v", b, err)
		}
	}
	return m
}

var withCSRF = map[string]string{"X-Shepherd": "1"}

func loginWithToken(t *testing.T, h *harness, client *http.Client) map[string]any {
	t.Helper()
	res := req(t, client, "POST", h.ts.URL+"/api/login", `{"token":"`+strings.Repeat("t", 64)+`"}`, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login = %d", res.StatusCode)
	}
	return decodeJSON(t, res)
}

func TestLoginReportsWhetherAPINIsSet(t *testing.T) {
	h, _ := lockingHarness(t)
	m := loginWithToken(t, h, jarClient(t))
	if m["pin_set"] != false {
		t.Errorf("pin_set = %v, want false before any PIN is set", m["pin_set"])
	}
}

func TestPINSetupThenPINLoginAfterLosingTheSession(t *testing.T) {
	h, _ := lockingHarness(t)
	client := jarClient(t)
	loginWithToken(t, h, client)

	setRes := req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF)
	if setRes.StatusCode != http.StatusOK {
		t.Fatalf("set PIN = %d: %s", setRes.StatusCode, mustBody(t, setRes))
	}
	setBody := decodeJSON(t, setRes)
	if setBody["device_id"] == "" || setBody["device_id"] == nil {
		t.Fatalf("set PIN did not return a device_id: %v", setBody)
	}

	// Explicit lock ends the session but must not touch the trusted cookie.
	lockRes := req(t, client, "POST", h.ts.URL+"/api/lock", "", withCSRF)
	if lockRes.StatusCode != http.StatusOK {
		t.Fatalf("lock = %d", lockRes.StatusCode)
	}
	if locked := req(t, client, "GET", h.ts.URL+"/api/trusted-devices", "", nil); locked.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after lock, an authenticated endpoint = %d, want 401", locked.StatusCode)
	}

	pinRes := req(t, client, "POST", h.ts.URL+"/api/login/pin", `{"pin":"a1b2c3"}`, nil)
	if pinRes.StatusCode != http.StatusOK {
		t.Fatalf("PIN login = %d: %s", pinRes.StatusCode, mustBody(t, pinRes))
	}
	again := req(t, client, "GET", h.ts.URL+"/api/trusted-devices", "", nil)
	if again.StatusCode != http.StatusOK {
		t.Fatalf("after PIN login, an authenticated endpoint = %d", again.StatusCode)
	}
}

func mustBody(t *testing.T, res *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(res.Body)
	res.Body = io.NopCloser(strings.NewReader(string(b)))
	return string(b)
}

func TestLoginPINWithoutTrustedCookieIsUnauthorized(t *testing.T) {
	h, _ := lockingHarness(t)
	client := jarClient(t)
	res := req(t, client, "POST", h.ts.URL+"/api/login/pin", `{"pin":"a1b2c3"}`, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("PIN login with no trusted cookie = %d, want 401", res.StatusCode)
	}
}

func TestPINLockoutThenRevocation(t *testing.T) {
	h, fc := lockingHarness(t)
	client := jarClient(t)
	loginWithToken(t, h, client)
	if res := req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF); res.StatusCode != http.StatusOK {
		t.Fatalf("set PIN = %d", res.StatusCode)
	}
	req(t, client, "POST", h.ts.URL+"/api/lock", "", withCSRF)

	wrong := func() int {
		return req(t, client, "POST", h.ts.URL+"/api/login/pin", `{"pin":"wrongpin"}`, nil).StatusCode
	}
	for i := 0; i < pinFailsLockout; i++ {
		if got := wrong(); got != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d, want 401", i, got)
		}
	}
	// Now locked out, even with the right PIN.
	right := req(t, client, "POST", h.ts.URL+"/api/login/pin", `{"pin":"a1b2c3"}`, nil)
	if right.StatusCode != http.StatusLocked {
		t.Fatalf("locked-out attempt = %d, want 423", right.StatusCode)
	}
	if ra := right.Header.Get("Retry-After"); ra == "" {
		t.Error("a 423 should carry Retry-After")
	}

	// After the lockout window passes, the right PIN works again.
	fc.Advance(pinLockoutFor + time.Minute)
	ok := req(t, client, "POST", h.ts.URL+"/api/login/pin", `{"pin":"a1b2c3"}`, nil)
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("after the lockout window, right PIN = %d", ok.StatusCode)
	}
}

func TestPINRevokedAfterTooManyFailures(t *testing.T) {
	h, _ := lockingHarness(t)
	client := jarClient(t)
	loginWithToken(t, h, client)
	req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF)
	req(t, client, "POST", h.ts.URL+"/api/lock", "", withCSRF)

	var last *http.Response
	for i := 0; i < pinFailsRevoke; i++ {
		last = req(t, client, "POST", h.ts.URL+"/api/login/pin", `{"pin":"wrongpin"}`, nil)
	}
	if last.StatusCode != http.StatusUnauthorized {
		t.Fatalf("final failure = %d", last.StatusCode)
	}
	// The device is gone outright now, so even the right PIN is refused.
	right := req(t, client, "POST", h.ts.URL+"/api/login/pin", `{"pin":"a1b2c3"}`, nil)
	if right.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after revoke, right PIN = %d, want 401 (not trusted)", right.StatusCode)
	}
}

func TestIdlePollingAloneDoesNotKeepASessionAlive(t *testing.T) {
	h, fc := lockingHarness(t)
	h.srv.IdleLockMinutes = 10
	client := jarClient(t)
	loginWithToken(t, h, client)

	fc.Advance(9 * time.Minute)
	if res := req(t, client, "GET", h.ts.URL+"/api/status", "", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("status within the idle window = %d", res.StatusCode)
	}
	fc.Advance(9 * time.Minute) // 18 min since creation; status polling never touched it
	if res := req(t, client, "GET", h.ts.URL+"/api/status", "", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status past the idle window = %d, want 401 (passive polling must not extend idle)", res.StatusCode)
	}
}

func TestRealActivityExtendsTheIdleWindow(t *testing.T) {
	h, fc := lockingHarness(t)
	h.srv.IdleLockMinutes = 10
	client := jarClient(t)
	loginWithToken(t, h, client)

	fc.Advance(9 * time.Minute)
	if res := req(t, client, "GET", h.ts.URL+"/api/trusted-devices", "", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("active call within the idle window = %d", res.StatusCode)
	}
	fc.Advance(9 * time.Minute) // only 9 min since the last (active) call
	if res := req(t, client, "GET", h.ts.URL+"/api/trusted-devices", "", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("active call should have slid the idle window forward, got %d", res.StatusCode)
	}
}

func TestIdleLockMinutesZeroNeverLocks(t *testing.T) {
	h, fc := lockingHarness(t)
	h.srv.IdleLockMinutes = 0
	client := jarClient(t)
	loginWithToken(t, h, client)
	fc.Advance(24 * time.Hour)
	if res := req(t, client, "GET", h.ts.URL+"/api/status", "", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("idle_lock_minutes=0 should never lock, got %d", res.StatusCode)
	}
}

func TestExplicitLockEndsTheSession(t *testing.T) {
	h, _ := lockingHarness(t)
	client := jarClient(t)
	loginWithToken(t, h, client)
	if res := req(t, client, "GET", h.ts.URL+"/api/status", "", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("status before lock = %d", res.StatusCode)
	}
	if res := req(t, client, "POST", h.ts.URL+"/api/lock", "", nil); res.StatusCode != http.StatusForbidden {
		t.Fatalf("lock without X-Shepherd = %d, want 403", res.StatusCode)
	}
	if res := req(t, client, "POST", h.ts.URL+"/api/lock", "", withCSRF); res.StatusCode != http.StatusOK {
		t.Fatalf("lock = %d", res.StatusCode)
	}
	if res := req(t, client, "GET", h.ts.URL+"/api/status", "", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status after lock = %d, want 401", res.StatusCode)
	}
	// Locking again, now with no session left, is simply unauthorized like
	// any other protected endpoint: there is nothing left to lock.
	if res := req(t, client, "POST", h.ts.URL+"/api/lock", "", withCSRF); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("locking an already-locked browser = %d, want 401", res.StatusCode)
	}
}

func TestSettingsLockingOverridePersistsAndValidates(t *testing.T) {
	h, _ := lockingHarness(t)
	h.srv.IdleLockMinutes = 10
	client := jarClient(t)
	loginWithToken(t, h, client)

	before := decodeJSON(t, req(t, client, "GET", h.ts.URL+"/api/settings", "", nil))
	locking, _ := before["locking"].(map[string]any)
	if locking["idle_lock_minutes"] != float64(10) {
		t.Fatalf("default idle_lock_minutes = %v", locking["idle_lock_minutes"])
	}

	if res := req(t, client, "POST", h.ts.URL+"/api/settings/locking", `{"idle_lock_minutes":-1}`, withCSRF); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("negative idle_lock_minutes = %d, want 400", res.StatusCode)
	}
	if res := req(t, client, "POST", h.ts.URL+"/api/settings/locking", `{"idle_lock_minutes":0}`, withCSRF); res.StatusCode != http.StatusOK {
		t.Fatalf("set idle_lock_minutes = %d", res.StatusCode)
	}
	after := decodeJSON(t, req(t, client, "GET", h.ts.URL+"/api/settings", "", nil))
	locking2, _ := after["locking"].(map[string]any)
	if locking2["idle_lock_minutes"] != float64(0) {
		t.Fatalf("override did not stick: %v", locking2["idle_lock_minutes"])
	}
}

func TestSetPINValidatesAndReportsPinSet(t *testing.T) {
	h, _ := lockingHarness(t)
	client := jarClient(t)
	loginWithToken(t, h, client)
	cases := []struct{ pin string }{{"short"}, {"111111"}, {"123456"}, {"has space!"}}
	for _, c := range cases {
		if res := req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"`+c.pin+`"}`, withCSRF); res.StatusCode != http.StatusBadRequest {
			t.Errorf("pin %q = %d, want 400", c.pin, res.StatusCode)
		}
	}
	if res := req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF); res.StatusCode != http.StatusOK {
		t.Fatalf("valid pin = %d", res.StatusCode)
	}
	settings := decodeJSON(t, req(t, client, "GET", h.ts.URL+"/api/settings", "", nil))
	locking, _ := settings["locking"].(map[string]any)
	if locking["pin_set"] != true {
		t.Errorf("pin_set = %v, want true", locking["pin_set"])
	}
}

func TestTrustedDevicesListAndRevoke(t *testing.T) {
	h, _ := lockingHarness(t)
	client := jarClient(t)
	loginWithToken(t, h, client)
	setBody := decodeJSON(t, req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF))
	id, _ := setBody["device_id"].(string)
	if id == "" {
		t.Fatal("no device_id")
	}

	list := decodeJSON(t, req(t, client, "GET", h.ts.URL+"/api/trusted-devices", "", nil))
	devs, _ := list["devices"].([]any)
	if len(devs) != 1 {
		t.Fatalf("devices = %v", devs)
	}
	dev, _ := devs[0].(map[string]any)
	for _, forbidden := range []string{"secret", "secret_hash", "hash", "pin"} {
		if _, has := dev[forbidden]; has {
			t.Errorf("trusted device listing leaked %q: %v", forbidden, dev)
		}
	}

	if res := req(t, client, "DELETE", h.ts.URL+"/api/trusted-devices/"+id, "", nil); res.StatusCode != http.StatusForbidden {
		t.Fatalf("revoke without X-Shepherd = %d, want 403", res.StatusCode)
	}
	if res := req(t, client, "DELETE", h.ts.URL+"/api/trusted-devices/"+id, "", withCSRF); res.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d", res.StatusCode)
	}
	if res := req(t, client, "DELETE", h.ts.URL+"/api/trusted-devices/"+id, "", withCSRF); res.StatusCode != http.StatusNotFound {
		t.Fatalf("revoke again = %d, want 404", res.StatusCode)
	}
	list2 := decodeJSON(t, req(t, client, "GET", h.ts.URL+"/api/trusted-devices", "", nil))
	if devs2, _ := list2["devices"].([]any); len(devs2) != 0 {
		t.Fatalf("devices after revoke = %v", devs2)
	}
}

func TestRevokingATrustedDeviceEndsItsSessions(t *testing.T) {
	h, _ := lockingHarness(t)
	client := jarClient(t)
	loginWithToken(t, h, client)
	setBody := decodeJSON(t, req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF))
	id, _ := setBody["device_id"].(string)

	req(t, client, "POST", h.ts.URL+"/api/lock", "", withCSRF)
	if res := req(t, client, "POST", h.ts.URL+"/api/login/pin", `{"pin":"a1b2c3"}`, nil); res.StatusCode != http.StatusOK {
		t.Fatalf("PIN login = %d", res.StatusCode)
	}
	if res := req(t, client, "GET", h.ts.URL+"/api/status", "", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("status with the PIN session = %d", res.StatusCode)
	}

	// Revoke the device from a second, bearer-token-authenticated client.
	other := jarClient(t)
	if res := req(t, other, "DELETE", h.ts.URL+"/api/trusted-devices/"+id, "", map[string]string{"Authorization": "Bearer " + strings.Repeat("t", 64), "X-Shepherd": "1"}); res.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d", res.StatusCode)
	}
	if res := req(t, client, "GET", h.ts.URL+"/api/status", "", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session from a revoked device should be dead, got %d", res.StatusCode)
	}
}

func TestClearPINRevokesTrustedDevicesAndTheirSessions(t *testing.T) {
	h, _ := lockingHarness(t)
	client := jarClient(t)
	loginWithToken(t, h, client)
	req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF)
	req(t, client, "POST", h.ts.URL+"/api/lock", "", withCSRF)
	req(t, client, "POST", h.ts.URL+"/api/login/pin", `{"pin":"a1b2c3"}`, nil)

	bearer := map[string]string{"Authorization": "Bearer " + strings.Repeat("t", 64), "X-Shepherd": "1"}
	if res := req(t, jarClient(t), "DELETE", h.ts.URL+"/api/pin", "", bearer); res.StatusCode != http.StatusOK {
		t.Fatalf("clear PIN = %d", res.StatusCode)
	}
	if res := req(t, client, "GET", h.ts.URL+"/api/status", "", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("clearing the PIN should end sessions from trusted devices, got %d", res.StatusCode)
	}
	if res := req(t, client, "POST", h.ts.URL+"/api/login/pin", `{"pin":"a1b2c3"}`, nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("PIN login after clearing the PIN = %d, want 401", res.StatusCode)
	}
}

func TestSetPINReusesAnExistingTrustedBrowser(t *testing.T) {
	h, _ := lockingHarness(t)
	client := jarClient(t)
	loginWithToken(t, h, client)
	first := decodeJSON(t, req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF))
	second := decodeJSON(t, req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"b2c3d4"}`, withCSRF))
	if first["device_id"] != second["device_id"] {
		t.Fatalf("changing the PIN from an already-trusted browser should keep its device id: %v vs %v", first, second)
	}
	list := decodeJSON(t, req(t, client, "GET", h.ts.URL+"/api/trusted-devices", "", nil))
	if devs, _ := list["devices"].([]any); len(devs) != 1 {
		t.Fatalf("expected exactly one trusted device, got %v", devs)
	}
}

func TestTooManyTrustedDevicesIsRejected(t *testing.T) {
	h, _ := lockingHarness(t)
	for i := 0; i < maxTrustedDevices; i++ {
		c := jarClient(t)
		loginWithToken(t, h, c)
		if res := req(t, c, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF); res.StatusCode != http.StatusOK {
			t.Fatalf("device %d: set PIN = %d", i, res.StatusCode)
		}
	}
	oneMore := jarClient(t)
	loginWithToken(t, h, oneMore)
	res := req(t, oneMore, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("over the cap = %d, want 409", res.StatusCode)
	}
}

func TestLoginPINMissingCSRFHeaderStillWorks(t *testing.T) {
	// /api/login/pin is an entry point like /api/login: it must not require
	// X-Shepherd, since the caller has no session yet to have learned it from.
	h, _ := lockingHarness(t)
	client := jarClient(t)
	loginWithToken(t, h, client)
	req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF)
	req(t, client, "POST", h.ts.URL+"/api/lock", "", withCSRF)
	if res := req(t, client, "POST", h.ts.URL+"/api/login/pin", `{"pin":"a1b2c3"}`, nil); res.StatusCode != http.StatusOK {
		t.Fatalf("PIN login without X-Shepherd = %d", res.StatusCode)
	}
}

func TestParseTrustedCookieRejectsMalformed(t *testing.T) {
	cases := []string{"", "no-dot-here", "id.not-hex", "id."}
	for _, c := range cases {
		if _, _, ok := parseTrustedCookie(c); ok {
			t.Errorf("parseTrustedCookie(%q) should have failed", c)
		}
	}
	id, secret, ok := parseTrustedCookie(encodeTrustedCookie("abc123", []byte{1, 2, 3}))
	if !ok || id != "abc123" || len(secret) != 3 {
		t.Errorf("round trip failed: id=%q secret=%v ok=%v", id, secret, ok)
	}
}

func TestBrowserNameDefaultsAndTruncates(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.invalid", nil)
	if got := browserName(r); got != "Unknown browser" {
		t.Errorf("empty UA: got %q", got)
	}
	r.Header.Set("User-Agent", strings.Repeat("x", 200))
	if got := browserName(r); len(got) != 120 {
		t.Errorf("long UA should be truncated to 120 chars, got %d", len(got))
	}
}

func TestPinParamsDefaults(t *testing.T) {
	s := &Server{}
	if tm, mem := s.pinParams(); tm != 3 || mem != 64*1024 {
		t.Errorf("default pinParams = (%d, %d), want (3, 65536)", tm, mem)
	}
	s.pinArgonTime, s.pinArgonMem = 1, 8
	if tm, mem := s.pinParams(); tm != 1 || mem != 8 {
		t.Errorf("overridden pinParams = (%d, %d), want (1, 8)", tm, mem)
	}
}

func TestLoginPINAndSetPINRejectBadJSON(t *testing.T) {
	h, _ := lockingHarness(t)
	client := jarClient(t)
	loginWithToken(t, h, client)
	if res := req(t, client, "POST", h.ts.URL+"/api/pin", "{not json", withCSRF); res.StatusCode != http.StatusBadRequest {
		t.Errorf("set PIN bad json = %d, want 400", res.StatusCode)
	}
	if res := req(t, client, "POST", h.ts.URL+"/api/login/pin", "{not json", nil); res.StatusCode != http.StatusBadRequest {
		t.Errorf("PIN login bad json = %d, want 400", res.StatusCode)
	}
	if res := req(t, client, "POST", h.ts.URL+"/api/settings/locking", "{not json", withCSRF); res.StatusCode != http.StatusBadRequest {
		t.Errorf("settings/locking bad json = %d, want 400", res.StatusCode)
	}
}

func TestTokenRotationAcrossRestartRevokesPINAndTrustedDevices(t *testing.T) {
	h, _ := lockingHarness(t)
	h.srv.DataDir = t.TempDir()
	// Reopen the lock store the way New() would, now that DataDir is set.
	h.srv.lockStore = openLockStore(h.srv.DataDir+"/locking.json", tokenHash(h.srv.Token))
	client := jarClient(t)
	loginWithToken(t, h, client)
	if res := req(t, client, "POST", h.ts.URL+"/api/pin", `{"pin":"a1b2c3"}`, withCSRF); res.StatusCode != http.StatusOK {
		t.Fatalf("set PIN = %d", res.StatusCode)
	}

	// Simulate a restart with a rotated token: a fresh store opened over the
	// same file, under a different token hash.
	rotated := openLockStore(h.srv.DataDir+"/locking.json", tokenHash("a-different-token"))
	if _, ok := rotated.pin(); ok {
		t.Error("rotating the token should have cleared the PIN")
	}
	if len(rotated.trustedDevices()) != 0 {
		t.Error("rotating the token should have cleared every trusted device")
	}
}
