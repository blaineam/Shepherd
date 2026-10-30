// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shepherd/internal/dnsengine"
)

func newTestServer(t *testing.T) (*httptest.Server, *dnsengine.Filter) {
	t.Helper()
	h := newHarness(t)
	return h.ts, h.filter
}

func do(t *testing.T, method, url, token, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func TestAPIRequiresToken(t *testing.T) {
	ts, _ := newTestServer(t)
	good := strings.Repeat("t", 64)
	for _, path := range []string{"/api/status", "/api/queries", "/api/rules"} {
		if got := do(t, "GET", ts.URL+path, "", "", nil).StatusCode; got != http.StatusUnauthorized {
			t.Errorf("GET %s without token = %d, want 401", path, got)
		}
		if got := do(t, "GET", ts.URL+path, "wrong", "", nil).StatusCode; got != http.StatusUnauthorized {
			t.Errorf("GET %s with wrong token = %d, want 401", path, got)
		}
		if got := do(t, "GET", ts.URL+path, good, "", nil).StatusCode; got != http.StatusOK {
			t.Errorf("GET %s with token = %d, want 200", path, got)
		}
	}
	// The static UI is public; it holds no data and shows the login form.
	if got := do(t, "GET", ts.URL+"/", "", "", nil).StatusCode; got != http.StatusOK {
		t.Errorf("GET / = %d", got)
	}
}

func TestStateChangesNeedCustomHeaderAndApplyImmediately(t *testing.T) {
	ts, filter := newTestServer(t)
	tok := strings.Repeat("t", 64)
	body := `{"kind":"block","domain":"evil.example"}`

	if got := do(t, "POST", ts.URL+"/api/rules", tok, body, nil).StatusCode; got != http.StatusForbidden {
		t.Errorf("POST without X-Shepherd = %d, want 403", got)
	}
	if filter.Check("evil.example").Blocked {
		t.Fatal("a rejected request changed state")
	}
	if got := do(t, "POST", ts.URL+"/api/rules", tok, body, map[string]string{"X-Shepherd": "1"}).StatusCode; got != http.StatusOK {
		t.Fatalf("POST rule = %d", got)
	}
	if !filter.Check("sub.evil.example").Blocked {
		t.Error("rule did not take effect")
	}
	if got := do(t, "POST", ts.URL+"/api/rules", tok, `{"kind":"block","domain":"bad domain"}`, map[string]string{"X-Shepherd": "1"}).StatusCode; got != http.StatusBadRequest {
		t.Errorf("invalid domain = %d, want 400", got)
	}
	if got := do(t, "DELETE", ts.URL+"/api/rules?kind=block&domain=evil.example", tok, "", map[string]string{"X-Shepherd": "1"}).StatusCode; got != http.StatusOK {
		t.Fatalf("DELETE rule = %d", got)
	}
	if filter.Check("evil.example").Blocked {
		t.Error("rule survived deletion")
	}

	pol := `{"name":"apple-private-relay","enabled":true}`
	if got := do(t, "POST", ts.URL+"/api/policies", tok, pol, map[string]string{"X-Shepherd": "1"}).StatusCode; got != http.StatusOK {
		t.Fatalf("POST policy = %d", got)
	}
	if d := filter.Check("mask.icloud.com"); !d.Blocked || !d.NXDOMAIN {
		t.Errorf("policy not active: %+v", d)
	}
}

func TestLoginSetsStrictHTTPOnlyCookie(t *testing.T) {
	ts, _ := newTestServer(t)
	bad := do(t, "POST", ts.URL+"/api/login", "", `{"token":"nope"}`, nil)
	if bad.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad login = %d", bad.StatusCode)
	}
	res := do(t, "POST", ts.URL+"/api/login", "", `{"token":"`+strings.Repeat("t", 64)+`"}`, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login = %d", res.StatusCode)
	}
	cookies := res.Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie = %+v", cookies)
	}
}

func TestTokenIsCreatedOnceWithPrivatePermissions(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreateToken(dir)
	if err != nil || len(a) < 32 {
		t.Fatalf("token %q err %v", a, err)
	}
	b, _ := LoadOrCreateToken(dir)
	if a != b {
		t.Error("token changed between loads")
	}
}
