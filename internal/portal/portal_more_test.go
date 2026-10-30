// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var hdr = map[string]string{"X-Shepherd": "1"}

func TestBadRequestsAreRejectedCleanly(t *testing.T) {
	ts, _ := newTestServer(t)
	tok := strings.Repeat("t", 64)
	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"login bad json", "POST", "/api/login", "{not json", 400},
		{"add rule bad json", "POST", "/api/rules", "{not json", 400},
		{"add rule bad kind", "POST", "/api/rules", `{"kind":"maybe","domain":"a.example"}`, 400},
		{"delete rule bad kind", "DELETE", "/api/rules?kind=maybe&domain=a.example", "", 400},
		{"policy bad json", "POST", "/api/policies", "{not json", 400},
		{"policy unknown", "POST", "/api/policies", `{"name":"nope","enabled":true}`, 400},
		{"oversized body", "POST", "/api/rules", `{"kind":"block","domain":"` + strings.Repeat("a", 70000) + `"}`, 400},
	}
	for _, c := range cases {
		got := do(t, c.method, ts.URL+c.path, tok, c.body, hdr).StatusCode
		if got != c.want {
			t.Errorf("%s = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestStatusReportsEverythingTheUINeeds(t *testing.T) {
	ts, _ := newTestServer(t)
	res := do(t, "GET", ts.URL+"/api/status", strings.Repeat("t", 64), "", nil)
	var s map[string]any
	if err := json.NewDecoder(res.Body).Decode(&s); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "uptime_seconds", "stats", "upstreams", "lists", "listed_domains", "allow_rules", "block_rules", "policies"} {
		if _, ok := s[key]; !ok {
			t.Errorf("status lacks %q", key)
		}
	}
	if s["version"] != "test" {
		t.Errorf("version = %v", s["version"])
	}
}

func TestQueriesPagingParameters(t *testing.T) {
	ts, _ := newTestServer(t)
	tok := strings.Repeat("t", 64)
	for _, q := range []string{"", "?limit=abc", "?limit=0", "?limit=99999", "?after=12", "?after=nope"} {
		res := do(t, "GET", ts.URL+"/api/queries"+q, tok, "", nil)
		if res.StatusCode != 200 {
			t.Errorf("queries%s = %d", q, res.StatusCode)
			continue
		}
		var body struct {
			Entries []any  `json:"entries"`
			Last    uint64 `json:"last"`
		}
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil || body.Entries == nil {
			t.Errorf("queries%s must return an entries array (never null): %v %+v", q, err, body)
		}
	}
}

func TestCookieAuthWorksAndStillNeedsCustomHeaderToChangeState(t *testing.T) {
	ts, filter := newTestServer(t)
	login := do(t, "POST", ts.URL+"/api/login", "", `{"token":"`+strings.Repeat("t", 64)+`"}`, nil)
	cookies := login.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %+v", cookies)
	}
	cookie := cookies[0]
	req, _ := http.NewRequest("GET", ts.URL+"/api/rules", nil)
	req.AddCookie(cookie)
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Errorf("cookie auth GET = %d", res.StatusCode)
	}
	post, _ := http.NewRequest("POST", ts.URL+"/api/rules", strings.NewReader(`{"kind":"block","domain":"csrf.example"}`))
	post.AddCookie(cookie)
	res, _ = http.DefaultClient.Do(post)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || filter.Check("csrf.example").Blocked {
		t.Errorf("a cross-site style POST must be refused: %d", res.StatusCode)
	}
}

func TestStaticUIAndSecurityHeaders(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, p := range []string{"/", "/app.js", "/style.css", "/icon.png"} {
		res := do(t, "GET", ts.URL+p, "", "", nil)
		if res.StatusCode != 200 {
			t.Errorf("GET %s = %d", p, res.StatusCode)
		}
		if res.Header.Get("Content-Security-Policy") == "" || res.Header.Get("X-Content-Type-Options") != "nosniff" ||
			res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("GET %s missing security headers: %v", p, res.Header)
		}
	}
}

func TestRefreshListsIsAccepted(t *testing.T) {
	ts, _ := newTestServer(t)
	if got := do(t, "POST", ts.URL+"/api/lists/refresh", strings.Repeat("t", 64), "", hdr).StatusCode; got != http.StatusAccepted {
		t.Errorf("refresh = %d, want 202", got)
	}
}

func TestPolicyToggleRoundTrip(t *testing.T) {
	ts, _ := newTestServer(t)
	tok := strings.Repeat("t", 64)
	on := do(t, "POST", ts.URL+"/api/policies", tok, `{"name":"apple-private-relay","enabled":true}`, hdr)
	var r struct{ Policies map[string]bool }
	json.NewDecoder(on.Body).Decode(&r)
	if !r.Policies["apple-private-relay"] {
		t.Errorf("policy not on: %+v", r)
	}
}

func TestTokenFileHandling(t *testing.T) {
	dir := t.TempDir()
	// A too-short existing token is replaced, not trusted.
	os.WriteFile(filepath.Join(dir, "portal-token"), []byte("short\n"), 0o600)
	tok, err := LoadOrCreateToken(dir)
	if err != nil || len(tok) < 32 || tok == "short" {
		t.Errorf("short token handling: %q %v", tok, err)
	}
	info, _ := os.Stat(filepath.Join(dir, "portal-token"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %v, want 0600", info.Mode().Perm())
	}
	// A directory where the token file belongs is an error, not a silent new token.
	bad := t.TempDir()
	os.MkdirAll(filepath.Join(bad, "portal-token"), 0o750)
	if _, err := LoadOrCreateToken(bad); err == nil {
		t.Error("an unreadable token path must error")
	}
	// Unwritable data dir.
	if _, err := LoadOrCreateToken(filepath.Join(dir, "missing", "deeper")); err == nil {
		t.Error("an unwritable data dir must error")
	}
}
