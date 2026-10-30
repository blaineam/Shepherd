// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientFullFlow(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	ctx := context.Background()
	if c.HasSession() {
		t.Fatal("session before login")
	}
	login(t, c)
	if !c.HasSession() {
		t.Fatal("no session after verify")
	}
	nets, err := c.Networks(ctx)
	if err != nil || len(nets) != 2 || nets[0].ID != "1001" || nets[0].Name != "Home" || nets[1].Name != "Cabin" {
		t.Fatalf("%v %+v", err, nets)
	}
	snap, err := c.Snapshot(ctx, nets[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Devices) != 3 || len(snap.Profiles) != 2 || len(snap.Nodes) != 2 || len(snap.Warnings) != 0 {
		t.Fatalf("%+v", snap)
	}
	d := snap.Devices[0]
	if d.Nickname != "Kids Tablet" || d.MAC != "02:00:5E:00:00:11" || len(d.IPs) != 3 || d.IPs[0] != "192.0.2.21" || !d.Paused ||
		d.NodeLocation != "Living Room" || d.ProfileName != "Kids" || d.Connection != "wireless" || d.Manufacturer != "ExampleCo" {
		t.Fatalf("%+v", d)
	}
	if snap.Devices[1].Connection != "wired" || !snap.Devices[2].Guest || snap.Devices[2].Nickname != "" {
		t.Fatalf("%+v", snap.Devices[1:])
	}
	if p := snap.Profiles[0]; p.Name != "Kids" || len(p.DeviceMACs) != 1 || len(p.DeviceURLs) != 1 {
		t.Fatalf("%+v", p)
	}
	if n := snap.Nodes[0]; !n.Gateway || n.MAC != "00:00:5e:00:00:01" || n.Location != "Living Room" {
		t.Fatalf("%+v", n)
	}

	reqs := f.requests()
	if reqs[0].Path != "/2.2/login" || reqs[0].Cookie != "" || !strings.Contains(reqs[0].Body, testEmail) {
		t.Fatalf("login request: %+v", reqs[0])
	}
	if reqs[1].Path != "/2.2/login/verify" || reqs[1].Cookie != testPending || !strings.Contains(reqs[1].Body, testCode) {
		t.Fatalf("verify request: %+v", reqs[1])
	}
	for _, r := range reqs[2:] {
		if r.Method != http.MethodGet || r.Cookie != testPending || r.Body != "" {
			t.Fatalf("data request: %+v", r)
		}
	}
}

func TestLoginWithPhone(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	if err := c.StartLogin(context.Background(), "  "+testPhone+" "); err != nil {
		t.Fatal(err)
	}
}

func TestBaseURLRules(t *testing.T) {
	if c, err := NewClient(ClientOptions{}); err != nil || c.base.String() != DefaultEeroBaseURL {
		t.Fatalf("default: %v", err)
	}
	for _, bad := range []string{"http://api.example.com", "ftp://x", "https://", "://bad", "https://user:pw@api.example.com", "api.example.com"} { // leakcheck:allow credentials-in-URL test value
		if _, err := NewClient(ClientOptions{BaseURL: bad}); !errors.Is(err, ErrEeroBadURL) {
			t.Errorf("NewClient(%q): %v", bad, err)
		}
	}
	for _, bad := range []string{"http://api.example.com", "http://192.0.2.1:80", "ftp://127.0.0.1", "http://", "://bad", "http://u:p@localhost"} {
		if _, err := NewTestClient(bad, ClientOptions{}); !errors.Is(err, ErrEeroBadURL) {
			t.Errorf("NewTestClient(%q): %v", bad, err)
		}
	}
	for _, ok := range []string{"http://127.0.0.1:1234", "http://localhost:80", "http://[::1]:99", "https://api.example.com"} {
		if _, err := NewTestClient(ok, ClientOptions{}); err != nil {
			t.Errorf("NewTestClient(%q): %v", ok, err)
		}
	}
}

func TestTLSIsVerifiedByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached a server with an untrusted certificate")
	}))
	defer srv.Close()
	logs := &logCapture{}
	c, err := NewTestClient(srv.URL, ClientOptions{MinInterval: -1, Logger: logs.logger()})
	if err != nil {
		t.Fatal(err)
	}
	err = c.StartLogin(context.Background(), testEmail)
	if err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if contains(err.Error(), testEmail) || contains(logs.String(), testEmail) {
		t.Fatal("credential leaked on a TLS failure")
	}
	// A client that trusts the test CA works over https.
	var gotTLS bool
	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTLS = r.TLS != nil && r.TLS.Version >= tls.VersionTLS12
		_, _ = io.WriteString(w, envelopeOf(`{"user_token":"`+testPending+`"}`))
	}))
	defer srv2.Close()
	c2, _ := NewTestClient(srv2.URL, ClientOptions{MinInterval: -1, HTTPClient: srv2.Client()})
	if err := c2.StartLogin(context.Background(), testEmail); err != nil || !gotTLS {
		t.Fatalf("%v tls=%v", err, gotTLS)
	}
}

func TestRedirectToOtherHostRefused(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("followed a redirect to another host")
	}))
	defer other.Close()
	f := newFakeEero(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		http.Redirect(w, r, strings.Replace(other.URL, "127.0.0.1", "localhost", 1)+"/steal", http.StatusTemporaryRedirect)
		return true
	}
	c, _ := testClient(t, f, nil)
	err := c.StartLogin(context.Background(), testEmail)
	if err == nil || contains(err.Error(), testEmail) {
		t.Fatalf("%v", err)
	}
}

func TestRedirectLoopIsBounded(t *testing.T) {
	f := newFakeEero(t)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		http.Redirect(w, r, "/2.2/loop", http.StatusTemporaryRedirect)
		return true
	}
	c, _ := testClient(t, f, nil)
	if err := c.StartLogin(context.Background(), testEmail); err == nil {
		t.Fatal("expected an error")
	}
}

func TestInvalidAndExpiredCodes(t *testing.T) {
	f := newFakeEero(t)
	logs := &logCapture{}
	c, _ := testClient(t, f, func(o *ClientOptions) { o.Logger = logs.logger() })
	ctx := context.Background()
	if err := c.Verify(ctx, testCode); err == nil || errors.Is(err, ErrEeroInvalidCode) {
		t.Fatalf("verify before login: %v", err)
	}
	if err := c.StartLogin(ctx, testEmail); err != nil {
		t.Fatal(err)
	}
	err := c.Verify(ctx, "111111")
	var ae *APIError
	if !errors.Is(err, ErrEeroInvalidCode) || !errors.As(err, &ae) || ae.Status != 401 {
		t.Fatalf("%v", err)
	}
	if contains(err.Error(), "111111") || contains(ae.Message, "111111") {
		t.Fatalf("the code was echoed in an error: %v / %q", err, ae.Message)
	}
	if c.HasSession() {
		t.Fatal("session after a bad code")
	}
	if err := c.Verify(ctx, "000000"); !errors.Is(err, ErrEeroCodeExpired) {
		t.Fatalf("%v", err)
	}
	if err := c.Verify(ctx, "  "); !errors.Is(err, ErrEeroInvalidCode) {
		t.Fatalf("%v", err)
	}
	if err := c.Verify(ctx, testCode); err != nil {
		t.Fatalf("a right code after wrong ones: %v", err)
	}
	if contains(logs.String(), "111111", testCode, testEmail, testPending) {
		t.Fatalf("logs leak a secret:\n%s", logs.String())
	}
}

func TestBadLogin(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	if err := c.StartLogin(context.Background(), "   "); err == nil {
		t.Fatal("empty login accepted")
	}
	err := c.StartLogin(context.Background(), "nobody@example.net")
	if err == nil || contains(err.Error(), "nobody@example.net") {
		t.Fatalf("%v", err)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 422 || ae.Code != 422 || ae.Message != "error.login.invalid" {
		t.Fatalf("%v", err)
	}
}

func TestCredentialsNeverInLogsOrErrors(t *testing.T) {
	f := newFakeEero(t)
	logs := &logCapture{}
	c, _ := testClient(t, f, func(o *ClientOptions) { o.Logger = logs.logger() })
	ctx := context.Background()
	var errs []string
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	// The server echoes credentials in its error text; none may surface.
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/2.2/networks/1001/devices" {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, errBody(500, "boom "+testEmail+" "+testCode+" "+testPending))
			return true
		}
		return false
	}
	collect(c.StartLogin(ctx, testEmail))
	collect(c.Verify(ctx, "999999"))
	collect(c.Verify(ctx, testCode))
	_, err := c.Devices(ctx, "1001")
	collect(err)
	_, err = c.Devices(ctx, "1001")
	if err == nil {
		t.Fatal("expected an error")
	}
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("%v", err)
	}
	if contains(ae.Message, testEmail, testCode, testPending) || !strings.Contains(ae.Message, "[redacted]") {
		t.Fatalf("message not scrubbed: %q", ae.Message)
	}
	collect(err)
	// Transport failure after the server is gone.
	f.srv.Close()
	collect(c.StartLogin(ctx, testEmail))
	for _, e := range errs {
		if contains(e, testEmail, testCode, testPending, "999999") {
			t.Errorf("error leaks a credential: %q", e)
		}
	}
	if contains(logs.String(), testEmail, testCode, testPending, "999999", testSession) {
		t.Errorf("logs leak a credential:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "/2.2/login") {
		t.Errorf("expected request logging, got:\n%s", logs.String())
	}
}

func TestSessionExpiredAndNoSession(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	ctx := context.Background()
	if _, err := c.Networks(ctx); !errors.Is(err, ErrEeroNoSession) {
		t.Fatalf("%v", err)
	}
	if _, err := c.Devices(ctx, "1001"); !errors.Is(err, ErrEeroNoSession) {
		t.Fatalf("%v", err)
	}
	login(t, c)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, errBody(401, "error.session.refresh"))
		return true
	}
	if _, err := c.Networks(ctx); !errors.Is(err, ErrEeroSessionExpire) {
		t.Fatalf("%v", err)
	}
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(403)
		_, _ = io.WriteString(w, errBody(403, "forbidden"))
		return true
	}
	if _, err := c.Networks(ctx); !errors.Is(err, ErrEeroUnauthorized) {
		t.Fatalf("%v", err)
	}
	// An error inside a 200 envelope is still an error.
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		_, _ = io.WriteString(w, errBody(401, "error.session.invalid"))
		return true
	}
	if _, err := c.Networks(ctx); !errors.Is(err, ErrEeroSessionExpire) {
		t.Fatalf("%v", err)
	}
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "not json")
		return true
	}
	var ae *APIError
	if _, err := c.Networks(ctx); !errors.As(err, &ae) || ae.Status != 404 || ae.Error() != "eero: HTTP 404" {
		t.Fatalf("%v", err)
	}
}

func TestDiscardAndTokenStore(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	login(t, c)
	c.Discard()
	if c.HasSession() {
		t.Fatal("session survived Discard")
	}
	if _, err := c.Networks(context.Background()); !errors.Is(err, ErrEeroNoSession) {
		t.Fatalf("%v", err)
	}
	// Default: nothing is stored anywhere and there is nothing to resume.
	if ok, err := c.Resume(); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if err := c.Forget(); err != nil {
		t.Fatal(err)
	}
}

type memStore struct {
	tok            string
	saves, deletes int
	failSave       bool
	failLoad       bool
}

func (m *memStore) Load() (string, error) {
	if m.failLoad {
		return "", errors.New("load failed")
	}
	return m.tok, nil
}
func (m *memStore) Save(t string) error {
	m.saves++
	if m.failSave {
		return errors.New("disk full")
	}
	m.tok = t
	return nil
}
func (m *memStore) Delete() error { m.deletes++; m.tok = ""; return nil }

func TestTokenStoreOnlyWhenProvided(t *testing.T) {
	f := newFakeEero(t)
	st := &memStore{}
	c, _ := testClient(t, f, func(o *ClientOptions) { o.TokenStore = st })
	ctx := context.Background()
	if err := c.StartLogin(ctx, testEmail); err != nil {
		t.Fatal(err)
	}
	if st.saves != 0 {
		t.Fatal("token stored before it was verified")
	}
	if err := c.Verify(ctx, testCode); err != nil {
		t.Fatal(err)
	}
	if st.saves != 1 || st.tok != testPending {
		t.Fatalf("%+v", st)
	}
	c.Discard()
	if st.tok == "" {
		t.Fatal("Discard must not touch the caller's store")
	}
	// A new client resumes from the store without logging in again.
	c2, _ := testClient(t, f, func(o *ClientOptions) { o.TokenStore = st })
	if ok, err := c2.Resume(); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if nets, err := c2.Networks(ctx); err != nil || len(nets) != 2 {
		t.Fatalf("%v %v", err, nets)
	}
	if err := c2.Forget(); err != nil || st.deletes != 1 || st.tok != "" || c2.HasSession() {
		t.Fatalf("%v %+v", err, st)
	}
	if ok, _ := c2.Resume(); ok {
		t.Fatal("resumed after Forget")
	}
	st.failLoad = true
	if _, err := c2.Resume(); err == nil {
		t.Fatal("load error swallowed")
	}
	// A store that fails to save is reported.
	c3, _ := testClient(t, f, func(o *ClientOptions) { o.TokenStore = &memStore{failSave: true} })
	_ = c3.StartLogin(ctx, testEmail)
	if err := c3.Verify(ctx, testCode); err == nil || contains(err.Error(), testPending) {
		t.Fatalf("%v", err)
	}
}

func TestRateLimitRetryAfter(t *testing.T) {
	f := newFakeEero(t)
	c, sl := testClient(t, f, nil)
	login(t, c)
	calls := 0
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/2.2/account" {
			return false
		}
		calls++
		if calls <= 2 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(429)
			_, _ = io.WriteString(w, errBody(429, "error.rate-limit"))
			return true
		}
		return false
	}
	nets, err := c.Networks(context.Background())
	if err != nil || len(nets) != 2 || calls != 3 {
		t.Fatalf("%v %v calls=%d", err, nets, calls)
	}
	if got := sl.list(); len(got) != 2 || got[0] != 3*time.Second || got[1] != 3*time.Second {
		t.Fatalf("sleeps %v", got)
	}
}

func TestRateLimitExhaustedAndTooLong(t *testing.T) {
	f := newFakeEero(t)
	c, sl := testClient(t, f, func(o *ClientOptions) { o.MaxRetries = 2; o.MaxRetryWait = 10 * time.Second })
	login(t, c)
	hits := 0
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/2.2/account" {
			hits++
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return true
		}
		return false
	}
	_, err := c.Networks(context.Background())
	var ae *APIError
	if !errors.Is(err, ErrEeroRateLimited) || !errors.As(err, &ae) || ae.RetryAfter != time.Second || hits != 3 {
		t.Fatalf("%v hits=%d", err, hits)
	}
	if len(sl.list()) != 2 {
		t.Fatalf("sleeps %v", sl.list())
	}
	// A Retry-After beyond the cap is reported at once, without waiting.
	hits = 0
	before := len(sl.list())
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		hits++
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(429)
		return true
	}
	_, err = c.Networks(context.Background())
	if !errors.Is(err, ErrEeroRateLimited) || hits != 1 || len(sl.list()) != before {
		t.Fatalf("%v hits=%d", err, hits)
	}
	if !errors.As(err, &ae) || ae.RetryAfter != time.Hour {
		t.Fatalf("%+v", ae)
	}
}

func TestRetryAfterForms(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	c := &Client{now: func() time.Time { return now }}
	mk := func(v string) *http.Response {
		r := &http.Response{Header: http.Header{}}
		if v != "" {
			r.Header.Set("Retry-After", v)
		}
		return r
	}
	cases := map[string]time.Duration{
		"":        2 * time.Second,
		"5":       5 * time.Second,
		"-4":      0,
		"garbage": 2 * time.Second,
		now.Add(7 * time.Second).UTC().Format(http.TimeFormat): 7 * time.Second,
		now.Add(-time.Hour).UTC().Format(http.TimeFormat):      0,
	}
	for in, want := range cases {
		if got := c.retryAfter(mk(in)); got != want {
			t.Errorf("%q: %v want %v", in, got, want)
		}
	}
}

func TestServerErrorsRetryOnlyForReads(t *testing.T) {
	f := newFakeEero(t)
	c, sl := testClient(t, f, nil)
	// POST (login) is not retried on 503: it could send a second code.
	posts := 0
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost {
			posts++
			w.WriteHeader(503)
			return true
		}
		return false
	}
	if err := c.StartLogin(context.Background(), testEmail); err == nil || posts != 1 {
		t.Fatalf("%v posts=%d", err, posts)
	}
	f.override = nil
	login(t, c)
	gets := 0
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/2.2/account" {
			gets++
			if gets == 1 {
				w.WriteHeader(503)
				return true
			}
		}
		return false
	}
	if _, err := c.Networks(context.Background()); err != nil || gets != 2 {
		t.Fatalf("%v gets=%d", err, gets)
	}
	if len(sl.list()) != 1 {
		t.Fatalf("%v", sl.list())
	}
}

func TestContextCancelStopsRetries(t *testing.T) {
	f := newFakeEero(t)
	ctx, cancel := context.WithCancel(context.Background())
	c, _ := testClient(t, f, func(o *ClientOptions) {
		o.Sleep = func(ctx context.Context, d time.Duration) error { cancel(); return ctx.Err() }
	})
	login(t, c)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(429)
		return true
	}
	if _, err := c.Networks(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	// Cancelled before the request is made.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := c.StartLogin(ctx2, testEmail); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

func TestPoliteRequestSpacing(t *testing.T) {
	f := newFakeEero(t)
	sl := &sleeps{}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	c, _ := NewTestClient(f.srv.URL, ClientOptions{MinInterval: 200 * time.Millisecond, Sleep: sl.sleep, Now: func() time.Time { return now }})
	login(t, c)
	_, _ = c.Networks(context.Background())
	got := sl.list()
	if len(got) != 2 || got[0] != 200*time.Millisecond || got[1] != 400*time.Millisecond {
		t.Fatalf("spacing %v", got)
	}
}

func TestDefaultSleepHonoursContext(t *testing.T) {
	c, _ := NewClient(ClientOptions{})
	if err := c.sleep(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestResponseSizeCap(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, func(o *ClientOptions) { o.MaxResponseBytes = 200 })
	login(t, c)
	if _, err := c.Devices(context.Background(), "1001"); !errors.Is(err, ErrEeroTooLarge) {
		t.Fatalf("%v", err)
	}
}

func TestMalformedResponses(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	ctx := context.Background()
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		_, _ = io.WriteString(w, "<html>not json</html>")
		return true
	}
	if err := c.StartLogin(ctx, testEmail); !errors.Is(err, ErrEeroBadResponse) {
		t.Fatalf("%v", err)
	}
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		_, _ = io.WriteString(w, envelopeOf(`{}`))
		return true
	}
	if err := c.StartLogin(ctx, testEmail); !errors.Is(err, ErrEeroBadResponse) {
		t.Fatalf("no token: %v", err)
	}
	f.override = nil
	login(t, c)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		_, _ = io.WriteString(w, envelopeOf(`"a string"`))
		return true
	}
	if _, err := c.Networks(ctx); !errors.Is(err, ErrEeroBadResponse) {
		t.Fatalf("account: %v", err)
	}
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		_, _ = io.WriteString(w, "[1,2")
		return true
	}
	if _, err := c.Devices(ctx, "1001"); !errors.Is(err, ErrEeroBadResponse) {
		t.Fatalf("devices: %v", err)
	}
}

func TestTruncatedBodyReportsReadError(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "short")
		return true
	}
	if err := c.StartLogin(context.Background(), testEmail); err == nil || contains(err.Error(), testEmail) {
		t.Fatalf("%v", err)
	}
}

func TestSnapshotDegradesGracefully(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	login(t, c)
	ctx := context.Background()
	net := Network{ID: "1001", Name: "Home"}
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/profiles") || strings.HasSuffix(r.URL.Path, "/eeros") {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, errBody(500, "error.internal"))
			return true
		}
		return false
	}
	s, err := c.Snapshot(ctx, net)
	if err != nil || len(s.Devices) != 3 || len(s.Warnings) != 2 || !strings.Contains(s.Warnings[0], "no groups") || !strings.Contains(s.Warnings[1], "infrastructure") {
		t.Fatalf("%v %+v", err, s)
	}
	// Devices are required.
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(500)
		return true
	}
	if _, err := c.Snapshot(ctx, net); err == nil {
		t.Fatal("expected an error")
	}
	// A rate limit or expired session during profiles aborts rather than half-importing.
	for _, suffix := range []string{"/profiles", "/eeros"} {
		suffix := suffix
		f.override = func(w http.ResponseWriter, r *http.Request) bool {
			if strings.HasSuffix(r.URL.Path, suffix) {
				w.WriteHeader(401)
				_, _ = io.WriteString(w, errBody(401, "error.session.refresh"))
				return true
			}
			return false
		}
		if _, err := c.Snapshot(ctx, net); !errors.Is(err, ErrEeroSessionExpire) {
			t.Fatalf("%s: %v", suffix, err)
		}
	}
}

func TestNetworkIDIsEscaped(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	login(t, c)
	_, _ = c.Devices(context.Background(), "../../etc/pass wd")
	for _, r := range f.requests() {
		if strings.Contains(r.Path, "..") && !strings.HasPrefix(r.Path, "/2.2/networks/") {
			t.Fatalf("path traversal: %q", r.Path)
		}
	}
}
