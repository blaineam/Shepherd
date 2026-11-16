// SPDX-License-Identifier: AGPL-3.0-or-later

package routerusage

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakeMSP stands in for a Firewalla MSP instance. Tests keep the real
// https address in the config and send the traffic to this server through
// a transport, so address validation is exercised exactly as shipped.
type fakeMSP struct {
	mu      sync.Mutex
	token   string
	body    string
	status  int
	gotAuth string
	gotPath string
	gotBox  string
	hits    int
}

func (f *fakeMSP) transport(t *testing.T) http.RoundTripper {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		f.gotAuth, f.gotPath, f.gotBox = r.Header.Get("Authorization"), r.URL.Path, r.URL.Query().Get("box")
		if f.gotAuth != "Token "+f.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		fmt.Fprint(w, f.body)
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const mspDevices = `[
 {"id":"02:00:5E:00:00:01","name":"Living room TV","online":true,"totalDownload":5000,"totalUpload":700},
 {"id":"02-00-5e-00-00-02","name":"Laptop","totalDownload":"123","totalUpload":"45"},
 {"id":"vpn_profile_7","name":"Phone VPN","totalDownload":1,"totalUpload":1},
 {"id":"02:00:5E:00:00:03","name":"No totals"}
]`

func newMSP(t *testing.T, f *fakeMSP, mutate func(*FirewallaConfig)) *Firewalla {
	t.Helper()
	cfg := FirewallaConfig{BaseURL: "home.firewalla.net", Token: f.token, Transport: f.transport(t)}
	if mutate != nil {
		mutate(&cfg)
	}
	src, err := NewFirewalla(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestFirewallaReadsByteTotalsPerDevice(t *testing.T) {
	f := &fakeMSP{token: "tok-1", body: mspDevices}
	src := newMSP(t, f, nil)
	if src.Name() != "firewalla" || src.Kind() != KindCounters || src.Kind().Estimated() {
		t.Fatalf("name %q kind %v", src.Name(), src.Kind())
	}
	got, err := src.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The VPN profile has no MAC and the last device has no totals.
	if len(got) != 2 {
		t.Fatalf("samples = %+v", got)
	}
	tv, laptop := got[0], got[1]
	if tv.MAC != "02005e000001" || tv.Name != "Living room TV" || tv.DownBytes != 5000 || tv.UpBytes != 700 {
		t.Fatalf("tv = %+v", tv)
	}
	// A total given as a string, and a MAC written with dashes, still read.
	if laptop.MAC != "02005e000002" || laptop.DownBytes != 123 || laptop.UpBytes != 45 {
		t.Fatalf("laptop = %+v", laptop)
	}
	if f.gotAuth != "Token tok-1" || f.gotPath != "/v2/devices" || f.gotBox != "" {
		t.Fatalf("request: auth %q path %q box %q", f.gotAuth, f.gotPath, f.gotBox)
	}
}

func TestFirewallaSharedDomainUsesTheAPIPrefixAndABoxFilter(t *testing.T) {
	f := &fakeMSP{token: "t", body: `[]`}
	// "/portal" is the page people sign in to, not the API.
	if _, err := NewFirewalla(FirewallaConfig{BaseURL: "https://firewalla.net/portal", Token: "t"}); !errors.Is(err, ErrFirewallaBadURL) {
		t.Fatalf("err = %v", err)
	}
	src := newMSP(t, f, func(c *FirewallaConfig) { c.BaseURL = "firewalla.net"; c.Box = "gid 1&x" })
	if _, err := src.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.gotPath != "/api/v2/devices" {
		t.Fatalf("path = %q, want the shared domain's /api prefix", f.gotPath)
	}
	if f.gotBox != "gid 1&x" {
		t.Fatalf("box = %q, want it sent as one escaped parameter", f.gotBox)
	}
}

func TestFirewallaMACListedByTwoBoxesIsTheSumOfBoth(t *testing.T) {
	f := &fakeMSP{token: "t", body: `[
	 {"id":"02:00:5E:00:00:01","gid":"a","totalDownload":10,"totalUpload":1},
	 {"id":"02:00:5E:00:00:01","gid":"b","totalDownload":5,"totalUpload":2}]`}
	got, err := newMSP(t, f, nil).Poll(context.Background())
	if err != nil || len(got) != 1 || got[0].DownBytes != 15 || got[0].UpBytes != 3 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestFirewallaAddressIsLimitedToFirewallaNet(t *testing.T) {
	good := map[string]string{
		"home.firewalla.net":          "https://home.firewalla.net",
		"https://Home.Firewalla.net/": "https://home.firewalla.net",
		"https://firewalla.net/api":   "https://firewalla.net/api",
		"https://firewalla.net/api/":  "https://firewalla.net/api",
		"  my-msp.firewalla.net  ":    "https://my-msp.firewalla.net",
		"a.b.firewalla.net":           "https://a.b.firewalla.net",
	}
	for in, want := range good {
		if got, err := NormalizeFirewallaURL(in); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "   ",
		"http://home.firewalla.net",      // the token must not travel in clear
		"https://evil.example.com",       // someone else's server
		"https://firewalla.net.evil.com", // suffix trick
		"https://evilfirewalla.net",      // not a subdomain
		"https://home.firewalla.net%40evil.example.com",
		"https://user:pw@home.firewalla.net", // leakcheck:allow
		"https://home.firewalla.net:8443",
		"https://home.firewalla.net/v2",
		"https://home.firewalla.net/?x=1",
		"https://.firewalla.net",
		"ftp://home.firewalla.net",
		"https://firewalla.net/other",
		"https://home_x.firewalla.net",
	} {
		if got, err := NormalizeFirewallaURL(in); !errors.Is(err, ErrFirewallaBadURL) {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
	if _, err := NewFirewalla(FirewallaConfig{BaseURL: "home.firewalla.net"}); !errors.Is(err, ErrFirewallaNoToken) {
		t.Fatalf("no token: %v", err)
	}
	if _, err := NewFirewalla(FirewallaConfig{BaseURL: "home.firewalla.net", Token: "  "}); !errors.Is(err, ErrFirewallaNoToken) {
		t.Fatalf("blank token: %v", err)
	}
}

func TestFirewallaRefusalsAreNamed(t *testing.T) {
	f := &fakeMSP{token: "good", body: `[]`}
	src := newMSP(t, f, func(c *FirewallaConfig) { c.Token = "bad" })
	_, err := src.Poll(context.Background())
	if !errors.Is(err, ErrFirewallaAuth) || !FirewallaNeedsSignIn(err) {
		t.Fatalf("wrong token: %v", err)
	}

	for status, want := range map[int]error{
		http.StatusTooManyRequests:     ErrFirewallaRateLimited,
		http.StatusInternalServerError: ErrFirewallaRefused,
		http.StatusNotFound:            ErrFirewallaRefused,
	} {
		f := &fakeMSP{token: "t", status: status}
		_, err := newMSP(t, f, nil).Poll(context.Background())
		if !errors.Is(err, want) {
			t.Errorf("HTTP %d: %v, want %v", status, err, want)
		}
		if FirewallaNeedsSignIn(err) {
			t.Errorf("HTTP %d must not ask for a new token", status)
		}
	}

	_, err = newMSP(t, &fakeMSP{token: "t", body: `{"error":"x"}`}, nil).Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not a device list") {
		t.Fatalf("an object instead of a list: %v", err)
	}
}

func TestFirewallaNeverFollowsARedirectOrLeaksTheTokenInAnError(t *testing.T) {
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_ = r
	}))
	t.Cleanup(other.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	src, err := NewFirewalla(FirewallaConfig{
		BaseURL: "home.firewalla.net", Token: "secret-token-value",
		// Only the MSP address is diverted; anything else goes where it
		// says, so a followed redirect would really reach the other server.
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Hostname() == "home.firewalla.net" {
				r = r.Clone(r.Context())
				r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
			}
			return http.DefaultTransport.RoundTrip(r)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = src.Poll(context.Background())
	if err == nil {
		t.Fatal("a redirect was followed")
	}
	if hits != 0 {
		t.Fatalf("the redirect target was contacted %d times", hits)
	}
	if strings.Contains(err.Error(), "secret-token-value") {
		t.Fatalf("the token is in the error: %v", err)
	}
}

func TestFirewallaCancelledContextEndsThePoll(t *testing.T) {
	f := &fakeMSP{token: "t", body: `[]`}
	src := newMSP(t, f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Poll(ctx); err == nil {
		t.Fatal("a cancelled context must fail")
	}
}
