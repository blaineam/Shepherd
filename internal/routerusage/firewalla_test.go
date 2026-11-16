// SPDX-License-Identifier: AGPL-3.0-or-later

package routerusage

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"shepherd/internal/backends"
)

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
}

func TestAnAuthFailureFromTheBackendAsksForANewToken(t *testing.T) {
	if !FirewallaNeedsSignIn(fmt.Errorf("wrapped: %w", backends.ErrAuth)) {
		t.Fatal("a refused token must ask for a new one")
	}
	for _, err := range []error{backends.ErrRateLimited, backends.ErrRefused, errors.New("timeout")} {
		if FirewallaNeedsSignIn(err) {
			t.Fatalf("%v must not ask for a new token", err)
		}
	}
}

func TestAFeedReportsWhateverCountersItIsGiven(t *testing.T) {
	counters := []Sample{{MAC: "02005e000001", DownBytes: 10, UpBytes: 1}}
	f := NewFeed("firewalla", func() []Sample { return counters })
	if f.Name() != "firewalla" || f.Kind() != KindCounters || f.Kind().Estimated() {
		t.Fatalf("%q %v", f.Name(), f.Kind())
	}
	got, err := f.Poll(context.Background())
	if err != nil || len(got) != 1 || got[0].DownBytes != 10 {
		t.Fatalf("%+v, %v", got, err)
	}
	counters = nil
	if got, _ := f.Poll(context.Background()); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Poll(ctx); err == nil {
		t.Fatal("a cancelled context must fail")
	}
}
