// SPDX-License-Identifier: AGPL-3.0-or-later

package reverseproxy

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	good := map[string]string{
		"jellyfin.example.com":   "jellyfin.example.com",
		"  Jellyfin.Example.COM": "jellyfin.example.com",
		"git.example.com.":       "git.example.com",
		"xn--bcher-kva.example":  "xn--bcher-kva.example",
		"a-b.c-d.example.net":    "a-b.c-d.example.net",
	}
	for in, want := range good {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "   ", "localhost", "example", "*.example.com", "exa mple.com", "example.com:443",
		"-bad.example.com", "bad-.example.com", "a..example.com", ".example.com",
		"192.0.2.10", "app.123", "under_score.example.com", "https://example.com", "example.com/path",
		strings.Repeat("a", 64) + ".example.com", strings.Repeat("abcdefghi.", 26) + "example.com",
	}
	for _, in := range bad {
		if got, err := NormalizeDomain(in); err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want an ErrInvalid", in, got, err)
		}
	}
}

func TestHostNormalize(t *testing.T) {
	cases := []struct {
		name string
		in   Host
		want Host
		err  string
	}{
		{
			name: "http backend on loopback",
			in:   Host{Domain: "Jellyfin.Example.com", TargetScheme: "HTTP", TargetHost: "127.0.0.1", TargetPort: 8096, Enabled: true},
			want: Host{Domain: "jellyfin.example.com", TargetScheme: "http", TargetHost: "127.0.0.1", TargetPort: 8096, Enabled: true},
		},
		{
			name: "empty scheme means http",
			in:   Host{Domain: "a.example.com", TargetHost: "192.0.2.10", TargetPort: 80},
			want: Host{Domain: "a.example.com", TargetScheme: "http", TargetHost: "192.0.2.10", TargetPort: 80},
		},
		{
			name: "https backend keeps skip-verify",
			in:   Host{Domain: "nas.example.com", TargetScheme: "https", TargetHost: "NAS.lan", TargetPort: 5001, SkipTLSVerify: true},
			want: Host{Domain: "nas.example.com", TargetScheme: "https", TargetHost: "nas.lan", TargetPort: 5001, SkipTLSVerify: true},
		},
		{
			name: "skip-verify means nothing for plain http",
			in:   Host{Domain: "a.example.com", TargetScheme: "http", TargetHost: "app", TargetPort: 3000, SkipTLSVerify: true},
			want: Host{Domain: "a.example.com", TargetScheme: "http", TargetHost: "app", TargetPort: 3000},
		},
		{
			name: "bracketed IPv6 backend",
			in:   Host{Domain: "v6.example.com", TargetScheme: "http", TargetHost: "[2001:db8::10]", TargetPort: 8080},
			want: Host{Domain: "v6.example.com", TargetScheme: "http", TargetHost: "2001:db8::10", TargetPort: 8080},
		},
		{name: "bad domain", in: Host{Domain: "nope", TargetHost: "app", TargetPort: 80}, err: "domain"},
		{name: "unknown scheme", in: Host{Domain: "a.example.com", TargetScheme: "ftp", TargetHost: "app", TargetPort: 21}, err: "target_scheme"},
		{name: "no target host", in: Host{Domain: "a.example.com", TargetPort: 80}, err: "target_host"},
		{name: "target host with a port", in: Host{Domain: "a.example.com", TargetHost: "app:80", TargetPort: 80}, err: "target_host"},
		{name: "target host with a scheme", in: Host{Domain: "a.example.com", TargetHost: "http://app", TargetPort: 80}, err: "target_host"},
		{name: "target host with a path", in: Host{Domain: "a.example.com", TargetHost: "app/x", TargetPort: 80}, err: "target_host"},
		{name: "unclosed IPv6 bracket", in: Host{Domain: "a.example.com", TargetHost: "[2001:db8::1", TargetPort: 80}, err: "target_host"},
		{name: "bracketed non-address", in: Host{Domain: "a.example.com", TargetHost: "[nas]", TargetPort: 80}, err: "target_host"},
		{name: "overlong target host", in: Host{Domain: "a.example.com", TargetHost: strings.Repeat("abcdefghi.", 26) + "lan", TargetPort: 80}, err: "target_host"},
		{name: "port zero", in: Host{Domain: "a.example.com", TargetHost: "app", TargetPort: 0}, err: "target_port"},
		{name: "port too large", in: Host{Domain: "a.example.com", TargetHost: "app", TargetPort: 65536}, err: "target_port"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.in.Normalize()
			if c.err != "" {
				if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("Normalize() err = %v, want an ErrInvalid mentioning %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize(): %v", err)
			}
			if got != c.want {
				t.Errorf("Normalize() = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestHostTarget(t *testing.T) {
	cases := map[string]Host{
		"http://127.0.0.1:8096":    {TargetScheme: "http", TargetHost: "127.0.0.1", TargetPort: 8096},
		"https://nas.lan:5001":     {TargetScheme: "https", TargetHost: "nas.lan", TargetPort: 5001},
		"http://[2001:db8::10]:80": {TargetScheme: "http", TargetHost: "2001:db8::10", TargetPort: 80},
	}
	for want, h := range cases {
		if got := h.Target().String(); got != want {
			t.Errorf("Target() = %q, want %q", got, want)
		}
	}
}

func TestCovers(t *testing.T) {
	cases := []struct {
		base, domain string
		want         bool
	}{
		{"example.com", "jellyfin.example.com", true},
		{"example.com", "a.b.example.com", false}, // a wildcard covers exactly one label
		{"example.com", "example.com", false},     // and never the apex itself
		{"example.com", "jellyfin.example.net", false},
		{"example.com", "badexample.com", false},
		{"", "jellyfin.example.com", false},
		{"home.example.com", "git.home.example.com", true},
	}
	for _, c := range cases {
		if got := Covers(c.base, c.domain); got != c.want {
			t.Errorf("Covers(%q, %q) = %v, want %v", c.base, c.domain, got, c.want)
		}
	}
}
