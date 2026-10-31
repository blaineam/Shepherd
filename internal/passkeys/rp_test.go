// SPDX-License-Identifier: AGPL-3.0-or-later

package passkeys

import (
	"crypto/tls"
	"errors"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestNewRelyingPartyFromTheTLSHostnameAndListenPort(t *testing.T) {
	rp, err := NewRelyingParty("Shepherd.Example.COM.", "0.0.0.0:8443")
	if err != nil {
		t.Fatal(err)
	}
	if rp.ID != "shepherd.example.com" {
		t.Errorf("ID = %q, want the hostname lowercased without its trailing dot", rp.ID)
	}
	if rp.Origin != "https://shepherd.example.com:8443" {
		t.Errorf("Origin = %q, want the listener's own https origin", rp.Origin)
	}
	// The standard-port origin is accepted too, for a port mapping such as a
	// container publishing 443 onto the listener's 8443: the browser then
	// reports no port at all.
	want := []string{"https://shepherd.example.com:8443", "https://shepherd.example.com"}
	if !slices.Equal(rp.Origins, want) {
		t.Errorf("Origins = %v, want %v", rp.Origins, want)
	}
}

func TestNewRelyingPartyOnPort443HasOneOrigin(t *testing.T) {
	for _, listen := range []string{":443", "192.0.2.10:443", ""} {
		rp, err := NewRelyingParty("shepherd.example.com", listen)
		if err != nil {
			t.Fatalf("%q: %v", listen, err)
		}
		if rp.Origin != "https://shepherd.example.com" || !slices.Equal(rp.Origins, []string{"https://shepherd.example.com"}) {
			t.Errorf("%q: origin %q, origins %v", listen, rp.Origin, rp.Origins)
		}
	}
}

func TestNewRelyingPartyRefusesWhatWebAuthnCannotUse(t *testing.T) {
	if _, err := NewRelyingParty("", ":8443"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no hostname: err = %v, want ErrNotConfigured", err)
	}
	if _, err := NewRelyingParty("   ", ":8443"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("blank hostname: err = %v, want ErrNotConfigured", err)
	}
	for _, h := range []string{"192.0.2.10", "2001:db8::1", "[2001:db8::1]", "shepherd.example.com:8443", "https://shepherd.example.com", "bad host.example.com", "a..example.com", "-a.example.com", "localhost", "shepherd"} {
		if _, err := NewRelyingParty(h, ":8443"); err == nil || errors.Is(err, ErrNotConfigured) {
			t.Errorf("%q: err = %v, want a specific refusal (WebAuthn needs a real DNS name)", h, err)
		}
	}
	if _, err := NewRelyingParty("shepherd.example.com", "nonsense"); err == nil {
		t.Error("an unparsable listen address must be refused, not guessed at")
	}
}

func TestServesOnlyHTTPSRequestsForTheRPHostname(t *testing.T) {
	rp, err := NewRelyingParty("shepherd.example.com", ":8443")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		host string
		tls  bool
		want bool
	}{
		{"the HTTPS listener at its own name", "shepherd.example.com:8443", true, true},
		{"the same name on the standard port", "Shepherd.Example.com", true, true},
		{"a trailing dot", "shepherd.example.com.:8443", true, true},
		{"plain HTTP at the right name", "shepherd.example.com:8443", false, false},
		{"the LAN IP over HTTP", "192.0.2.10:8787", false, false},
		{"the LAN IP over HTTPS", "192.0.2.10:8443", true, false},
		{"another name over HTTPS", "other.example.com", true, false},
		{"localhost", "localhost:8787", false, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = c.host
		if c.tls {
			r.TLS = &tls.ConnectionState{}
		} else {
			r.TLS = nil
		}
		if got := rp.Serves(r); got != c.want {
			t.Errorf("%s: Serves = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRequestOrigin(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "192.0.2.10:8787"
	r.TLS = nil
	if got := RequestOrigin(r); got != "http://192.0.2.10:8787" {
		t.Errorf("plain: %q", got)
	}
	r.TLS = &tls.ConnectionState{}
	r.Host = "shepherd.example.com:8443"
	if got := RequestOrigin(r); got != "https://shepherd.example.com:8443" {
		t.Errorf("tls: %q", got)
	}
}
