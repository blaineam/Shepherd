// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestValidateEndpoint(t *testing.T) {
	ok := []string{
		"https://push.example.com/send/abc",
		"https://push.example.com:443/send/abc",
		"https://updates.push.example.net/wpush/v2/xyz",
		"https://push.example.org./x",
		"https://203.0.113.9/x", // documentation range is not private
		"https://[2001:db8::1]/x",
	}
	for _, e := range ok {
		if err := ValidateEndpoint(e); err != nil {
			t.Errorf("%s: %v", e, err)
		}
	}
	bad := []string{
		"", "nonsense", "http://push.example.com/x", "ftp://push.example.com/x",
		"https://user:pw" + "@push.example.com/x",
		"https://push.example.com:8443/x",
		"https:///nohost",
		"https://localhost/x", "https://sub.localhost/x", "https://intranet/x",
		"https://printer.local/x", "https://nas.internal/x", "https://box.lan/x", "https://router.home.arpa/x",
		"https://127.0.0.1/x", "https://[::1]/x", "https://10.1.2.3/x", "https://172.16.0.9/x",
		"https://192.168.1.1/x", "https://169.254.169.254/x", "https://100.64.1.1/x", "https://0.0.0.0/x",
		"https://[fe80::1]/x", "https://[fd00::1]/x", "https://[::ffff:10.0.0.1]/x", "https://224.0.0.1/x", // leakcheck:allow RFC range literals under test
		"https://" + string(make([]byte, 0)) + "push.example.com/" + longString(3000),
		"https://push.example.com/%zz",
		"https://[::1/x",
	}
	for _, e := range bad {
		err := ValidateEndpoint(e)
		if err == nil {
			t.Errorf("%q accepted", e)
		} else if !errors.Is(err, ErrEndpoint) {
			t.Errorf("%q: error %v is not ErrEndpoint", e, err)
		}
	}
	if err := AllowAnyEndpoint("http://127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func TestBlockedAddr(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "::1", "10.0.0.1", "192.168.0.1", "100.100.1.1", "169.254.1.1", "fe80::1", "fc00::1", "0.0.0.0", "::", "224.0.0.251", "ff02::fb", "::ffff:127.0.0.1"} { // leakcheck:allow RFC range literals under test
		if !BlockedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s not blocked", s)
		}
	}
	for _, s := range []string{"198.51.100.1", "203.0.113.1", "2001:db8::1", "8.8.8.8"} {
		if BlockedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s blocked", s)
		}
	}
	if !BlockedAddr(netip.Addr{}) {
		t.Error("invalid addr must be blocked")
	}
}

func TestHTTPClientRefusesInternalAddressesAtDialTime(t *testing.T) {
	// A server on loopback stands in for "a public hostname that resolves to
	// an internal address": the dial guard must refuse the connection.
	hit := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	c := NewHTTPClient()
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("dial to loopback succeeded")
	} else if !errors.Is(err, ErrEndpoint) {
		t.Fatalf("err = %v", err)
	}
	if hit {
		t.Fatal("request reached the internal server")
	}
	if err := guardControl("tcp", "no-port", nil); !errors.Is(err, ErrEndpoint) {
		t.Fatalf("bad address: %v", err)
	}
	if err := guardControl("tcp", "localhost:443", nil); !errors.Is(err, ErrEndpoint) {
		t.Fatalf("unparsed host: %v", err)
	}
	if err := guardControl("tcp", "203.0.113.5:443", nil); err != nil {
		t.Fatalf("public address blocked: %v", err)
	}
}

func TestHTTPClientDoesNotFollowRedirects(t *testing.T) {
	c := NewHTTPClient()
	req, _ := http.NewRequest("GET", "https://push.example.com/", nil)
	if err := c.CheckRedirect(req, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v", err)
	}
}
