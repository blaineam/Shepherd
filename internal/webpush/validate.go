// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrEndpoint reports a subscription endpoint that must not be called.
var ErrEndpoint = errors.New("webpush: endpoint rejected")

// cgnat is the carrier-grade NAT range, which Tailscale uses for node
// addresses. netip.Addr.IsPrivate does not cover it.
var cgnat = netip.MustParsePrefix("100.64.0.0/10") // leakcheck:allow the CGNAT block itself, not a host

// BlockedAddr reports whether a is an address a push message must never be
// sent to: loopback, private (RFC 1918 and ULA), CGNAT, link-local,
// multicast, unspecified, or an IPv4-mapped form of any of those.
func BlockedAddr(a netip.Addr) bool {
	a = a.Unmap()
	return !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsMulticast() || a.IsUnspecified() || cgnat.Contains(a)
}

// ValidateEndpoint is the default subscription-endpoint check. A subscription
// is posted by a browser, so the endpoint is attacker-influenced input and a
// malicious one must not make the server call an internal address. It must be
// https, carry no credentials, use port 443 (or none), and its host must not
// be localhost, a bare name, a .local/.internal/.lan name or a private,
// loopback or link-local IP literal. Hostnames that resolve to internal
// addresses are caught again at dial time by NewHTTPClient.
func ValidateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 2048 {
		return fmt.Errorf("%w: not a URL", ErrEndpoint)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: must be https", ErrEndpoint)
	}
	if u.User != nil {
		return fmt.Errorf("%w: credentials in URL", ErrEndpoint)
	}
	if p := u.Port(); p != "" && p != "443" {
		return fmt.Errorf("%w: port %s", ErrEndpoint, p)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return fmt.Errorf("%w: no host", ErrEndpoint)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if BlockedAddr(a) {
			return fmt.Errorf("%w: private or loopback address", ErrEndpoint)
		}
		return nil
	}
	if !strings.Contains(host, ".") || host == "localhost" {
		return fmt.Errorf("%w: not a public host name", ErrEndpoint)
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa", ".corp", ".intranet"} {
		if strings.HasSuffix(host, suffix) {
			return fmt.Errorf("%w: not a public host name", ErrEndpoint)
		}
	}
	return nil
}

// AllowAnyEndpoint accepts every endpoint. It exists as the injectable test
// override (httptest servers listen on loopback); never use it in production.
func AllowAnyEndpoint(string) error { return nil }

// guardControl is a net.Dialer Control hook that refuses to connect to a
// blocked address, whatever name it was resolved from.
func guardControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEndpoint, err)
	}
	a, err := netip.ParseAddr(host)
	if err != nil || BlockedAddr(a) {
		return fmt.Errorf("%w: resolves to a private or loopback address", ErrEndpoint)
	}
	return nil
}

// NewHTTPClient returns the client the Sender uses by default: a 15 second
// timeout, no redirects (a push service answers directly), and a dialer that
// refuses private, loopback and link-local addresses after DNS resolution.
func NewHTTPClient() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: guardControl}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           func(ctx context.Context, n, a string) (net.Conn, error) { return d.DialContext(ctx, n, a) },
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
