// SPDX-License-Identifier: AGPL-3.0-or-later

package reverseproxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ErrInvalid marks a rejected host definition, so the portal can answer 400
// for a typo and keep 500 for a disk that refused a save.
var ErrInvalid = errors.New("invalid proxy host")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Host is one public hostname and the backend it forwards to: the same
// shape as a proxy host in a typical reverse-proxy manager, so moving a
// service over is a matter of copying four fields.
type Host struct {
	ID string `json:"id"`
	// Domain is the public name clients ask for, e.g. "jellyfin.example.com".
	Domain string `json:"domain"`
	// TargetScheme is "http" or "https": some backends terminate TLS
	// themselves and only listen for HTTPS.
	TargetScheme string `json:"target_scheme"`
	TargetHost   string `json:"target_host"`
	TargetPort   int    `json:"target_port"`
	// SkipTLSVerify accepts any certificate from an https backend. Backends
	// on loopback or the LAN usually present a self-signed certificate (or
	// one that cannot match an IP address), and a typical reverse-proxy
	// manager never verified them at all; this makes that trade-off explicit
	// and per host instead of silent and global. Ignored for http.
	SkipTLSVerify bool `json:"skip_tls_verify"`
	Enabled       bool `json:"enabled"`
}

// Normalize validates h and returns it in canonical form (lowercase names,
// a default "http" scheme, brackets stripped from an IPv6 backend), so the
// Store only ever holds definitions that compare and route predictably.
func (h Host) Normalize() (Host, error) {
	d, err := NormalizeDomain(h.Domain)
	if err != nil {
		return Host{}, fmt.Errorf("domain: %w", err)
	}
	h.Domain = d

	h.TargetScheme = strings.ToLower(strings.TrimSpace(h.TargetScheme))
	if h.TargetScheme == "" {
		h.TargetScheme = "http"
	}
	if h.TargetScheme != "http" && h.TargetScheme != "https" {
		return Host{}, invalid(`target_scheme must be "http" or "https", got %q`, h.TargetScheme)
	}
	if h.TargetScheme == "http" {
		h.SkipTLSVerify = false
	}

	th, err := normalizeTargetHost(h.TargetHost)
	if err != nil {
		return Host{}, err
	}
	h.TargetHost = th

	if h.TargetPort < 1 || h.TargetPort > 65535 {
		return Host{}, invalid("target_port must be between 1 and 65535, got %d", h.TargetPort)
	}
	return h, nil
}

// Target is the backend URL a request for h is forwarded to.
func (h Host) Target() *url.URL {
	return &url.URL{Scheme: h.TargetScheme, Host: net.JoinHostPort(h.TargetHost, strconv.Itoa(h.TargetPort))}
}

// NormalizeDomain lowercases and validates a public hostname. It insists on
// a real multi-label DNS name because the wildcard certificate can only
// ever cover names like that; an IP address, a bare "localhost" or a
// wildcard pattern would be accepted here only to fail every handshake.
func NormalizeDomain(s string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if d == "" {
		return "", invalid("a domain is required")
	}
	if len(d) > 253 {
		return "", invalid("%q is longer than 253 characters", d)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", invalid("%q needs at least two labels, like app.example.com", d)
	}
	for _, l := range labels {
		if !validLabel(l) {
			return "", invalid("%q is not a valid DNS name", d)
		}
	}
	if net.ParseIP(d) != nil || isNumeric(labels[len(labels)-1]) {
		return "", invalid("%q is an address, not a name", d)
	}
	return d, nil
}

// Covers reports whether the wildcard certificate for "*.base" is valid for
// domain. A wildcard matches exactly one extra label, never the bare base
// and never anything deeper, which is the most common surprise when moving
// hosts onto one wildcard certificate.
func Covers(base, domain string) bool {
	if base == "" {
		return false
	}
	prefix, ok := strings.CutSuffix(domain, "."+base)
	return ok && prefix != "" && !strings.Contains(prefix, ".")
}

func normalizeTargetHost(s string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(s))
	if h == "" {
		return "", invalid("target_host is required")
	}
	if inner, ok := strings.CutPrefix(h, "["); ok {
		inner, ok = strings.CutSuffix(inner, "]")
		if !ok || net.ParseIP(inner) == nil {
			return "", invalid("target_host %q is not a valid address", s)
		}
		return inner, nil
	}
	if ip := net.ParseIP(h); ip != nil {
		return h, nil
	}
	// A single label is fine here, unlike for a public domain: backends
	// are often reached by a container or LAN name ("jellyfin", "nas").
	if len(h) > 253 {
		return "", invalid("target_host %q is too long", s)
	}
	for _, l := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if !validLabel(l) {
			return "", invalid("target_host %q must be a hostname or IP address, without a scheme, port or path", s)
		}
	}
	return h, nil
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, c := range l {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
