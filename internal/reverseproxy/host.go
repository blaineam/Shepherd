// SPDX-License-Identifier: AGPL-3.0-or-later

package reverseproxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	// Allow restricts who may reach this host: each entry is an IP, a
	// CIDR prefix, or the word "local", which stands for every network
	// this host has an address on plus Tailscale's own range. Empty means
	// anyone who reaches the listener, which is what a reverse-proxy
	// manager does by default too. A refused request gets a plain 403.
	Allow []string `json:"allow,omitempty"`
	// HSTS adds a Strict-Transport-Security header (30 days, this name
	// only, no preload) to every response served over HTTPS, so a browser
	// that has seen it once refuses plain http for the name afterwards.
	// Off by default: it is a promise the owner makes for a month.
	HSTS    bool `json:"hsts"`
	Enabled bool `json:"enabled"`
}

// AllowLocal is the Allow entry that stands for this host's own networks
// and Tailscale's range.
const AllowLocal = "local"

// HSTSMaxAge is the Strict-Transport-Security max-age Host.HSTS sends:
// long enough to matter, short enough that turning it off again is not a
// year-long regret.
const HSTSMaxAge = 30 * 24 * 60 * 60

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
	allow, err := normalizeAllow(h.Allow)
	if err != nil {
		return Host{}, err
	}
	h.Allow = allow
	return h, nil
}

// normalizeAllow canonicalises an allow list: "local" lowercased, a bare
// address as a single-address prefix, every prefix in its masked form, and
// duplicates dropped. nil for an empty list, so "open to anyone" has one
// spelling in the store.
func normalizeAllow(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range in {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" {
			continue
		}
		if e != AllowLocal {
			p, err := parseAllowPrefix(e)
			if err != nil {
				return nil, invalid("allow: %q is not an address, a prefix like 192.0.2.0/24, or %q", raw, AllowLocal)
			}
			e = p.String()
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out, nil
}

func parseAllowPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// Allowed reports whether client may reach h: true for an empty list,
// else when any entry covers the address. local supplies what "local"
// stands for.
func (h Host) Allowed(client netip.Addr, local func() []netip.Prefix) bool {
	if len(h.Allow) == 0 {
		return true
	}
	client = client.Unmap()
	for _, e := range h.Allow {
		if e == AllowLocal {
			if local == nil {
				continue
			}
			for _, p := range local() {
				if p.Contains(client) {
					return true
				}
			}
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil && p.Contains(client) {
			return true
		}
	}
	return false
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
