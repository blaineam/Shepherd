// SPDX-License-Identifier: AGPL-3.0-or-later

package routerusage

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"shepherd/internal/backends"
)

// Firewalla MSP's own per-device figures are a rolling 24 hours, which
// cannot be differenced into traffic. Bandwidth from a Firewalla therefore
// comes from the flows the dashboard hub ingests (internal/backends/hub),
// added up into running counters, and reaches the Collector through a Feed.
// This file holds what both halves share: the address rules.

// Errors about a Firewalla connection. Use errors.Is.
var (
	ErrFirewallaBadURL  = errors.New("firewalla: the MSP address must be your own domain on firewalla.net, such as mydomain.firewalla.net")
	ErrFirewallaNoToken = errors.New("firewalla: a personal access token is required")
)

// NormalizeFirewallaURL turns what an owner types into the https origin
// requests are sent to, or ErrFirewallaBadURL. The shared domain gets its
// /api prefix; a domain of the owner's own gets none.
func NormalizeFirewallaURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrFirewallaBadURL
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" ||
		u.RawQuery != "" || u.Fragment != "" {
		return "", ErrFirewallaBadURL
	}
	host := strings.ToLower(u.Hostname())
	path := strings.TrimRight(u.Path, "/")
	switch {
	case host == "firewalla.net":
		if path != "" && path != "/api" {
			return "", ErrFirewallaBadURL
		}
		return "https://firewalla.net/api", nil
	case strings.HasSuffix(host, ".firewalla.net") && len(host) > len(".firewalla.net"):
		// Labels are letters, digits and hyphens: nothing that could
		// smuggle another host past the suffix check.
		for _, r := range strings.TrimSuffix(host, ".firewalla.net") {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
				return "", ErrFirewallaBadURL
			}
		}
		if path != "" {
			return "", ErrFirewallaBadURL
		}
		return "https://" + host, nil
	}
	return "", ErrFirewallaBadURL
}

// FirewallaNeedsSignIn reports whether err means the stored token no
// longer works, so the portal asks for a new one instead of showing a
// transient failure.
func FirewallaNeedsSignIn(err error) bool { return errors.Is(err, backends.ErrAuth) }

// Feed is a Source over counters something else keeps, such as the hub's
// running per-device totals. It does no I/O of its own.
type Feed struct {
	name string
	read func() []Sample
}

// NewFeed returns a KindCounters Source named name that reads its samples
// from read on every Poll.
func NewFeed(name string, read func() []Sample) *Feed { return &Feed{name: name, read: read} }

// Name implements Source.
func (f *Feed) Name() string { return f.name }

// Kind implements Source: the counters only grow.
func (f *Feed) Kind() Kind { return KindCounters }

// Poll implements Source.
func (f *Feed) Poll(ctx context.Context) ([]Sample, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.read(), nil
}
