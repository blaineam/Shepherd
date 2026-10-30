// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

import "strings"

// PublicAnycastTargets are well-known, highly-available public DNS
// resolvers added to every probe cycle alongside the configured upstreams,
// so a reading still means something even on a network with just one
// upstream configured, and so a total outage of the configured upstreams
// alone is distinguishable from an outage of the network's path to the
// internet generally.
var PublicAnycastTargets = []string{"1.1.1.1", "8.8.8.8"}

// hostFromUpstream extracts the bare host from one of
// internal/config.DNS.Upstreams's accepted forms: a plain IP ("9.9.9.10"),
// a scheme-prefixed address ("tcp://1.1.1.1", "udp://1.1.1.1"), or a DoT/DoH
// host, optionally with its own port ("tls://dns.quad9.net:853"). The
// upstream's own port is deliberately discarded: this package always times
// a plain TCP connect to port 53 (see doc.go), not whatever port the
// upstream serves DoT or DoH on.
func hostFromUpstream(spec string) string {
	s := strings.TrimSpace(spec)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// https:// and tls:// forms may carry a path (DoH) or a port; take the
	// authority up to the first '/'.
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return ""
	}
	// IPv6 in brackets: "[::1]:853" or "[::1]".
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end >= 0 {
			return s[1:end]
		}
		return s
	}
	// host:port — but a bare IPv6 address (no brackets) has multiple colons
	// and no port to strip.
	if strings.Count(s, ":") == 1 {
		if i := strings.LastIndex(s, ":"); i >= 0 {
			return s[:i]
		}
	}
	return s
}

// DefaultTargets builds the probe target list from the configured DNS
// upstreams plus the built-in public anycast targets, deduplicated and in a
// stable order (upstreams first, in their configured order, then any public
// target not already covered). Empty or unparseable upstream entries are
// skipped rather than probed as empty strings.
func DefaultTargets(upstreams []string) []string {
	seen := make(map[string]bool, len(upstreams)+len(PublicAnycastTargets))
	out := make([]string, 0, len(upstreams)+len(PublicAnycastTargets))
	add := func(host string) {
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		out = append(out, host)
	}
	for _, u := range upstreams {
		add(hostFromUpstream(u))
	}
	for _, p := range PublicAnycastTargets {
		add(p)
	}
	return out
}
