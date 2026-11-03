// SPDX-License-Identifier: AGPL-3.0-or-later

package setup

import (
	"context"
	"sort"
	"time"
)

// Choosing upstream resolvers, by measuring rather than by asking.
//
// The owner cannot know from a list of names which resolver is fast from
// their house, which one is flaky on their uplink, or which one quietly
// fails every few queries. Shepherd can: it asks each candidate the same
// uncached question several times and reports what came back. So setup
// tests them all and recommends one, instead of putting six names on a page
// and hoping.
//
// What it prefers, in order:
//
//  1. Encrypted (DoT) with malware filtering upstream. Encryption keeps the
//     names this network looks up off the wire between here and the
//     resolver, and a resolver that drops known-malicious names catches
//     what a blocklist has not heard about yet. Shepherd's own lists still
//     do the work it is for.
//  2. Reliability. A resolver that lost any probe here is not recommended,
//     whatever its latency: a dropped query is a device that waits, and
//     then a device that falls back to another resolver entirely.
//  3. Latency, by the median of the probes that answered, which is every
//     lookup this network makes that is not already cached.
//
// A recommendation is never silently applied: the page shows the numbers it
// was made from, and the owner can pick any of them or type their own.

// Candidate is one resolver setup offers and measures.
type Candidate struct {
	// ID is stable, so the page can post back a choice.
	ID string `json:"id"`
	// Name is what it is called, Note what it does and does not do. The
	// notes say what the resolver blocks, because that is the part the
	// owner is choosing between -- not how fast it claims to be.
	Name string `json:"name"`
	Note string `json:"note"`
	// Addrs is what goes into dns.upstreams.
	Addrs []string `json:"addrs"`
	// Encrypted is DNS over TLS: the names are not in the clear between
	// this host and the resolver.
	Encrypted bool `json:"encrypted"`
	// Filters means the resolver blocks known-malicious names itself,
	// before Shepherd's lists ever see them.
	Filters bool `json:"filters"`
}

// Candidates are the resolvers setup measures. Encrypted, filtering ones
// come first so that is what a tie resolves to; the plain and unfiltered
// ones are kept because they are what some networks can actually use (a
// captive uplink that blocks 853, a household that wants no second filter).
//
// Only well-known public resolvers are listed, by their documented
// addresses and names.
var Candidates = []Candidate{
	{
		ID: "quad9-dot", Name: "Quad9 over TLS", Encrypted: true, Filters: true,
		Note:  "encrypted, and Quad9 blocks known-malicious names before Shepherd sees them",
		Addrs: []string{"tls://dns.quad9.net"},
	},
	{
		ID: "cloudflare-security-dot", Name: "Cloudflare Security over TLS", Encrypted: true, Filters: true,
		Note:  "encrypted, and Cloudflare blocks known-malicious names",
		Addrs: []string{"tls://security.cloudflare-dns.com"},
	},
	{
		ID: "cloudflare-dot", Name: "Cloudflare over TLS", Encrypted: true,
		Note:  "encrypted, no blocking of its own, so Shepherd's lists are the only filter",
		Addrs: []string{"tls://cloudflare-dns.com"},
	},
	{
		ID: "quad9", Name: "Quad9", Filters: true,
		Note:  "not encrypted; Quad9 blocks known-malicious names",
		Addrs: []string{"9.9.9.9", "149.112.112.112"},
	},
	{
		ID: "quad9-unfiltered", Name: "Quad9, no blocking", Note: "not encrypted; Shepherd's lists are the only filter",
		Addrs: []string{"9.9.9.10", "149.112.112.10"},
	},
	{
		ID: "cloudflare", Name: "Cloudflare", Note: "not encrypted, no blocking of its own",
		Addrs: []string{"1.1.1.1", "1.0.0.1"},
	},
	{
		ID: "google", Name: "Google", Note: "not encrypted, no blocking of its own",
		Addrs: []string{"8.8.8.8", "8.8.4.4"},
	},
}

// Measurement is what the probes found out about one candidate.
type Measurement struct {
	Candidate
	// OK is "every probe answered": the bar for a recommendation.
	OK bool `json:"ok"`
	// MedianMs is the median of the probes that answered, 0 when none
	// did. Lost is how many were lost, of Probes sent.
	MedianMs float64 `json:"median_ms"`
	Lost     int     `json:"lost"`
	Probes   int     `json:"probes"`
	Error    string  `json:"error,omitempty"`
	// Recommended marks the one the page ticks. Exactly one measurement
	// carries it, unless nothing answered at all.
	Recommended bool `json:"recommended"`
}

// probesPer is how many times each address is asked. Three is enough to
// tell a resolver that drops queries from one that does not, without
// turning the page into a minute of waiting.
const probesPer = 3

// slowMs is the latency past which an encrypted filtering resolver stops
// being worth preferring: above it, the owner would feel every uncached
// lookup, and a plain resolver that answers quickly is the better trade.
const slowMs = 250

// Measure probes every candidate and returns them in the order they should
// be offered: the recommendation first, then the rest by the same ranking.
// test is the per-address probe (cmd/shepherd passes the real one); a nil
// test measures nothing and returns the candidates unranked.
func Measure(ctx context.Context, cands []Candidate, test func(context.Context, string) error) []Measurement {
	out := make([]Measurement, 0, len(cands))
	for _, c := range cands {
		m := Measurement{Candidate: c}
		if test == nil {
			out = append(out, m)
			continue
		}
		var times []float64
		for _, addr := range c.Addrs {
			for i := 0; i < probesPer; i++ {
				if ctx.Err() != nil {
					break
				}
				start := time.Now()
				if err := test(ctx, addr); err != nil {
					m.Lost++
					if m.Error == "" {
						m.Error = err.Error()
					}
					continue
				}
				times = append(times, float64(time.Since(start).Microseconds())/1000)
			}
		}
		m.Probes = len(c.Addrs) * probesPer
		m.MedianMs = median(times)
		m.OK = m.Lost == 0 && len(times) > 0
		out = append(out, m)
	}
	rank(out)
	return out
}

// rank orders the measurements and marks the recommendation. The order is
// the argument this file's doc comment makes: reliability, then what the
// resolver protects against, then speed.
func rank(ms []Measurement) {
	sort.SliceStable(ms, func(i, j int) bool {
		a, b := ms[i], ms[j]
		if a.OK != b.OK {
			return a.OK // anything that lost a probe sinks
		}
		if ai, bi := preferred(a), preferred(b); ai != bi {
			return ai
		}
		if a.MedianMs != b.MedianMs {
			return a.MedianMs < b.MedianMs
		}
		return a.ID < b.ID
	})
	for i := range ms {
		if ms[i].OK {
			ms[i].Recommended = true
			return
		}
	}
}

// preferred reports whether a measurement is in the class setup leads with:
// encrypted, filtering, and quick enough that preferring it is not paid for
// on every uncached lookup.
func preferred(m Measurement) bool {
	return m.Encrypted && m.Filters && m.MedianMs > 0 && m.MedianMs <= slowMs
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}
