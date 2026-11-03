// SPDX-License-Identifier: AGPL-3.0-or-later

package routerusage

import (
	"context"
	"strings"
	"time"
)

// Kind is the shape of the numbers a Source reports. See the package doc.
type Kind int

const (
	// KindRates: an instantaneous rate per device, in bits per second.
	// Integrating it is an estimate.
	KindRates Kind = iota
	// KindCounters: bytes transferred since the router last booted.
	// Differencing it is exact apart from resets.
	KindCounters
)

// String names the kind for the portal and the logs.
func (k Kind) String() string {
	if k == KindCounters {
		return "counters"
	}
	return "rates"
}

// Estimated reports whether numbers of this kind are an approximation. It
// is what the portal reads to label the figures honestly.
func (k Kind) Estimated() bool { return k == KindRates }

// Sample is one device as the router currently sees it. MAC identifies it;
// everything else is advisory. Only the fields matching the Source's Kind
// are read.
type Sample struct {
	MAC  string
	Name string // the router's name for it, for a device Shepherd has never seen

	// KindRates, in bits per second as the router reports them.
	DownBitsPerSecond, UpBitsPerSecond float64

	// KindCounters, in bytes since the router booted.
	DownBytes, UpBytes uint64
}

// Source is one router's per-device bandwidth, read without touching the
// owner's traffic. Poll returns every device the router currently knows
// about; a device missing from a poll is treated as idle, not as gone.
//
// Implementations must be safe for concurrent use and must return promptly
// when ctx ends.
type Source interface {
	// Name is the router this reads, lowercase and stable ("eero"). It
	// appears in the portal and in log lines.
	Name() string
	// Kind says which fields of Sample are filled in.
	Kind() Kind
	// Poll reads the router once.
	Poll(ctx context.Context) ([]Sample, error)
}

// NormalizeMAC lowercases a MAC and strips the separators routers disagree
// about, so "02:00:5E:11:22:33", "02-00-5e-11-22-33" and "02005e112233" all
// match the same device. It returns "" for anything that is not twelve hex
// digits, which is what a Source should treat as "no MAC".
func NormalizeMAC(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		case r == ':' || r == '-' || r == '.' || r == ' ':
		default:
			return ""
		}
	}
	out := b.String()
	if len(out) != 12 {
		return ""
	}
	return out
}

// Status is what the portal shows about a collector: whether it is on,
// whether the last poll worked, and how much it saw.
type Status struct {
	// Source is the router's name, "" when none is configured.
	Source string `json:"source"`
	// Enabled is the owner's switch.
	Enabled bool `json:"enabled"`
	// Estimated is true when the numbers are integrated rates rather than
	// counters, so the portal can say so.
	Estimated bool `json:"estimated"`
	// Interval between polls.
	IntervalSeconds int `json:"interval_seconds"`
	// LastPoll is when a poll last succeeded, nil until one has. It is a
	// pointer because encoding/json's omitempty does not omit a zero
	// time.Time, and a zero timestamp in the JSON reads to the portal as
	// "it has polled", which is the opposite of the truth.
	LastPoll *time.Time `json:"last_poll,omitempty"`
	// DevicesSeen is how many devices the last successful poll returned,
	// and Matched how many of those are known to the device registry.
	DevicesSeen int `json:"devices_seen"`
	Matched     int `json:"matched"`
	// LastError is the last failure, already scrubbed of credentials by
	// the Source. Empty when the last poll succeeded.
	LastError string `json:"last_error,omitempty"`
	// NeedsSignIn is true when the failure was the session expiring, so
	// the portal can offer to sign in again rather than show a raw error.
	NeedsSignIn bool `json:"needs_sign_in"`
}
