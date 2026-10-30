// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import (
	"net/netip"
	"time"

	"shepherd/internal/devices"
)

// Config tunes the Monitor. Zero values take the defaults from
// DefaultConfig. docs/ARP.md documents every threshold.
type Config struct {
	// Sink receives device observations (source "arp"). May be nil.
	Sink devices.Sink
	// OnEvent receives ARP-layer events. May be nil. It is called from the
	// Monitor's goroutine and should return quickly.
	OnEvent func(Event)
	// OnError receives non-fatal problems (undecodable frames are counted,
	// not reported; this is for gateway lookup failures). May be nil.
	OnError func(error)

	// Gateway is the default gateway's IPv4 address. When invalid, GatewayFunc
	// is consulted instead (on Linux, DefaultGatewayFunc(os.ReadFile)).
	Gateway     netip.Addr
	GatewayFunc func() (netip.Addr, error)
	// GatewayMAC optionally pins the gateway's known-good MAC. Without it
	// the first MAC seen claiming the gateway IP is the baseline.
	GatewayMAC MAC
	// TrustedMACs are exempt from mac-claims-many-ips (routers doing proxy
	// ARP, a host running virtual machines).
	TrustedMACs []MAC

	Now func() time.Time

	// MaxTracked caps every table (MACs, IPs, pairs, recent requests,
	// cooldowns). Default 16384.
	MaxTracked int
	// ObserveInterval is the minimum gap between observations of one
	// (MAC, IP) pair. Default 5m.
	ObserveInterval time.Duration
	// LearnPeriod after the first frame during which events are flagged
	// Baseline. Default 2m.
	LearnPeriod time.Duration
	// EventCooldown suppresses repeats of one event Key. Default 1h.
	EventCooldown time.Duration

	// QuietPeriod: an old MAC unseen this long is "gone" when its IP changes
	// hands. Default 10m.
	QuietPeriod time.Duration
	// ManyIPsThreshold distinct IPs claimed by one MAC within ManyIPsWindow.
	// Defaults 8 and 10m.
	ManyIPsThreshold int
	ManyIPsWindow    time.Duration
	// DuplicateFlips owner changes of one IP within DuplicateWindow.
	// Defaults 3 and 2m. OwnerLive is how recently an owner must have
	// spoken for a probe of its IP to count as a conflict. Default 5m.
	DuplicateFlips  int
	DuplicateWindow time.Duration
	OwnerLive       time.Duration
	// GratuitousLimit gratuitous frames from one MAC per RateWindow.
	// Defaults 20 and 1m.
	GratuitousLimit int
	RateWindow      time.Duration
	// UnsolicitedLimit replies per RateWindow from one MAC that answer no
	// request seen within RequestWindow. Defaults 10 and 30s.
	UnsolicitedLimit int
	RequestWindow    time.Duration
	// SpoofMinSignals distinct signal types for one suspect MAC within
	// SpoofWindow raise arp-spoofing-suspected. Defaults 3 and 10m. A
	// gateway-mac-changed plus any one other signal also qualifies.
	SpoofMinSignals int
	SpoofWindow     time.Duration
	// GatewayRefresh is how often GatewayFunc is re-read. Default 5m.
	GatewayRefresh time.Duration
}

// DefaultConfig returns the defaults, tuned for few false positives on a home network.
func DefaultConfig() Config {
	return Config{
		Now:              time.Now,
		MaxTracked:       16384,
		ObserveInterval:  5 * time.Minute,
		LearnPeriod:      2 * time.Minute,
		EventCooldown:    time.Hour,
		QuietPeriod:      10 * time.Minute,
		ManyIPsThreshold: 8,
		ManyIPsWindow:    10 * time.Minute,
		DuplicateFlips:   3,
		DuplicateWindow:  2 * time.Minute,
		OwnerLive:        5 * time.Minute,
		GratuitousLimit:  20,
		RateWindow:       time.Minute,
		UnsolicitedLimit: 10,
		RequestWindow:    30 * time.Second,
		SpoofMinSignals:  3,
		SpoofWindow:      10 * time.Minute,
		GatewayRefresh:   5 * time.Minute,
	}
}

// withDefaults fills unset (zero or negative) numeric fields.
func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.Now == nil {
		c.Now = d.Now
	}
	fi := func(v *int, def int) {
		if *v <= 0 {
			*v = def
		}
	}
	fd := func(v *time.Duration, def time.Duration) {
		if *v <= 0 {
			*v = def
		}
	}
	fi(&c.MaxTracked, d.MaxTracked)
	fd(&c.ObserveInterval, d.ObserveInterval)
	fd(&c.LearnPeriod, d.LearnPeriod)
	fd(&c.EventCooldown, d.EventCooldown)
	fd(&c.QuietPeriod, d.QuietPeriod)
	fi(&c.ManyIPsThreshold, d.ManyIPsThreshold)
	fd(&c.ManyIPsWindow, d.ManyIPsWindow)
	fi(&c.DuplicateFlips, d.DuplicateFlips)
	fd(&c.DuplicateWindow, d.DuplicateWindow)
	fd(&c.OwnerLive, d.OwnerLive)
	fi(&c.GratuitousLimit, d.GratuitousLimit)
	fd(&c.RateWindow, d.RateWindow)
	fi(&c.UnsolicitedLimit, d.UnsolicitedLimit)
	fd(&c.RequestWindow, d.RequestWindow)
	fi(&c.SpoofMinSignals, d.SpoofMinSignals)
	fd(&c.SpoofWindow, d.SpoofWindow)
	fd(&c.GatewayRefresh, d.GatewayRefresh)
	return c
}
