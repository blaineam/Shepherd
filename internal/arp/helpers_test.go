// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"shepherd/internal/devices"
)

var t0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// mac builds a documentation-range address. Stable (globally administered)
// ones use RFC 7042's 00:00:5e range, randomized ones 02:00:5e.
func stable(n byte) MAC { return MAC{0x00, 0x00, 0x5e, 0x00, 0x53, n} }
func rnd(n byte) MAC    { return MAC{0x02, 0x00, 0x5e, 0x00, 0x00, n} }
func ip(n byte) netip.Addr {
	return netip.AddrFrom4([4]byte{192, 0, 2, n})
}
func at(d time.Duration) time.Time { return t0.Add(d) }

func timed(f Frame, d time.Duration) Frame { f.Time = at(d); return f }

type recSink struct {
	mu  sync.Mutex
	obs []devices.Observation
}

func (r *recSink) Observe(o devices.Observation) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.obs = append(r.obs, o)
	return ""
}

func (r *recSink) list() []devices.Observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]devices.Observation(nil), r.obs...)
}

type harness struct {
	t    *testing.T
	m    *Monitor
	sink *recSink
	evs  []Event
}

func newHarness(t *testing.T, mod func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, sink: &recSink{}}
	cfg := DefaultConfig()
	cfg.Sink = h.sink
	cfg.OnEvent = func(e Event) { h.evs = append(h.evs, e) }
	if mod != nil {
		mod(&cfg)
	}
	h.m = NewMonitor(NewFakeSource(), cfg)
	return h
}

func (h *harness) send(f Frame, d time.Duration) { h.m.Handle(timed(f, d)) }

func (h *harness) count(t EventType) int {
	n := 0
	for _, e := range h.evs {
		if e.Type == t {
			n++
		}
	}
	return n
}

func (h *harness) find(t EventType) *Event {
	for i := range h.evs {
		if h.evs[i].Type == t {
			return &h.evs[i]
		}
	}
	return nil
}
