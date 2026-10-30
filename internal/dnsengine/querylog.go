// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Dest is a geolocated address a query resolved to.
type Dest struct {
	IP      string  `json:"ip"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	City    string  `json:"city,omitempty"`
	Country string  `json:"country,omitempty"` // ISO 3166-1 alpha-2
}

// Geo places an address on the globe. It returns false when it cannot.
type Geo interface {
	Locate(ip net.IP) (Dest, bool)
}

// Entry is one answered query.
type Entry struct {
	ID     uint64    `json:"id"`
	Time   time.Time `json:"time"`
	Client string    `json:"client"`
	// Device and DeviceID name the device behind Client when the registry
	// knows it. They are filled when the query is recorded, so history keeps
	// the name the device had then.
	Device   string  `json:"device,omitempty"`
	DeviceID string  `json:"device_id,omitempty"`
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Action   string  `json:"action"` // allowed, cached, blocked or error
	Reason   string  `json:"reason,omitempty"`
	Upstream string  `json:"upstream,omitempty"`
	Ms       float64 `json:"ms"`
	Rcode    string  `json:"rcode"`
	// Dests are the geolocated addresses the answer pointed at: for an
	// allowed or cached query, or for one blocked by country (Reason "geo"),
	// where it carries the destination the block was for.
	Dests []Dest `json:"dests,omitempty"`
	// GeoCountry is set on a query blocked by country (Reason "geo"): the
	// ISO 3166-1 alpha-2 code of the resolved address that matched. See
	// Engine.CountryBlock and docs/GEOBLOCK.md.
	GeoCountry string `json:"geo_country,omitempty"`
	// Wandering marks a query from a device in wandering mode (never filtered).
	// Shadow names what would have blocked it, when something would have.
	Wandering bool   `json:"wandering,omitempty"`
	Shadow    string `json:"shadow,omitempty"`
}

// QueryLog is a fixed-size in-memory ring. It never writes to disk itself; a
// sink (the encrypted history) can be attached to persist entries.
type QueryLog struct {
	mu   sync.Mutex
	buf  []Entry
	next uint64
	subs map[chan Entry]struct{}
	sink func(Entry)
}

func NewQueryLog(size int) *QueryLog {
	if size < 1 {
		size = 1000
	}
	return &QueryLog{buf: make([]Entry, size), next: 1, subs: map[chan Entry]struct{}{}}
}

// SetSink attaches f, called synchronously with every new entry (after it has
// its ID). f must be fast and must not call back into the log.
func (l *QueryLog) SetSink(f func(Entry)) {
	l.mu.Lock()
	l.sink = f
	l.mu.Unlock()
}

// Subscribe returns a channel of new entries and a cancel function. A slow
// subscriber drops entries instead of blocking DNS. The channel is never
// closed; stop reading after cancel.
func (l *QueryLog) Subscribe(buffer int) (<-chan Entry, func()) {
	if buffer < 1 {
		buffer = 1
	}
	ch := make(chan Entry, buffer)
	l.mu.Lock()
	l.subs[ch] = struct{}{}
	l.mu.Unlock()
	return ch, func() {
		l.mu.Lock()
		delete(l.subs, ch)
		l.mu.Unlock()
	}
}

// Preload fills the ring with past entries (oldest first), for example from the
// encrypted history after a restart. It does not notify subscribers or the sink.
func (l *QueryLog) Preload(es []Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range es {
		e.ID = l.next
		l.buf[(l.next-1)%uint64(len(l.buf))] = e
		l.next++
	}
}

// All returns every retained entry, oldest first.
func (l *QueryLog) All() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	latest := l.next - 1
	if latest == 0 {
		return nil
	}
	size := uint64(len(l.buf))
	first := uint64(1)
	if latest > size {
		first = latest - size + 1
	}
	out := make([]Entry, 0, latest-first+1)
	for i := first; i <= latest; i++ {
		out = append(out, l.buf[(i-1)%size])
	}
	return out
}

func (l *QueryLog) Add(e Entry) {
	l.mu.Lock()
	e.ID = l.next
	l.buf[(l.next-1)%uint64(len(l.buf))] = e
	l.next++
	subs := make([]chan Entry, 0, len(l.subs))
	for c := range l.subs {
		subs = append(subs, c)
	}
	sink := l.sink
	l.mu.Unlock()
	for _, c := range subs {
		select {
		case c <- e:
		default: // never let a slow reader stall DNS
		}
	}
	if sink != nil {
		sink(e)
	}
}

// After returns up to limit entries newer than id, oldest first, and the id of
// the last one returned. With id 0 it returns the most recent limit entries.
func (l *QueryLog) After(id uint64, limit int) ([]Entry, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	latest := l.next - 1
	if latest == 0 {
		return nil, 0
	}
	size := uint64(len(l.buf))
	oldest := uint64(1)
	if latest > size {
		oldest = latest - size + 1
	}
	lim := uint64(limit)
	start := id + 1
	if id == 0 {
		start = 1
		if latest > lim {
			start = latest - lim + 1
		}
	}
	if start < oldest {
		start = oldest
	}
	if start > latest {
		return nil, latest
	}
	end := latest
	if end-start+1 > lim {
		end = start + lim - 1
	}
	out := make([]Entry, 0, end-start+1)
	for i := start; i <= end; i++ {
		out = append(out, l.buf[(i-1)%size])
	}
	return out, end
}

type Count struct {
	Key string `json:"key"`
	N   uint64 `json:"n"`
}

// Stats keeps running counters since startup.
type Stats struct {
	total, blocked, cached, errors atomic.Uint64

	mu      sync.Mutex
	clients map[string]uint64
	domains map[string]uint64 // blocked domains
	reasons map[string]uint64 // blocked, by reason
}

type Snapshot struct {
	Total      uint64  `json:"total"`
	Blocked    uint64  `json:"blocked"`
	Cached     uint64  `json:"cached"`
	Errors     uint64  `json:"errors"`
	TopClients []Count `json:"top_clients"`
	TopBlocked []Count `json:"top_blocked"`
	Reasons    []Count `json:"blocked_by_reason"`
}

func NewStats() *Stats {
	return &Stats{clients: map[string]uint64{}, domains: map[string]uint64{}, reasons: map[string]uint64{}}
}

const statsCap = 5000

func bump(m map[string]uint64, key string) {
	if _, ok := m[key]; !ok && len(m) >= statsCap {
		clear(m)
	}
	m[key]++
}

func (s *Stats) Record(e Entry) {
	s.total.Add(1)
	switch e.Action {
	case "blocked":
		s.blocked.Add(1)
	case "cached":
		s.cached.Add(1)
	case "error":
		s.errors.Add(1)
	}
	s.mu.Lock()
	bump(s.clients, e.Client)
	if e.Action == "blocked" {
		bump(s.domains, e.Name)
		bump(s.reasons, e.Reason)
	}
	s.mu.Unlock()
}

func top(m map[string]uint64, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{
		Total: s.total.Load(), Blocked: s.blocked.Load(), Cached: s.cached.Load(), Errors: s.errors.Load(),
		TopClients: top(s.clients, 10), TopBlocked: top(s.domains, 10), Reasons: top(s.reasons, 8),
	}
}
