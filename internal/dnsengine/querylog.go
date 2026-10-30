// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one answered query.
type Entry struct {
	ID       uint64    `json:"id"`
	Time     time.Time `json:"time"`
	Client   string    `json:"client"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Action   string    `json:"action"` // allowed, cached, blocked or error
	Reason   string    `json:"reason,omitempty"`
	Upstream string    `json:"upstream,omitempty"`
	Ms       float64   `json:"ms"`
	Rcode    string    `json:"rcode"`
}

// QueryLog is a fixed-size in-memory ring. Entries are never written to disk.
type QueryLog struct {
	mu   sync.Mutex
	buf  []Entry
	next uint64
}

func NewQueryLog(size int) *QueryLog {
	if size < 1 {
		size = 1000
	}
	return &QueryLog{buf: make([]Entry, size), next: 1}
}

func (l *QueryLog) Add(e Entry) {
	l.mu.Lock()
	e.ID = l.next
	l.buf[(l.next-1)%uint64(len(l.buf))] = e
	l.next++
	l.mu.Unlock()
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
