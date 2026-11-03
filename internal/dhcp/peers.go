// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// DefaultSettle is how long the segment must be quiet of other DHCP servers
// before Shepherd will start answering, and how long after the last sighting
// a server is still considered present.
//
// Sixty seconds is a judgement rather than a measurement. It has to be longer
// than a client's retry interval, because a quiet minute during which no
// client happened to ask proves nothing about a server that is sitting there
// ready to answer — and that is the honest limit of this interlock: it
// detects a server that *answers*, not one that merely exists. On a
// household segment some device asks within a minute, which is what makes it
// work in practice rather than in principle.
const DefaultSettle = 60 * time.Second

// Peer is one other DHCP server seen answering on this segment.
type Peer struct {
	Server netip.Addr `json:"server"`
	First  time.Time  `json:"first"`
	Last   time.Time  `json:"last"`
	Count  int        `json:"count"`
}

// Peers remembers the other DHCP servers that have answered on this segment.
// It is the interlock that keeps two servers from splitting the household
// between them: Shepherd refuses to serve while one is present, and stops
// serving if one appears.
//
// Two servers answering is not a conflict the protocol resolves. A client
// takes whichever offer it likes, which in practice means whichever arrived
// first, which varies per device and per boot. Half the house on each
// gateway, non-deterministically, is the worst state this feature can reach
// and it is one forgotten checkbox away.
type Peers struct {
	mu   sync.RWMutex
	seen map[netip.Addr]*Peer
}

// NewPeers returns an empty record.
func NewPeers() *Peers { return &Peers{seen: map[netip.Addr]*Peer{}} }

// maxPeers bounds the table. More than a handful of DHCP servers on one
// segment is not a situation to catalogue; it is one to report.
const maxPeers = 32

// Saw records that server answered at t.
func (p *Peers) Saw(server netip.Addr, t time.Time) {
	if !server.IsValid() || server.IsUnspecified() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.seen[server]; ok {
		e.Last, e.Count = t, e.Count+1
		return
	}
	if len(p.seen) >= maxPeers {
		return
	}
	p.seen[server] = &Peer{Server: server, First: t, Last: t, Count: 1}
}

// Active returns the servers seen within the settle window, newest sighting
// first. An empty result is what lets Shepherd serve.
func (p *Peers) Active(now time.Time, settle time.Duration) []Peer {
	if settle <= 0 {
		settle = DefaultSettle
	}
	cutoff := now.Add(-settle)
	p.mu.RLock()
	defer p.mu.RUnlock()
	var out []Peer
	for _, e := range p.seen {
		if e.Last.After(cutoff) {
			out = append(out, *e)
		}
	}
	slices.SortFunc(out, func(a, b Peer) int { return b.Last.Compare(a.Last) })
	return out
}

// All returns every server ever seen, newest sighting first, for the portal's
// account of what has been on this segment.
func (p *Peers) All() []Peer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Peer, 0, len(p.seen))
	for _, e := range p.seen {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b Peer) int { return b.Last.Compare(a.Last) })
	return out
}

// Forget clears the record. The portal offers this for the case the
// interlock is right about the past and wrong about the present: the router's
// DHCP has now been turned off, and the operator does not want to wait out
// the window of a server that is gone.
func (p *Peers) Forget() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = map[netip.Addr]*Peer{}
}
