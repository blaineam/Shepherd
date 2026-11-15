// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"crypto/tls"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// dotIdleTTL is how long a DoT connection may sit unused before it is
	// dropped instead of reused. Public resolvers hang up on idle clients
	// after roughly ten seconds and middleboxes forget quiet flows, so a
	// connection older than this is more likely dead than alive, and a dead
	// one costs a full timeout to discover.
	dotIdleTTL = 9 * time.Second
	// dotMaxIdle caps the connections kept per upstream. A household's
	// concurrency is small; more would only hold sockets open for nothing.
	dotMaxIdle = 2
	// dotReuseTimeout bounds one attempt on a pooled connection. A fresh
	// connection gets the pool's full timeout, but a pooled one that has
	// silently died (a NAT dropped the flow) must fail fast so the retry on
	// a fresh connection still lands inside the client's patience.
	dotReuseTimeout = time.Second
)

// dotIdle holds an upstream's idle DoT connections. Encrypted DNS used to
// open a fresh TCP and TLS connection for every query: two or three round
// trips of setup for a one-round-trip question, and a chance to time out on
// each. Reusing them is the whole point of DNS over TLS (RFC 7858).
//
// A connection is owned by exactly one goroutine between get and put, so no
// connection is ever used concurrently.
type dotIdle struct {
	mu    sync.Mutex
	conns []dotIdleConn
	now   func() time.Time // injected by tests
}

type dotIdleConn struct {
	c  *dns.Conn
	at time.Time
}

func (d *dotIdle) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

// get returns the most recently used live-looking connection, closing any
// that have idled past the TTL on the way, or nil.
func (d *dotIdle) get() *dns.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.clock()
	var expired []*dns.Conn
	var out *dns.Conn
	for len(d.conns) > 0 {
		last := d.conns[len(d.conns)-1]
		d.conns = d.conns[:len(d.conns)-1]
		if now.Sub(last.at) > dotIdleTTL {
			expired = append(expired, last.c)
			continue
		}
		out = last.c
		break
	}
	// Anything still held is older than what was just taken, so older ones
	// are the likelier to have expired: drop them now rather than wait.
	keep := d.conns[:0]
	for _, c := range d.conns {
		if now.Sub(c.at) > dotIdleTTL {
			expired = append(expired, c.c)
			continue
		}
		keep = append(keep, c)
	}
	d.conns = keep
	for _, c := range expired {
		_ = c.Close()
	}
	return out
}

// put returns a connection after a good exchange. Past the cap the oldest
// idle connection is closed.
func (d *dotIdle) put(c *dns.Conn) {
	d.mu.Lock()
	d.conns = append(d.conns, dotIdleConn{c: c, at: d.clock()})
	var drop *dns.Conn
	if len(d.conns) > dotMaxIdle {
		drop = d.conns[0].c
		d.conns = d.conns[1:]
	}
	d.mu.Unlock()
	if drop != nil {
		_ = drop.Close()
	}
}

func (d *dotIdle) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.conns)
}

func (d *dotIdle) closeAll() {
	d.mu.Lock()
	conns := d.conns
	d.conns = nil
	d.mu.Unlock()
	for _, c := range conns {
		_ = c.c.Close()
	}
}

// dotClientConfig is the TLS configuration for this upstream's connections.
// The session cache lets a fresh connection resume the last session, which
// turns the handshake into one round trip instead of two.
func (u *Upstream) dotClientConfig() *tls.Config {
	u.tlsOnce.Do(func() { u.tlsCache = tls.NewLRUClientSessionCache(8) })
	return &tls.Config{
		ServerName: u.serverName, MinVersion: tls.VersionTLS12, RootCAs: u.env.roots,
		ClientSessionCache: u.tlsCache,
	}
}
