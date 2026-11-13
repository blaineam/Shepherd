// SPDX-License-Identifier: AGPL-3.0-or-later

// Package decoy listens on a few TCP ports nothing on a home network has a
// reason to connect to: Telnet, remote desktop, screen sharing. Nothing is
// served on them. A connection is accepted, its source recorded and the
// connection closed, so the only thing a decoy ever says is "something on
// this network tried the door". That is the one sign of a device probing
// its neighbours that needs no traffic mirror: the probe comes to Shepherd.
// See docs/DETECT.md.
package decoy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"
)

// DefaultPorts are the doors: Telnet and its usual alternate (what worms
// that spread between cameras and routers try first), Windows remote
// desktop and VNC screen sharing. A port already in use on the host, or
// one the process may not bind, is skipped.
func DefaultPorts() []int { return []int{23, 2323, 3389, 5900} }

// DefaultQuiet is how long one source touching one port is not reported
// again.
const DefaultQuiet = time.Hour

const recentMax = 200

// Touch is one source connecting to one decoy port.
type Touch struct {
	Time   time.Time `json:"time"`
	Source string    `json:"source"`
	Port   int       `json:"port"`
	// Count is how many times this source has connected to this port since
	// Shepherd started, this one included.
	Count int `json:"count"`
}

// PortStatus is one configured port's state.
type PortStatus struct {
	Port      int    `json:"port"`
	Listening bool   `json:"listening"`
	Error     string `json:"error,omitempty"`
}

// Options configures a Decoy.
type Options struct {
	// Ports to listen on; nil uses DefaultPorts.
	Ports []int
	// Host is the address to bind; empty binds every address.
	Host string
	// Listen opens a listener; nil uses net.Listen.
	Listen func(network, addr string) (net.Listener, error)
	// Ignore reports sources that are not news: this host's own addresses,
	// which Shepherd's own port scan connects from. Loopback is always
	// ignored.
	Ignore func(netip.Addr) bool
	// OnTouch hears every reported touch. It must not block.
	OnTouch func(Touch)
	Now     func() time.Time
	// Quiet defaults to DefaultQuiet.
	Quiet time.Duration
}

type hit struct {
	count int
	last  time.Time // when it was last reported
}

// Decoy is the set of listeners. It is safe for concurrent use.
type Decoy struct {
	opt Options

	mu     sync.Mutex
	ports  []PortStatus
	lns    []net.Listener
	hits   map[string]*hit
	recent []Touch
	wg     sync.WaitGroup
}

// New builds a Decoy. Nothing listens until Start.
func New(opt Options) *Decoy {
	if opt.Ports == nil {
		opt.Ports = DefaultPorts()
	}
	if opt.Listen == nil {
		opt.Listen = net.Listen
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Quiet <= 0 {
		opt.Quiet = DefaultQuiet
	}
	return &Decoy{opt: opt, hits: map[string]*hit{}}
}

// Start opens every port it can and serves them until ctx ends. A port
// that cannot be opened is recorded in Status and skipped: a decoy that
// cannot listen costs nothing and must never stop Shepherd.
func (d *Decoy) Start(ctx context.Context) []PortStatus {
	ports := slices.Clone(d.opt.Ports)
	sort.Ints(ports)
	ports = slices.Compact(ports)
	d.mu.Lock()
	for _, p := range ports {
		st := PortStatus{Port: p}
		ln, err := d.opt.Listen("tcp", net.JoinHostPort(d.opt.Host, strconv.Itoa(p)))
		if err != nil {
			st.Error = err.Error()
		} else {
			st.Listening = true
			d.lns = append(d.lns, ln)
			d.wg.Add(1)
			go d.serve(ln, p)
		}
		d.ports = append(d.ports, st)
	}
	lns := slices.Clone(d.lns)
	out := slices.Clone(d.ports)
	d.mu.Unlock()
	go func() {
		<-ctx.Done()
		for _, ln := range lns {
			ln.Close()
		}
	}()
	return out
}

// Wait blocks until every listener has stopped, which follows the end of
// Start's context.
func (d *Decoy) Wait() { d.wg.Wait() }

func (d *Decoy) serve(ln net.Listener, port int) {
	defer d.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A transient accept failure (out of descriptors): back off
			// rather than spin, and keep the door open.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		src := c.RemoteAddr()
		c.Close()
		d.touched(src, port)
	}
}

func (d *Decoy) touched(src net.Addr, port int) {
	ap, err := netip.ParseAddrPort(src.String())
	if err != nil {
		return
	}
	addr := ap.Addr().Unmap()
	if addr.IsLoopback() || (d.opt.Ignore != nil && d.opt.Ignore(addr)) {
		return
	}
	now := d.opt.Now()
	key := addr.String() + "|" + strconv.Itoa(port)
	d.mu.Lock()
	h := d.hits[key]
	if h == nil {
		if len(d.hits) >= 4096 {
			clear(d.hits)
		}
		h = &hit{}
		d.hits[key] = h
	}
	h.count++
	if h.count > 1 && now.Sub(h.last) < d.opt.Quiet {
		d.mu.Unlock()
		return
	}
	h.last = now
	t := Touch{Time: now, Source: addr.String(), Port: port, Count: h.count}
	d.recent = append(d.recent, t)
	if over := len(d.recent) - recentMax; over > 0 {
		d.recent = slices.Clone(d.recent[over:])
	}
	d.mu.Unlock()
	if d.opt.OnTouch != nil {
		d.opt.OnTouch(t)
	}
}

// Status lists every configured port and whether it is listening.
func (d *Decoy) Status() []PortStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := slices.Clone(d.ports)
	if out == nil {
		out = []PortStatus{}
	}
	return out
}

// Listening returns the ports that are open, sorted.
func (d *Decoy) Listening() []int {
	var out []int
	for _, p := range d.Status() {
		if p.Listening {
			out = append(out, p.Port)
		}
	}
	return out
}

// Recent returns the latest reported touches, newest first.
func (d *Decoy) Recent() []Touch {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := slices.Clone(d.recent)
	slices.Reverse(out)
	if out == nil {
		out = []Touch{}
	}
	return out
}

// PortName says what a decoy port pretends to be, for an alarm.
func PortName(port int) string {
	switch port {
	case 23, 2323:
		return "Telnet"
	case 3389:
		return "remote desktop"
	case 5900:
		return "screen sharing (VNC)"
	case 445:
		return "Windows file sharing"
	case 22:
		return "SSH"
	}
	return "port " + strconv.Itoa(port)
}
