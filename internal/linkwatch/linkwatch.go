// SPDX-License-Identifier: AGPL-3.0-or-later

package linkwatch

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Iface is the part of a network interface linkwatch cares about.
type Iface struct {
	Name    string
	Up      bool // administratively up
	Running bool // the link has carrier (IFF_RUNNING)
	Addrs   []netip.Addr
}

// Lister returns the machine's interfaces.
type Lister func() ([]Iface, error)

// Episode is one stretch during which a watched address was unusable.
type Episode struct {
	Addr   netip.Addr
	Iface  string // the interface the address was last seen on
	Reason string
	Start  time.Time
	End    time.Time // zero while the episode is still open
}

// Duration is how long the address was gone, or has been gone so far.
func (e Episode) Duration(now time.Time) time.Duration {
	end := e.End
	if end.IsZero() {
		end = now
	}
	return end.Sub(e.Start).Round(time.Second)
}

// Options configures a Watcher.
type Options struct {
	// Addrs are the addresses Shepherd serves on. Loopback and unspecified
	// addresses are ignored: they cannot lose their link.
	Addrs []netip.Addr
	// Interval is the polling period. Default one second.
	Interval time.Duration
	// List reads the interfaces. Default SystemInterfaces.
	List Lister
	// Now is the clock. Default time.Now.
	Now func() time.Time
	// OnLost is called when an address becomes unusable, with Episode.End
	// zero. It runs on the watcher's goroutine: keep it quick.
	OnLost func(Episode)
	// OnRestored is called when it is usable again, with the closed Episode.
	OnRestored func(Episode)
}

// Watcher polls interface state and reports loss and restoration.
type Watcher struct {
	o    Options
	mu   sync.Mutex
	open map[netip.Addr]*Episode
	last map[netip.Addr]string // last interface each address was seen on
}

// New builds a Watcher.
func New(o Options) *Watcher {
	if o.Interval <= 0 {
		o.Interval = time.Second
	}
	if o.List == nil {
		o.List = SystemInterfaces
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	var addrs []netip.Addr
	for _, a := range o.Addrs {
		a = a.Unmap()
		if a.IsValid() && !a.IsLoopback() && !a.IsUnspecified() {
			addrs = append(addrs, a)
		}
	}
	o.Addrs = addrs
	return &Watcher{o: o, open: map[netip.Addr]*Episode{}, last: map[netip.Addr]string{}}
}

// Watching reports how many addresses are being watched.
func (w *Watcher) Watching() int { return len(w.o.Addrs) }

// Open returns the episodes that have not ended yet.
func (w *Watcher) Open() []Episode {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []Episode
	for _, e := range w.open {
		out = append(out, *e)
	}
	return out
}

// Poll takes one observation. Run calls it on a ticker; tests call it
// directly. A failure to list interfaces is not a finding: the watcher says
// nothing rather than guess.
func (w *Watcher) Poll() {
	ifs, err := w.o.List()
	if err != nil {
		return
	}
	now := w.o.Now()
	for _, a := range w.o.Addrs {
		ok, name, reason := judge(ifs, a)
		if name != "" {
			w.mu.Lock()
			w.last[a] = name
			w.mu.Unlock()
		}
		w.mu.Lock()
		ep := w.open[a]
		switch {
		case !ok && ep == nil:
			ep = &Episode{Addr: a, Iface: w.last[a], Reason: reason, Start: now}
			w.open[a] = ep
			cp := *ep
			w.mu.Unlock()
			if w.o.OnLost != nil {
				w.o.OnLost(cp)
			}
		case ok && ep != nil:
			ep.End = now
			cp := *ep
			delete(w.open, a)
			w.mu.Unlock()
			if w.o.OnRestored != nil {
				w.o.OnRestored(cp)
			}
		default:
			w.mu.Unlock()
		}
	}
}

// Run polls until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	if len(w.o.Addrs) == 0 {
		return
	}
	t := time.NewTicker(w.o.Interval)
	defer t.Stop()
	w.Poll()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Poll()
		}
	}
}

// judge says whether addr is usable, which interface holds it, and if not why.
func judge(ifs []Iface, a netip.Addr) (ok bool, name, reason string) {
	for _, i := range ifs {
		for _, x := range i.Addrs {
			if x.Unmap() != a {
				continue
			}
			switch {
			case !i.Up:
				return false, i.Name, fmt.Sprintf("interface %s was taken down", i.Name)
			case !i.Running:
				return false, i.Name, fmt.Sprintf("interface %s lost its link (no carrier)", i.Name)
			}
			return true, i.Name, ""
		}
	}
	return false, "", "the address was removed from every interface"
}

// SystemInterfaces lists the real interfaces.
func SystemInterfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(ifs))
	for _, i := range ifs {
		item := Iface{Name: i.Name, Up: i.Flags&net.FlagUp != 0, Running: i.Flags&net.FlagRunning != 0}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				if p, err := netip.ParsePrefix(a.String()); err == nil {
					item.Addrs = append(item.Addrs, p.Addr())
				} else if ip, err := netip.ParseAddr(a.String()); err == nil {
					item.Addrs = append(item.Addrs, ip)
				}
			}
		}
		out = append(out, item)
	}
	return out, nil
}
