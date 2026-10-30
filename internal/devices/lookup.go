// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"sync"
	"sync/atomic"
	"time"

	"shepherd/internal/dnsengine"
)

// Lookup answers the DNS engine's per-query question "which device is this,
// what is it called, and is it excluded". It satisfies dnsengine.DeviceNamer.
//
// The hot path is two lock-free reads: the registry's scope snapshot (client
// address to device ID) and an immutable map of device ID to display name. The
// map is rebuilt from the registry after any registry event, by the next query
// that finds it stale, so names and the Excluded flag follow edits at once.
type Lookup struct {
	reg   *Registry
	unsub func()

	info  atomic.Pointer[map[string]dnsengine.DeviceInfo]
	stale atomic.Bool
	build sync.Mutex
}

// NewLookup attaches a Lookup to reg. Call Close to detach it.
func NewLookup(reg *Registry) *Lookup {
	l := &Lookup{reg: reg}
	l.stale.Store(true)
	l.unsub = reg.Subscribe(func(Event) { l.stale.Store(true) })
	return l
}

// Close stops following the registry.
func (l *Lookup) Close() { l.unsub() }

func (l *Lookup) rebuild() {
	if !l.build.TryLock() { // someone else is rebuilding; use what we have
		return
	}
	defer l.build.Unlock()
	if !l.stale.Swap(false) {
		return
	}
	devs := l.reg.List()
	m := make(map[string]dnsengine.DeviceInfo, len(devs))
	for _, d := range devs {
		m[d.ID] = dnsengine.DeviceInfo{ID: d.ID, Name: d.DisplayName(), Excluded: d.Excluded, Wandering: d.Wandering, WanderingUntil: d.WanderingUntil}
	}
	l.info.Store(&m)
}

// DeviceFor implements dnsengine.DeviceNamer.
func (l *Lookup) DeviceFor(clientIP string) dnsengine.DeviceInfo {
	id, _ := l.reg.ScopesFor(clientIP)
	if id == "" {
		return dnsengine.DeviceInfo{}
	}
	if l.stale.Load() || l.info.Load() == nil {
		l.rebuild()
	}
	if m := l.info.Load(); m != nil {
		return (*m)[id]
	}
	return dnsengine.DeviceInfo{}
}

// DNSFeeder turns DNS clients into observations: every query's source
// address is evidence that a device is there. Each address is reported at most
// once per interval so a chatty device costs one registry write a minute.
type DNSFeeder struct {
	Sink     Sink
	Interval time.Duration // default 1m
	Now      func() time.Time

	seen sync.Map // string -> *atomic.Int64 (next allowed unix nano)
	n    atomic.Int32
}

// maxFeederAddrs bounds the rate-limit table; past it the table resets, which
// at worst reports every active address once more.
const maxFeederAddrs = 8192

// Seen reports a query from clientIP. It is safe for concurrent use and
// cheap when the address was reported recently.
func (f *DNSFeeder) Seen(clientIP string) {
	every := f.Interval
	if every <= 0 {
		every = time.Minute
	}
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	t := now()
	v, ok := f.seen.Load(clientIP)
	if !ok {
		if f.n.Add(1) > maxFeederAddrs {
			f.seen.Range(func(k, _ any) bool { f.seen.Delete(k); return true })
			f.n.Store(1)
		}
		v, _ = f.seen.LoadOrStore(clientIP, new(atomic.Int64))
	}
	next := v.(*atomic.Int64)
	cur := next.Load()
	if t.UnixNano() < cur || !next.CompareAndSwap(cur, t.Add(every).UnixNano()) {
		return
	}
	f.Sink.Observe(Observation{Source: SourceDNS, IP: clientIP, Time: t})
}
