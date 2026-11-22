// SPDX-License-Identifier: AGPL-3.0-or-later

// Package namesync keeps one name per device across every place that has
// one (docs/BACKENDS.md, "Device names"): Shepherd's own registry and the
// routers and firewalls the owner has connected.
//
// Devices are matched by MAC address. The first time a device is seen in
// more than one place, the most readable name wins (Quality): a name a
// person typed beats a hostname, which beats a maker's name, and a MAC
// address or "Unknown" never replaces anything. After that, a name edited
// in any one place is written to all the others.
//
// To tell an edit from a name that was simply different all along, the
// engine remembers the name it last saw for each device in each place. It
// also remembers the name it last agreed on, so a place that could not be
// written (a read-only token, a failed request) is caught up later.
package namesync

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	// DefaultInterval between automatic runs.
	DefaultInterval = 2 * time.Minute
	// echoWindow is how long after writing a name the old one is still
	// expected back from a service that answers from a cache. Without it
	// the stale answer would read as someone editing the name back.
	echoWindow = 10 * time.Minute
	// retryAfter is how long a write that failed is left alone.
	retryAfter = 30 * time.Minute
	maxLog     = 200
	runTimeout = 10 * time.Minute
)

// Entry is one device's name in one place.
type Entry struct {
	// MAC is lowercase hex with no separators.
	MAC  string
	Name string
	// Typed is true when the place knows a person set the name. Learned is
	// true when it knows the device reported it (a hostname). A place that
	// cannot tell sets neither.
	Typed, Learned bool
	Vendor         string
	// Handle is whatever the Source needs to rename the device.
	Handle any
}

// Source is one place devices have names.
type Source interface {
	// ID is lowercase and stable ("shepherd", "firewalla", "eero").
	ID() string
	// Label is how the place is written on the screen.
	Label() string
	// Entries lists every device with a MAC.
	Entries(ctx context.Context) ([]Entry, error)
	// ReadOnly is why names cannot be written here right now, "" when
	// they can.
	ReadOnly() string
	// MaxLen is the longest name the place accepts, in characters; 0 for
	// no limit.
	MaxLen() int
	Rename(ctx context.Context, e Entry, name string) error
}

// Options configures an Engine.
type Options struct {
	// Sources returns the places to sync right now, most trusted first:
	// when two names are equally good, the earlier source's wins. It is
	// called on every run, because connections come and go.
	Sources func() []Source
	// StatePath keeps what the engine remembers. Empty keeps it in memory.
	StatePath string
	Interval  time.Duration
	// KickDelay is how long Run waits after a Kick, so a burst of edits
	// becomes one run (default 3s).
	KickDelay time.Duration
	Now       func() time.Time
	Logf      func(string, ...any)
}

// SourceStatus is one place as the last run found it.
type SourceStatus struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Devices  int    `json:"devices"`
	ReadOnly string `json:"read_only,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Change is one device whose name is, or would be, written somewhere.
type Change struct {
	MAC  string `json:"mac"`
	Name string `json:"name"`
	// Reason is "first" (the best of the names found), "edit" (it was
	// changed in From) or "catchup" (a place is behind the agreed name).
	Reason string `json:"reason"`
	// From is the place the name came from.
	From string `json:"from"`
	// Names is the name in each place before the change.
	Names map[string]string `json:"names"`
	// Writes are the places the name is written to; Held the places it
	// would be but cannot right now; Failed the places that refused it.
	Writes []string          `json:"writes,omitempty"`
	Held   []string          `json:"held,omitempty"`
	Failed map[string]string `json:"failed,omitempty"`
}

// Report is the outcome of one run, or of a preview.
type Report struct {
	Time    time.Time      `json:"time"`
	DryRun  bool           `json:"dry_run"`
	Sources []SourceStatus `json:"sources"`
	Changes []Change       `json:"changes"`
	// Written, Held and Failed count names, not devices.
	Written int `json:"written"`
	Held    int `json:"held"`
	Failed  int `json:"failed"`
	// InSync is how many devices already carry one name everywhere.
	InSync int `json:"in_sync"`
}

// LogEntry is one name the engine wrote, kept so a change can be traced
// and undone by hand.
type LogEntry struct {
	Time   time.Time `json:"time"`
	MAC    string    `json:"mac"`
	Source string    `json:"source"`
	Old    string    `json:"old"`
	New    string    `json:"new"`
	Reason string    `json:"reason"`
	From   string    `json:"from"`
}

// Status is what the portal shows.
type Status struct {
	Auto    bool       `json:"auto"`
	Running bool       `json:"running"`
	Last    *Report    `json:"last,omitempty"`
	Log     []LogEntry `json:"log"`
}

type pending struct {
	Old string    `json:"old"`
	At  time.Time `json:"at"`
}

type state struct {
	Auto bool `json:"auto"`
	// Base is the agreed name per MAC.
	Base map[string]string `json:"base"`
	// Seen is the name last seen or written, per source, per MAC.
	Seen map[string]map[string]string `json:"seen"`
	// Pending is the name a write replaced, per source, per MAC.
	Pending map[string]map[string]pending `json:"pending,omitempty"`
	Log     []LogEntry                    `json:"log,omitempty"`
}

// Engine runs the sync.
type Engine struct {
	o Options

	run sync.Mutex // one run at a time

	mu      sync.Mutex
	st      state
	last    *Report
	running bool
	failed  map[string]time.Time // source|mac|name → when it was refused
	kick    chan struct{}
}

// New returns an Engine. Nothing is read or written until Preview, Sync or
// Run.
func New(o Options) *Engine {
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.KickDelay <= 0 {
		o.KickDelay = 3 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	e := &Engine{o: o, failed: map[string]time.Time{}, kick: make(chan struct{}, 1)}
	e.st = state{Base: map[string]string{}, Seen: map[string]map[string]string{}, Pending: map[string]map[string]pending{}}
	e.load()
	return e
}

func (e *Engine) load() {
	if e.o.StatePath == "" {
		return
	}
	b, err := os.ReadFile(e.o.StatePath)
	if err != nil {
		return
	}
	var st state
	if json.Unmarshal(b, &st) != nil {
		e.o.Logf("names: %s is unreadable; starting again as a first sync", e.o.StatePath)
		return
	}
	if st.Base == nil {
		st.Base = map[string]string{}
	}
	if st.Seen == nil {
		st.Seen = map[string]map[string]string{}
	}
	if st.Pending == nil {
		st.Pending = map[string]map[string]pending{}
	}
	e.st = st
}

// saveLocked writes the state. The caller holds e.mu.
func (e *Engine) saveLocked() error {
	if e.o.StatePath == "" {
		return nil
	}
	b, _ := json.Marshal(e.st)
	tmp := e.o.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.o.StatePath)
}

// Status reports the switch, the last run and the recent writes.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Status{Auto: e.st.Auto, Running: e.running, Last: e.last, Log: append([]LogEntry{}, e.st.Log...)}
}

// SetAuto turns the automatic sync on or off. Turning it on runs one soon.
func (e *Engine) SetAuto(on bool) error {
	e.mu.Lock()
	e.st.Auto = on
	err := e.saveLocked()
	e.mu.Unlock()
	if on {
		e.Kick()
	}
	return err
}

// Kick asks Run for a sync soon, for a name that was just edited in
// Shepherd. It does nothing while the automatic sync is off.
func (e *Engine) Kick() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// Run syncs every Interval, and shortly after a Kick, while the automatic
// sync is on. It returns when ctx ends.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(e.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.kick:
			// Let a burst of edits settle into one run.
			select {
			case <-ctx.Done():
				return
			case <-time.After(e.o.KickDelay):
			}
		}
		e.mu.Lock()
		auto := e.st.Auto
		e.mu.Unlock()
		if !auto {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, runTimeout)
		if rep, err := e.Sync(rctx); err != nil {
			e.o.Logf("names: %v", err)
		} else if rep.Written+rep.Failed > 0 {
			e.o.Logf("names: wrote %d, %d failed, %d waiting", rep.Written, rep.Failed, rep.Held)
		}
		cancel()
	}
}

// ErrNothingToSync is returned when fewer than two places are connected.
var ErrNothingToSync = errors.New("names: connect a router or firewall first; there is nothing to sync names with")

// Preview reports what a sync would write, and writes nothing.
func (e *Engine) Preview(ctx context.Context) (Report, error) { return e.sync(ctx, true) }

// Sync reads every place and writes the names that differ.
func (e *Engine) Sync(ctx context.Context) (Report, error) { return e.sync(ctx, false) }

// Start runs a Sync in the background, for the portal, which reads the
// outcome from Status. It reports false when one is already running.
func (e *Engine) Start(ctx context.Context) bool {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return false
	}
	e.running = true
	e.mu.Unlock()
	go func() {
		rctx, cancel := context.WithTimeout(ctx, runTimeout)
		defer cancel()
		if _, err := e.Sync(rctx); err != nil {
			e.o.Logf("names: %v", err)
		}
	}()
	return true
}

// read is one source as this run found it.
type read struct {
	src     Source
	entries map[string]Entry
	err     error
}

func (e *Engine) sync(ctx context.Context, dry bool) (Report, error) {
	e.run.Lock()
	defer e.run.Unlock()
	if !dry {
		e.mu.Lock()
		e.running = true
		e.mu.Unlock()
		defer func() {
			e.mu.Lock()
			e.running = false
			e.mu.Unlock()
		}()
	}

	var srcs []Source
	if e.o.Sources != nil {
		srcs = e.o.Sources()
	}
	if len(srcs) < 2 {
		return Report{}, ErrNothingToSync
	}
	now := e.o.Now()
	rep := Report{Time: now, DryRun: dry, Changes: []Change{}}
	reads := make([]read, 0, len(srcs))
	for _, s := range srcs {
		st := SourceStatus{ID: s.ID(), Label: s.Label(), ReadOnly: s.ReadOnly()}
		list, err := s.Entries(ctx)
		r := read{src: s, err: err, entries: map[string]Entry{}}
		if err != nil {
			st.Error = err.Error()
		}
		for _, en := range list {
			if en.MAC == "" {
				continue
			}
			// A place that lists a device twice keeps the better name.
			if old, dup := r.entries[en.MAC]; dup && score(old) >= score(en) {
				continue
			}
			r.entries[en.MAC] = en
		}
		st.Devices = len(r.entries)
		rep.Sources = append(rep.Sources, st)
		reads = append(reads, r)
	}

	e.mu.Lock()
	decisions, inSync := e.planLocked(reads, now)
	e.mu.Unlock()
	rep.InSync = inSync
	wrote := map[string]bool{} // source|mac written by this run

	for _, d := range decisions {
		ch := Change{MAC: d.mac, Name: d.name, Reason: d.reason, From: d.from, Names: d.names}
		for _, w := range d.writes {
			if w.held {
				ch.Held = append(ch.Held, w.src.ID())
				rep.Held++
				continue
			}
			if dry {
				ch.Writes = append(ch.Writes, w.src.ID())
				rep.Written++
				continue
			}
			err := ctx.Err()
			if err == nil {
				err = w.src.Rename(ctx, w.entry, w.name)
			}
			e.mu.Lock()
			if err != nil {
				if ch.Failed == nil {
					ch.Failed = map[string]string{}
				}
				ch.Failed[w.src.ID()] = err.Error()
				rep.Failed++
				e.failed[failKey(w.src.ID(), d.mac, w.name)] = now
				e.o.Logf("names: renaming %s on %s: %v", d.mac, w.src.ID(), err)
			} else {
				ch.Writes = append(ch.Writes, w.src.ID())
				rep.Written++
				wrote[w.src.ID()+"|"+d.mac] = true
				e.noteWriteLocked(w, d, now)
			}
			e.mu.Unlock()
		}
		if len(ch.Writes)+len(ch.Held)+len(ch.Failed) > 0 {
			rep.Changes = append(rep.Changes, ch)
		}
	}

	if dry {
		return rep, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rememberLocked(reads, decisions, wrote, now)
	e.last = &rep
	if err := e.saveLocked(); err != nil {
		e.o.Logf("names: keeping state: %v", err)
	}
	return rep, nil
}

func failKey(src, mac, name string) string { return src + "|" + mac + "|" + name }

type write struct {
	src   Source
	entry Entry
	name  string // the target, cut to what the place accepts
	held  bool   // wanted, but the place cannot be written right now
}

type decision struct {
	mac, name, reason, from string
	names                   map[string]string
	writes                  []write
	// echo lists the sources still answering with the name a recent write
	// replaced; what is remembered for them is left alone.
	echo map[string]bool
}

// planLocked decides, for every device seen in a readable place, which
// name it should carry and where that has to be written. It changes
// nothing. The second result counts devices that already agree.
func (e *Engine) planLocked(reads []read, now time.Time) ([]decision, int) {
	macs := map[string]bool{}
	for _, r := range reads {
		if r.err != nil {
			continue
		}
		for mac := range r.entries {
			macs[mac] = true
		}
	}
	order := make([]string, 0, len(macs))
	for mac := range macs {
		order = append(order, mac)
	}
	sort.Strings(order)

	var out []decision
	inSync := 0
	for _, mac := range order {
		d := decision{mac: mac, names: map[string]string{}, echo: map[string]bool{}}
		type cand struct {
			id    string
			entry Entry
		}
		var present, edits []cand
		fresh := false
		for _, r := range reads {
			if r.err != nil {
				continue
			}
			en, ok := r.entries[mac]
			if !ok {
				continue
			}
			id := r.src.ID()
			d.names[id] = en.Name
			present = append(present, cand{id, en})
			seen, known := e.st.Seen[id][mac]
			if !known {
				fresh = true
				continue
			}
			if p, ok := e.st.Pending[id][mac]; ok && en.Name == p.Old && en.Name != seen {
				// Still the name a write replaced. Inside the window the
				// answer may only be late, so wait; past it the write did
				// not stick and is made again. Either way it is not
				// somebody editing the name back.
				if now.Sub(p.At) < echoWindow {
					d.echo[id] = true
				}
				continue
			}
			if en.Name != seen && !en.Learned && score(en) > Useless {
				edits = append(edits, cand{id, en})
			}
		}
		best := func(list []cand) (cand, bool) {
			var win cand
			top := Useless
			for _, c := range list {
				// Strictly greater, so the earlier source wins a tie.
				if s := score(c.entry); s > top {
					win, top = c, s
				}
			}
			return win, top > Useless
		}
		switch {
		case len(edits) > 0:
			w, _ := best(edits)
			d.name, d.from, d.reason = w.entry.Name, w.id, "edit"
		case fresh:
			// A maker's name alone is not worth copying anywhere.
			if w, ok := best(present); ok && score(w.entry) > Generic {
				d.name, d.from, d.reason = w.entry.Name, w.id, "first"
			}
		case e.st.Base[mac] != "":
			d.name, d.reason = e.st.Base[mac], "catchup"
		}
		if d.name != "" {
			for _, r := range reads {
				en, ok := r.entries[mac]
				if r.err != nil || !ok {
					continue
				}
				id := r.src.ID()
				want := fit(d.name, r.src.MaxLen())
				// A place still answering with the old name is left alone
				// only while what it was sent is still what is wanted.
				if en.Name == want || d.echo[id] && e.st.Seen[id][mac] == want {
					continue
				}
				w := write{src: r.src, entry: en, name: want}
				if r.src.ReadOnly() != "" {
					w.held = true
				} else if at, bad := e.failed[failKey(id, mac, want)]; bad && now.Sub(at) < retryAfter {
					w.held = true
				}
				d.writes = append(d.writes, w)
			}
		}
		if len(d.writes) == 0 && len(present) > 1 && d.name != "" {
			inSync++
		}
		out = append(out, d)
	}
	return out, inSync
}

// noteWriteLocked records a name that was written.
func (e *Engine) noteWriteLocked(w write, d decision, now time.Time) {
	id := w.src.ID()
	if e.st.Seen[id] == nil {
		e.st.Seen[id] = map[string]string{}
	}
	if e.st.Pending[id] == nil {
		e.st.Pending[id] = map[string]pending{}
	}
	e.st.Seen[id][d.mac] = w.name
	e.st.Pending[id][d.mac] = pending{Old: w.entry.Name, At: now}
	e.st.Log = append([]LogEntry{{Time: now, MAC: d.mac, Source: id, Old: w.entry.Name, New: w.name, Reason: d.reason, From: d.from}}, e.st.Log...)
	if len(e.st.Log) > maxLog {
		e.st.Log = e.st.Log[:maxLog]
	}
}

// rememberLocked records what every readable place showed, so the next run
// can tell an edit from a name that has not changed.
func (e *Engine) rememberLocked(reads []read, decisions []decision, wrote map[string]bool, now time.Time) {
	for _, d := range decisions {
		if d.name != "" {
			e.st.Base[d.mac] = d.name
		}
		for _, r := range reads {
			en, ok := r.entries[d.mac]
			id := r.src.ID()
			if r.err != nil || !ok || wrote[id+"|"+d.mac] || d.echo[id] {
				continue
			}
			if e.st.Seen[id] == nil {
				e.st.Seen[id] = map[string]string{}
			}
			e.st.Seen[id][d.mac] = en.Name
		}
	}
	// A write is forgotten once the place stops answering with the name
	// it replaced, and not before: forgetting it by age alone would turn a
	// write that never stuck into an edit back to the old name.
	for _, r := range reads {
		id := r.src.ID()
		m := e.st.Pending[id]
		if r.err != nil || m == nil {
			continue
		}
		for mac, p := range m {
			if en, ok := r.entries[mac]; ok && en.Name != p.Old {
				delete(m, mac)
			}
		}
		if len(m) == 0 {
			delete(e.st.Pending, id)
		}
	}
	for k, at := range e.failed {
		if now.Sub(at) >= retryAfter {
			delete(e.failed, k)
		}
	}
}

// fit cuts name to max characters; 0 is no limit.
func fit(name string, max int) string {
	if r := []rune(name); max > 0 && len(r) > max {
		return string(r[:max])
	}
	return name
}
