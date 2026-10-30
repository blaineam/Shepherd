// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Errors returned by the engine.
var (
	ErrNotFound     = errors.New("alarms: alarm not found")
	ErrInvalidEvent = errors.New("alarms: invalid event")
	ErrClosed       = errors.New("alarms: engine closed")
)

// Retention bounds the stored history.
type Retention struct {
	// MaxAge drops resolved, acknowledged and muted alarms last seen longer
	// ago than this. Default 30 days.
	MaxAge time.Duration
	// MaxCount caps the number of alarms; the oldest resolved go first, then
	// acknowledged, muted and new. Default 5000.
	MaxCount int
	// TombstoneAge drops deleted records older than this. Only safe once
	// every replica has seen the deletion. Default 30 days.
	TombstoneAge time.Duration
}

// Options configures an Engine. The zero value is usable (memory only).
type Options struct {
	// Node is the writer identity stamped on records; default "local".
	Node string
	// Dir, when set, is where alarms, rules and preferences persist. It is
	// created (mode 0700) and loaded on start.
	Dir   string
	Clock Clock // default SystemClock
	Codec Codec // default PlainCodec
	// NewID produces alarm and rule ID material; default random.
	NewID func() string
	// Queue is the capacity of the Raise buffer (default 1024). When it is
	// full Raise drops the event and counts it.
	Queue int
	// DedupeWindow: the same Key within this window of the alarm's last
	// sighting folds into it. Default 1 hour; negative disables dedupe.
	DedupeWindow time.Duration
	// StormWindow and StormThreshold: more than StormThreshold new alarms of
	// one type for one device within StormWindow collapse into a bundle.
	// Defaults 1 minute and 5; a negative threshold disables storm control.
	StormWindow    time.Duration
	StormThreshold int
	Retention      Retention
	// TickEvery is how often the worker sweeps expiries and prunes
	// (default 30 seconds). SaveEvery bounds how often changes reach disk
	// (default 5 seconds; Close always saves).
	TickEvery time.Duration
	SaveEvery time.Duration
	// UndoTTL is how long undo handles live (default 10 minutes).
	UndoTTL time.Duration
	// Preferences are the initial preferences when none were saved; default
	// DefaultPreferences.
	Preferences *Preferences
}

type item struct {
	ev   Event
	done chan struct{}
}

type member struct {
	id string
	at time.Time
}

// Engine is the alarm engine. It is safe for concurrent use.
type Engine struct {
	mu    sync.Mutex
	node  string
	dir   string
	clock Clock
	codec Codec
	newID func() string

	dedupe    time.Duration
	storm     time.Duration
	stormN    int
	retention Retention
	tickEvery time.Duration
	saveEvery time.Duration
	undoTTL   time.Duration

	hlc          HLC
	alarms       map[string]*Alarm
	byKey        map[string]string
	children     map[string][]string
	buckets      map[string][]member
	rules        map[string]*Rule
	types        map[string]AlarmType
	prefs        Preferences
	prefsUpdated HLC
	installedAt  time.Time
	deviceSeen   map[string]time.Time
	undos        map[string]*undoEntry
	undoOrder    []string
	nextSweep    time.Time
	dirty        bool
	lastSave     time.Time

	dropped atomic.Uint64
	closed  atomic.Bool
	queue   chan item
	quit    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once

	subMu  sync.RWMutex
	subSeq int
	subs   map[int]func(Change)
}

func randomID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// New creates an engine, loads any saved state from Options.Dir and starts the
// worker. Call Close to stop it.
func New(o Options) (*Engine, error) {
	e := &Engine{
		node: o.Node, dir: o.Dir, clock: o.Clock, codec: o.Codec, newID: o.NewID,
		dedupe: o.DedupeWindow, storm: o.StormWindow, stormN: o.StormThreshold,
		retention: o.Retention, tickEvery: o.TickEvery, saveEvery: o.SaveEvery, undoTTL: o.UndoTTL,
		alarms: map[string]*Alarm{}, byKey: map[string]string{}, children: map[string][]string{},
		buckets: map[string][]member{}, rules: map[string]*Rule{}, types: map[string]AlarmType{},
		deviceSeen: map[string]time.Time{}, undos: map[string]*undoEntry{}, subs: map[int]func(Change){},
		quit: make(chan struct{}),
	}
	if e.node == "" {
		e.node = "local"
	}
	if e.clock == nil {
		e.clock = SystemClock{}
	}
	if e.codec == nil {
		e.codec = PlainCodec{}
	}
	if e.newID == nil {
		e.newID = randomID
	}
	if e.dedupe == 0 {
		e.dedupe = time.Hour
	}
	if e.storm <= 0 {
		e.storm = time.Minute
	}
	if e.stormN == 0 {
		e.stormN = 5
	}
	if e.retention.MaxAge <= 0 {
		e.retention.MaxAge = 30 * 24 * time.Hour
	}
	if e.retention.MaxCount <= 0 {
		e.retention.MaxCount = 5000
	}
	if e.retention.TombstoneAge <= 0 {
		e.retention.TombstoneAge = 30 * 24 * time.Hour
	}
	if e.tickEvery <= 0 {
		e.tickEvery = 30 * time.Second
	}
	if e.saveEvery <= 0 {
		e.saveEvery = 5 * time.Second
	}
	if e.undoTTL <= 0 {
		e.undoTTL = 10 * time.Minute
	}
	qn := o.Queue
	if qn <= 0 {
		qn = 1024
	}
	e.queue = make(chan item, qn)
	for _, t := range BuiltinTypes() {
		e.types[t.ID] = t
	}
	e.prefs = DefaultPreferences()
	if o.Preferences != nil {
		if err := o.Preferences.Validate(); err != nil {
			return nil, err
		}
		e.prefs = o.Preferences.Clone()
	}
	if e.dir != "" {
		if err := os.MkdirAll(e.dir, 0o700); err != nil {
			return nil, err
		}
		if err := e.load(); err != nil {
			return nil, err
		}
	}
	if e.installedAt.IsZero() {
		e.installedAt = e.clock.Now()
		e.dirty = true
	}
	e.wg.Add(1)
	go e.worker()
	return e, nil
}

// Close stops the worker, processes anything still queued and saves.
func (e *Engine) Close() error {
	var err error
	e.once.Do(func() {
		e.closed.Store(true)
		close(e.quit)
		e.wg.Wait()
		for {
			select {
			case it := <-e.queue:
				e.handle(it)
				continue
			default:
			}
			break
		}
		err = e.Save()
	})
	return err
}

func (e *Engine) worker() {
	defer e.wg.Done()
	tk := e.clock.NewTicker(e.tickEvery)
	defer tk.Stop()
	for {
		select {
		case it := <-e.queue:
			e.handle(it)
		case <-tk.C():
			e.Tick()
		case <-e.quit:
			return
		}
	}
}

func (e *Engine) handle(it item) {
	if it.done != nil {
		close(it.done)
		return
	}
	e.RaiseSync(it.ev)
}

// Raise hands an event to the engine. It never blocks: the event is queued for
// a worker, and when the queue is full it is dropped and counted (see
// Dropped). It reports whether the event was queued.
func (e *Engine) Raise(ev Event) bool {
	if e.closed.Load() {
		e.dropped.Add(1)
		return false
	}
	select {
	case e.queue <- item{ev: ev}:
		return true
	default:
		e.dropped.Add(1)
		return false
	}
}

// Dropped is how many events Raise has discarded because the queue was full
// or the engine was closed.
func (e *Engine) Dropped() uint64 { return e.dropped.Load() }

// Drain blocks until every event queued before the call has been processed.
func (e *Engine) Drain() {
	done := make(chan struct{})
	select {
	case e.queue <- item{done: done}:
	case <-e.quit:
		return
	}
	select {
	case <-done:
	case <-e.quit:
	}
}

// ---- helpers (callers hold e.mu) -------------------------------------------

func (e *Engine) tick() HLC {
	w := e.clock.Now().UnixMilli()
	if w > e.hlc.Wall {
		e.hlc = HLC{Wall: w}
	} else {
		e.hlc.Counter++
	}
	return e.hlc
}

func (e *Engine) stamp(h *HLC, node *string) {
	*h = e.tick()
	*node = e.node
}

func (e *Engine) touch(a *Alarm) { e.stamp(&a.Updated, &a.Node) }

func (e *Engine) locLocked() *time.Location {
	loc, err := e.prefs.Location()
	if err != nil {
		return time.UTC
	}
	return loc
}

func (e *Engine) live(id string) *Alarm {
	if a := e.alarms[id]; a != nil && !a.Deleted {
		return a
	}
	return nil
}

func (e *Engine) hidden(a *Alarm) bool {
	return a.ParentID != "" && e.live(a.ParentID) != nil
}

func (e *Engine) sortedAlarms() []*Alarm {
	out := make([]*Alarm, 0, len(e.alarms))
	for _, a := range e.alarms {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// mutate runs fn under the lock after sweeping expiries, then emits its
// changes outside the lock and lets the autosave look at the dirty flag.
func (e *Engine) mutate(fn func(now time.Time) ([]Change, error)) error {
	e.mu.Lock()
	now := e.clock.Now()
	changes := e.sweepLocked(now)
	more, err := fn(now)
	changes = append(changes, more...)
	if len(changes) > 0 {
		e.dirty = true
	}
	e.mu.Unlock()
	e.emit(changes)
	e.autosave()
	return err
}

func (e *Engine) autosave() {
	if e.dir == "" {
		return
	}
	e.mu.Lock()
	due := e.dirty && e.clock.Now().Sub(e.lastSave) >= e.saveEvery
	e.mu.Unlock()
	if due {
		e.Save()
	}
}

// ---- subscribers ------------------------------------------------------------

// Subscribe registers fn for every Change. Callbacks run on the goroutine that
// made the change, after the engine's lock is released, so they may call back
// into the engine; they should be quick. It returns an unsubscribe function.
func (e *Engine) Subscribe(fn func(Change)) (unsubscribe func()) {
	e.subMu.Lock()
	e.subSeq++
	id := e.subSeq
	e.subs[id] = fn
	e.subMu.Unlock()
	return func() {
		e.subMu.Lock()
		delete(e.subs, id)
		e.subMu.Unlock()
	}
}

// Events returns a buffered channel of changes for streaming to the portal.
// When the buffer is full new changes are dropped rather than blocking the
// engine. Call cancel to stop; the channel is closed.
func (e *Engine) Events(buffer int) (<-chan Change, func()) {
	if buffer < 1 {
		buffer = 1
	}
	ch := make(chan Change, buffer)
	var mu sync.Mutex
	closed := false
	unsub := e.Subscribe(func(c Change) {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return
		}
		select {
		case ch <- c:
		default:
		}
	})
	return ch, func() {
		unsub()
		mu.Lock()
		defer mu.Unlock()
		if !closed {
			closed = true
			close(ch)
		}
	}
}

func (e *Engine) emit(changes []Change) {
	if len(changes) == 0 {
		return
	}
	e.subMu.RLock()
	fns := make([]func(Change), 0, len(e.subs))
	for _, fn := range e.subs {
		fns = append(fns, fn)
	}
	e.subMu.RUnlock()
	for _, c := range changes {
		for _, fn := range fns {
			fn(c)
		}
	}
}

// ---- raising -----------------------------------------------------------------

func sanitizeEvent(ev Event) (Event, error) {
	ev.Type = strings.TrimSpace(ev.Type)
	if ev.Type == "" || len(ev.Type) > 64 {
		return ev, fmt.Errorf("%w: type", ErrInvalidEvent)
	}
	ev.Title = clip(ev.Title, 200)
	ev.Body = clip(ev.Body, 2000)
	ev.Source = clip(ev.Source, 64)
	ev.DeviceID = clip(ev.DeviceID, 100)
	ev.DeviceClass = clip(ev.DeviceClass, 40)
	ev.Domain = strings.ToLower(strings.TrimSuffix(clip(ev.Domain, 253), "."))
	ev.Key = clip(ev.Key, 300)
	if ev.Count < 1 {
		ev.Count = 1
	}
	if len(ev.GroupIDs) > 20 {
		ev.GroupIDs = ev.GroupIDs[:20]
	}
	ev.GroupIDs = append([]string(nil), ev.GroupIDs...)
	if len(ev.Evidence) > 20 {
		ev.Evidence = ev.Evidence[:20]
	}
	ev.Evidence = append([]Evidence(nil), ev.Evidence...)
	for i := range ev.Evidence {
		ev.Evidence[i].Label = clip(ev.Evidence[i].Label, 60)
		ev.Evidence[i].Value = clip(ev.Evidence[i].Value, 300)
	}
	if u := ev.URL; u != "" && (len(u) > 300 || !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") || strings.ContainsAny(u, "\r\n\x00")) {
		ev.URL = ""
	}
	if ev.Severity != "" && !ev.Severity.Valid() {
		ev.Severity = ""
	}
	return ev, nil
}

// RaiseSync processes an event on the calling goroutine and returns the alarm
// it landed on (a new alarm, the alarm it was folded into, or the storm
// bundle that absorbed it). Prefer Raise on hot paths; RaiseSync suits API
// handlers such as "send a test notification".
func (e *Engine) RaiseSync(ev Event) (Alarm, error) {
	ev, err := sanitizeEvent(ev)
	if err != nil {
		return Alarm{}, err
	}
	var out Alarm
	e.mutate(func(now time.Time) ([]Change, error) {
		var changes []Change
		out, changes = e.processLocked(ev, now)
		return changes, nil
	})
	return out, nil
}

func (e *Engine) defaultKey(ev Event) string {
	return ev.Type + "|" + ev.DeviceID + "|" + ev.Domain
}

// processLocked is the dedupe, storm control and policy pipeline.
func (e *Engine) processLocked(ev Event, now time.Time) (Alarm, []Change) {
	if !ev.Time.IsZero() && !ev.Time.After(now) {
		now = ev.Time
	}
	t := e.typeOf(ev.Type)
	sev := ev.Severity
	if sev == "" {
		sev = t.DefaultSeverity
	}
	key := ev.Key
	if key == "" {
		key = e.defaultKey(ev)
	}
	if ev.DeviceID != "" {
		if _, ok := e.deviceSeen[ev.DeviceID]; !ok {
			e.deviceSeen[ev.DeviceID] = now
		}
	}
	// 1. Dedupe: the same key, still open, seen within the window.
	if e.dedupe > 0 {
		if a := e.live(e.byKey[key]); a != nil && a.State != StateResolved && now.Sub(a.LastSeen) <= e.dedupe {
			return e.foldLocked(a, ev, sev, t, now)
		}
	}
	// 2. Storm control.
	if e.stormN > 0 {
		bk := ev.Type + "|" + ev.DeviceID
		bkey := "bundle|" + bk
		if b := e.live(e.byKey[bkey]); b != nil && b.State != StateResolved && now.Sub(b.LastSeen) <= e.storm {
			return e.absorbLocked(b, ev, now)
		}
		recent := e.buckets[bk][:0:0]
		for _, m := range e.buckets[bk] {
			if now.Sub(m.at) <= e.storm && e.live(m.id) != nil {
				recent = append(recent, m)
			}
		}
		if len(recent) >= e.stormN {
			delete(e.buckets, bk)
			return e.bundleLocked(recent, bkey, ev, sev, t, now)
		}
		e.buckets[bk] = recent
	}
	// 3. A new alarm.
	a := e.newAlarmLocked(ev, t, sev, key, now)
	n := e.policyLocked(a, t, now)
	if e.stormN > 0 {
		bk := ev.Type + "|" + ev.DeviceID
		e.buckets[bk] = append(e.buckets[bk], member{a.ID, now})
	}
	return a.clone(), []Change{{Kind: ChangeRaised, Alarm: a.clone(), Notify: n}}
}

func (e *Engine) newAlarmLocked(ev Event, t AlarmType, sev Severity, key string, now time.Time) *Alarm {
	a := &Alarm{
		ID: "a" + e.newID(), Type: ev.Type, Severity: sev, Title: ev.Title, Body: ev.Body, Key: key, Source: ev.Source,
		DeviceID: ev.DeviceID, DeviceClass: ev.DeviceClass, GroupIDs: ev.GroupIDs, Domain: ev.Domain, Evidence: ev.Evidence,
		URL: ev.URL, State: StateNew, FirstSeen: now, LastSeen: now, Count: ev.Count,
	}
	if a.Title == "" {
		a.Title = t.Title
	}
	if a.URL == "" {
		a.URL = "/alarms/" + a.ID
	}
	e.alarms[a.ID] = a
	e.byKey[key] = a.ID
	return a
}

// policyLocked applies mute rules, learning mode and quiet hours to a new
// alarm and returns the notification decision.
func (e *Engine) policyLocked(a *Alarm, t AlarmType, now time.Time) Notify {
	var n Notify
	r := e.matchRule(a, now)
	switch {
	case t.Bypass:
		n = Notify{Send: true}
	case r != nil:
		a.State, a.MutedBy = StateMuted, r.ID
		n = Notify{Reason: "muted"}
	case e.learningLocked(a, t, now):
		a.RawSeverity, a.Severity, a.Learning = a.Severity, SeverityInfo, true
		n = Notify{Reason: "learning"}
	default:
		n = e.notifyLocked(a.Severity, now)
	}
	if n.Send {
		a.Notified = now
	}
	e.touch(a)
	return n
}

// notifyLocked is the quiet-hours part of the decision.
func (e *Engine) notifyLocked(sev Severity, now time.Time) Notify {
	if hold := e.prefs.QuietUntil(now, sev, e.locLocked()); !hold.IsZero() {
		return Notify{Send: true, HoldUntil: hold, Reason: "quiet-hours"}
	}
	return Notify{Send: true}
}

// learningLocked reports whether learning mode records the alarm as info.
func (e *Engine) learningLocked(a *Alarm, t AlarmType, now time.Time) bool {
	l := e.prefs.Learning
	if !l.Enabled || !t.LearningSuppresses {
		return false
	}
	if now.Before(e.installedAt.Add(l.Period.D())) {
		return true
	}
	if t.DeviceLearning && a.DeviceID != "" {
		if seen, ok := e.deviceSeen[a.DeviceID]; ok && now.Before(seen.Add(l.DevicePeriod.D())) {
			return true
		}
	}
	return false
}

// foldLocked folds a repeat into the existing alarm.
func (e *Engine) foldLocked(a *Alarm, ev Event, sev Severity, t AlarmType, now time.Time) (Alarm, []Change) {
	a.Count += ev.Count
	a.LastSeen = now
	if ev.Body != "" {
		a.Body = ev.Body
	}
	if ev.Title != "" {
		a.Title = ev.Title
	}
	if len(ev.Evidence) > 0 {
		a.Evidence = ev.Evidence
	}
	if ev.URL != "" {
		a.URL = ev.URL
	}
	kind, n := ChangeUpdated, Notify{}
	// A repeat with a higher severity re-notifies once; muted and learning
	// alarms stay quiet.
	if sev.Rank() > a.Severity.Rank() && a.State != StateMuted && !a.Learning && a.RawSeverity == "" {
		a.Severity = sev
		if a.State == StateAcknowledged {
			a.State, a.AckedAt = StateNew, time.Time{}
		}
		kind, n = ChangeEscalated, e.notifyLocked(sev, now)
		if n.Send {
			a.Notified = now
		}
	}
	e.touch(a)
	return a.clone(), []Change{{Kind: kind, Alarm: a.clone(), Notify: n}}
}

// absorbLocked counts an event into the active bundle without storing it.
func (e *Engine) absorbLocked(b *Alarm, ev Event, now time.Time) (Alarm, []Change) {
	b.Count += ev.Count
	b.LastSeen = now
	b.Title = bundleTitle(b.Count, e.typeOf(b.Type))
	b.Body = fmt.Sprintf("%d similar alerts.", b.Count)
	if len(b.Evidence) < 6 {
		b.Evidence = append(b.Evidence, Evidence{Label: "example", Value: ev.Title})
	}
	e.touch(b)
	return b.clone(), []Change{{Kind: ChangeUpdated, Alarm: b.clone()}}
}

func bundleTitle(n int, t AlarmType) string {
	return fmt.Sprintf("%d similar alerts: %s", n, t.Title)
}

// bundleLocked collapses the recent members and the new event into one bundle
// alarm, which notifies once.
func (e *Engine) bundleLocked(recent []member, bkey string, ev Event, sev Severity, t AlarmType, now time.Time) (Alarm, []Change) {
	total := ev.Count
	maxSev := sev
	var changes []Change
	b := &Alarm{
		ID: "a" + e.newID(), Type: ev.Type, Title: "", Key: bkey, Source: ev.Source, DeviceID: ev.DeviceID,
		DeviceClass: ev.DeviceClass, GroupIDs: ev.GroupIDs, Domain: ev.Domain, URL: "",
		State: StateNew, FirstSeen: now, LastSeen: now, Bundle: true,
	}
	b.URL = "/alarms/" + b.ID
	for _, m := range recent {
		c := e.live(m.id)
		total += c.Count
		if c.Severity.Rank() > maxSev.Rank() {
			maxSev = c.Severity
		}
		if c.FirstSeen.Before(b.FirstSeen) {
			b.FirstSeen = c.FirstSeen
		}
		if len(b.Evidence) < 5 {
			b.Evidence = append(b.Evidence, Evidence{Label: "example", Value: c.Title})
		}
		c.ParentID = b.ID
		e.children[b.ID] = append(e.children[b.ID], c.ID)
		e.touch(c)
		changes = append(changes, Change{Kind: ChangeUpdated, Alarm: c.clone()})
	}
	b.Severity, b.Count = maxSev, total
	b.Title = bundleTitle(total, t)
	b.Body = fmt.Sprintf("%d similar alerts.", total)
	e.alarms[b.ID] = b
	e.byKey[bkey] = b.ID
	n := e.policyLocked(b, t, now)
	changes = append(changes, Change{Kind: ChangeRaised, Alarm: b.clone(), Notify: n})
	return b.clone(), changes
}

// ---- device learning state ------------------------------------------------------

// NoteDeviceSeen records when a device was first seen, which starts its own
// learning period for types flagged DeviceLearning. The first call for a
// device wins; Raise also notes devices it sees.
func (e *Engine) NoteDeviceSeen(deviceID string, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.deviceSeen[deviceID]; !ok && deviceID != "" {
		e.deviceSeen[deviceID] = at
		e.dirty = true
	}
}

// LearningUntil is when the install learning period ends (the zero time when
// learning mode is off).
func (e *Engine) LearningUntil() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.prefs.Learning.Enabled {
		return time.Time{}
	}
	return e.installedAt.Add(e.prefs.Learning.Period.D())
}

// ---- preferences -------------------------------------------------------------------

// Preferences returns a copy of the current preferences.
func (e *Engine) Preferences() Preferences {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.prefs.Clone()
}

// SetPreferences validates and replaces the preferences.
func (e *Engine) SetPreferences(p Preferences) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return e.mutate(func(time.Time) ([]Change, error) {
		e.prefs = p.Clone()
		e.prefsUpdated = e.tick()
		return []Change{{Kind: ChangePrefs}}, nil
	})
}

// ---- periodic work -------------------------------------------------------------------

// Tick sweeps expired mutes and snoozes, ends stale storm buckets, prunes
// retention and saves when due. The worker calls it on its ticker; tests call
// it after advancing a fake clock.
func (e *Engine) Tick() {
	e.mu.Lock()
	now := e.clock.Now()
	e.nextSweep = time.Time{}
	changes := e.sweepLocked(now)
	e.pruneLocked(now)
	e.expireUndoLocked(now)
	if len(changes) > 0 {
		e.dirty = true
	}
	e.mu.Unlock()
	e.emit(changes)
	e.autosave()
}

// sweepLocked ends mutes whose rule expired or was removed and snoozes that
// ran out, returning the alarm to new. An alarm that is still active gets one
// fresh notification decision, so a mute that ends on a live problem is not
// silent.
func (e *Engine) sweepLocked(now time.Time) []Change {
	if now.Before(e.nextSweep) {
		return nil
	}
	e.nextSweep = now.Add(time.Second)
	var changes []Change
	for _, a := range e.sortedAlarms() {
		if a.Deleted || a.State != StateMuted {
			continue
		}
		expired := false
		if a.MutedBy == snoozeMarker {
			expired = !a.MutedUntil.IsZero() && !now.Before(a.MutedUntil)
		} else {
			r := e.rules[a.MutedBy]
			expired = r == nil || !r.Active(now)
		}
		if !expired {
			continue
		}
		cs := e.unmute(a)
		if e.dedupe > 0 && now.Sub(a.LastSeen) <= e.dedupe {
			cs[0].Notify = e.notifyLocked(a.Severity, now)
			if cs[0].Notify.Send {
				a.Notified = now
				cs[0].Alarm = a.clone()
			}
		}
		changes = append(changes, cs...)
	}
	// Forget storm buckets with no recent members.
	for k, ms := range e.buckets {
		if len(ms) == 0 || now.Sub(ms[len(ms)-1].at) > e.storm {
			delete(e.buckets, k)
		}
	}
	return changes
}

// unmute returns a muted alarm (and its bundle members) to the new state.
func (e *Engine) unmute(a *Alarm) []Change {
	var changes []Change
	e.family(a, func(x *Alarm) {
		if x.State == StateMuted {
			x.State, x.MutedBy, x.MutedUntil = StateNew, "", time.Time{}
			e.touch(x)
			changes = append(changes, Change{Kind: ChangeState, Alarm: x.clone()})
		}
	})
	return changes
}

// family applies fn to a and, for a bundle, to its live members.
func (e *Engine) family(a *Alarm, fn func(*Alarm)) {
	fn(a)
	if a.Bundle {
		for _, id := range e.children[a.ID] {
			if c := e.live(id); c != nil {
				fn(c)
			}
		}
	}
}

// muteAlarm mutes a (and its members) by rule or snooze.
func (e *Engine) muteAlarm(a *Alarm, by string, until time.Time, now time.Time, u *undoEntry) []Change {
	var changes []Change
	e.family(a, func(x *Alarm) {
		if x.State == StateResolved {
			return
		}
		u.record(x)
		x.State, x.MutedBy, x.MutedUntil = StateMuted, by, until
		e.touch(x)
		u.post[x.ID] = snapOf(x)
		changes = append(changes, Change{Kind: ChangeState, Alarm: x.clone()})
	})
	return changes
}
