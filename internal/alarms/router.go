// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Notification is what the Router hands to a channel: the same content for
// Web Push and ntfy.
type Notification struct {
	// ID is the alarm ID ("digest" for a digest).
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Title    string   `json:"title"`
	Body     string   `json:"body"`
	Severity Severity `json:"severity"`
	// URL is the portal route to open ("/alarms/a1b2"). Web Push carries it
	// as a path; the service worker opens only same-origin paths.
	URL string `json:"url"`
	// Click is URL made absolute with Preferences.PortalURL, for ntfy. Empty
	// when no portal URL is configured.
	Click string `json:"click,omitempty"`
	// Tag is the dedupe key: a device shows one notification per tag.
	Tag string `json:"tag"`
	// Digest marks a summary of several alarms.
	Digest bool `json:"digest,omitempty"`
}

// Payload size bounds. The Web Push limit is 4096 bytes including encryption
// overhead; these keep the JSON far below it.
const (
	maxPayloadTitle = 120
	maxPayloadBody  = 500
	maxPayloadURL   = 200
	maxPayloadTag   = 100
)

func plain(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// PushPayload is the small JSON the service worker receives:
// {title, body, url, tag, severity, id}. It is a few hundred bytes at most.
func (n Notification) PushPayload() []byte {
	type payload struct {
		Title    string   `json:"title"`
		Body     string   `json:"body"`
		URL      string   `json:"url"`
		Tag      string   `json:"tag"`
		Severity Severity `json:"severity"`
		ID       string   `json:"id"`
	}
	p := payload{plain(n.Title, maxPayloadTitle), plain(n.Body, maxPayloadBody), plain(n.URL, maxPayloadURL),
		plain(n.Tag, maxPayloadTag), n.Severity, plain(n.ID, 64)}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(p) // plain strings: cannot fail
	return bytes.TrimSpace(buf.Bytes())
}

// PushReport is a Pusher's account of one broadcast.
type PushReport struct {
	Subscribed int    // live subscriptions at the time
	Delivered  int    // accepted by a push service
	Gone       int    // subscriptions the push service retired
	Failed     int    // everything else
	Err        string // first error text, for the delivery log
}

// Pusher delivers a notification to every subscribed device. An error means
// the whole attempt failed before any device was tried.
type Pusher interface {
	Push(ctx context.Context, n Notification) (PushReport, error)
}

// NtfyPublisher publishes a notification to ntfy. Wrap an error in Permanent
// when retrying cannot help (bad credentials, bad topic).
type NtfyPublisher interface {
	Publish(ctx context.Context, n Notification) error
}

type permanentError struct{ err error }

func (p permanentError) Error() string { return p.err.Error() }
func (p permanentError) Unwrap() error { return p.err }

// Permanent marks err as not worth retrying.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanentError{err}
}

// IsPermanent reports whether err was marked with Permanent.
func IsPermanent(err error) bool {
	var p permanentError
	return errors.As(err, &p)
}

// Source is what the Router reads from the engine: current preferences and
// the type registry. *Engine implements it.
type Source interface {
	Preferences() Preferences
	Type(id string) (AlarmType, bool)
}

// DeliveryStatus is the state of one delivery in the log.
type DeliveryStatus string

// Delivery statuses.
const (
	DeliveryOK       DeliveryStatus = "ok"
	DeliveryRetrying DeliveryStatus = "retrying"
	DeliveryFailed   DeliveryStatus = "failed"  // gave up
	DeliverySkipped  DeliveryStatus = "skipped" // nothing to deliver to
)

// DeliveryRecord is one entry in the per-channel delivery log. A retried
// delivery is updated in place rather than duplicated.
type DeliveryRecord struct {
	Key      string         `json:"key"`
	AlarmID  string         `json:"alarm_id"`
	Channel  string         `json:"channel"`
	Title    string         `json:"title"`
	Severity Severity       `json:"severity"`
	Status   DeliveryStatus `json:"status"`
	Attempts int            `json:"attempts"`
	Error    string         `json:"error,omitempty"`
	Detail   string         `json:"detail,omitempty"`
	Time     time.Time      `json:"time"`
	// Next is when a retrying delivery is tried again.
	Next time.Time `json:"next,omitzero"`
}

// ChannelStatus summarizes a channel for the settings screen: when it last
// worked and the last error it hit. Show the error only when LastErrorAt is
// after LastOK.
type ChannelStatus struct {
	Channel     string    `json:"channel"`
	Configured  bool      `json:"configured"`
	LastOK      time.Time `json:"last_ok,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitzero"`
	OK          int       `json:"ok"`
	Failed      int       `json:"failed"`
}

// job is a pending retry.
type job struct {
	Key       string       `json:"key"`
	Channel   string       `json:"channel"`
	N         Notification `json:"n"`
	Attempt   int          `json:"attempt"`
	NotBefore time.Time    `json:"not_before"`
}

// digestItem is an alarm waiting for a digest or for the end of quiet hours.
type digestItem struct {
	N        Notification `json:"n"`
	Queued   time.Time    `json:"queued"`
	Due      time.Time    `json:"due"`
	Held     bool         `json:"held,omitempty"`
	WantPush bool         `json:"want_push,omitempty"`
	WantNtfy bool         `json:"want_ntfy,omitempty"`
}

// RouterOptions configures a Router.
type RouterOptions struct {
	// Source supplies preferences and the type registry (the Engine).
	Source Source
	// Pusher and Ntfy are the channels; nil means the channel is not set up.
	Pusher Pusher
	Ntfy   NtfyPublisher
	Clock  Clock // default SystemClock
	// Backoff lists the waits before each retry; its length is the number of
	// retries. Default 30s, 2m, 10m.
	Backoff []time.Duration
	// PollEvery is how often Run processes retries and the digest
	// (default 10 seconds).
	PollEvery time.Duration
	// MaxLog bounds the delivery log (default 500); LogAge drops older
	// records (default 14 days).
	MaxLog int
	LogAge time.Duration
	// Parallel bounds concurrent deliveries (default 8).
	Parallel int
	// Path and Codec persist the log, pending retries and the digest queue.
	// An empty Path keeps everything in memory.
	Path  string
	Codec Codec
}

// Router delivers the engine's notifications. It is safe for concurrent use.
type Router struct {
	src       Source
	pusher    Pusher
	ntfy      NtfyPublisher
	clock     Clock
	backoff   []time.Duration
	poll      time.Duration
	maxLog    int
	logAge    time.Duration
	path      string
	codec     Codec
	sem       chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	log       []*DeliveryRecord
	status    map[string]*ChannelStatus
	pending   []*job
	digest    []*digestItem
	digestSeq int
	dirty     bool
}

// NewRouter builds a Router. Subscribe it to the engine with
// eng.Subscribe(rt.Handle) and run rt.Run(ctx).
func NewRouter(o RouterOptions) *Router {
	r := &Router{src: o.Source, pusher: o.Pusher, ntfy: o.Ntfy, clock: o.Clock, backoff: o.Backoff, poll: o.PollEvery,
		maxLog: o.MaxLog, logAge: o.LogAge, path: o.Path, codec: o.Codec, status: map[string]*ChannelStatus{}}
	if r.clock == nil {
		r.clock = SystemClock{}
	}
	if r.codec == nil {
		r.codec = PlainCodec{}
	}
	if r.backoff == nil {
		r.backoff = []time.Duration{30 * time.Second, 2 * time.Minute, 10 * time.Minute}
	}
	if r.poll <= 0 {
		r.poll = 10 * time.Second
	}
	if r.maxLog <= 0 {
		r.maxLog = 500
	}
	if r.logAge <= 0 {
		r.logAge = 14 * 24 * time.Hour
	}
	par := o.Parallel
	if par <= 0 {
		par = 8
	}
	r.sem = make(chan struct{}, par)
	r.status[ChannelPush] = &ChannelStatus{Channel: ChannelPush, Configured: o.Pusher != nil}
	r.status[ChannelNtfy] = &ChannelStatus{Channel: ChannelNtfy, Configured: o.Ntfy != nil}
	return r
}

// Wait blocks until in-flight deliveries started by Handle finish.
func (r *Router) Wait() { r.wg.Wait() }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// notificationFor builds the notification for an alarm.
func notificationFor(a Alarm, p Preferences) Notification {
	body := a.Body
	if body == "" && len(a.Evidence) > 0 {
		parts := make([]string, 0, len(a.Evidence))
		for _, ev := range a.Evidence {
			parts = append(parts, ev.Label+": "+ev.Value)
		}
		body = strings.Join(parts, "; ")
	}
	n := Notification{ID: a.ID, Type: a.Type, Title: plain(a.Title, maxPayloadTitle), Body: plain(body, maxPayloadBody),
		Severity: a.Severity, URL: a.URL, Tag: a.Key}
	n.Click = clickURL(p.PortalURL, a.URL)
	return n
}

func clickURL(base, route string) string {
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + route
}

// plan decides which channels carry an alarm.
func (r *Router) plan(a Alarm, p Preferences) (pushOn, ntfyOn bool) {
	t, ok := r.src.Type(a.Type)
	if !ok {
		t = AlarmType{ID: a.Type, Channels: allChannels}
	}
	if !p.typeOn(a.Type, a.DeviceClass) {
		return false, false
	}
	chans := p.channelsFor(t)
	on := func(name string) bool {
		c, ok := p.Channels[name]
		return ok && c.Enabled && contains(chans, name) && a.Severity.AtLeast(c.MinSeverity)
	}
	return on(ChannelPush) && r.pusher != nil, on(ChannelNtfy) && r.ntfy != nil
}

// Handle consumes one engine Change. Subscribe it with eng.Subscribe(rt.Handle).
// It returns at once: delivery happens on goroutines (immediate alarms) or in
// the digest queue.
func (r *Router) Handle(c Change) {
	if !c.Notify.Send {
		return
	}
	switch c.Kind {
	case ChangeRaised, ChangeEscalated, ChangeState:
	default:
		return
	}
	p := r.src.Preferences()
	pushOn, ntfyOn := r.plan(c.Alarm, p)
	if !pushOn && !ntfyOn {
		return
	}
	n := notificationFor(c.Alarm, p)
	now := r.clock.Now()
	held := !c.Notify.HoldUntil.IsZero()
	if !held && (c.Alarm.Severity.AtLeast(p.ImmediateMin) || !p.Digest.Enabled) {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.sem <- struct{}{}
			defer func() { <-r.sem }()
			r.dispatch(context.Background(), n, pushOn, ntfyOn, p.NtfyAlways)
		}()
		return
	}
	it := &digestItem{N: n, Queued: now, Held: held, WantPush: pushOn, WantNtfy: ntfyOn}
	if held {
		it.Due = c.Notify.HoldUntil
	} else {
		it.Due = r.digestDue(p, now)
	}
	r.mu.Lock()
	r.digest = append(r.digest, it)
	r.dirty = true
	r.mu.Unlock()
}

func (r *Router) digestDue(p Preferences, now time.Time) time.Time {
	if p.Digest.At != "" {
		loc, err := p.Location()
		if err != nil {
			loc = time.UTC
		}
		return NextAt(now, p.Digest.At, loc)
	}
	return now.Add(p.Digest.Every.D())
}

// ---- delivery ---------------------------------------------------------------------

type outcome int

const (
	outOK   outcome = iota
	outNone         // nothing to deliver to, or permanently failed: no retry
	outFail         // failed; retry later
)

// dispatch delivers one notification: Web Push first, ntfy as the fallback when
// push delivered nothing, or alongside it when always is set (then the two run
// independently, so neither waits for the other).
func (r *Router) dispatch(ctx context.Context, n Notification, pushOn, ntfyOn, always bool) {
	var wg sync.WaitGroup
	if ntfyOn && (always || !pushOn) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.attempt(ctx, &job{Key: n.ID + "/" + ChannelNtfy, Channel: ChannelNtfy, N: n})
		}()
	}
	if pushOn {
		res := r.attempt(ctx, &job{Key: n.ID + "/" + ChannelPush, Channel: ChannelPush, N: n})
		if res != outOK && ntfyOn && !always {
			r.attempt(ctx, &job{Key: n.ID + "/" + ChannelNtfy, Channel: ChannelNtfy, N: n})
		}
	}
	wg.Wait()
}

// attempt tries one channel once, records the result and schedules a retry on a
// retryable failure.
func (r *Router) attempt(ctx context.Context, j *job) outcome {
	var out outcome
	var errText, detail string
	var err error
	switch j.Channel {
	case ChannelPush:
		var rep PushReport
		rep, err = r.pusher.Push(ctx, j.N)
		out, errText, detail = classifyPush(rep, err)
	default:
		err = r.ntfy.Publish(ctx, j.N)
		switch {
		case err == nil:
			out = outOK
		case IsPermanent(err):
			out, errText = outNone, err.Error()
		default:
			out, errText = outFail, err.Error()
		}
	}
	now := r.clock.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.recordFor(j, now)
	rec.Attempts = j.Attempt + 1
	rec.Time, rec.Error, rec.Detail, rec.Next = now, clip(errText, 300), clip(detail, 200), time.Time{}
	st := r.status[j.Channel]
	switch {
	case out == outOK:
		rec.Status = DeliveryOK
		st.LastOK, st.OK = now, st.OK+1
	case out == outNone && errText == "":
		rec.Status = DeliverySkipped
	default:
		st.LastError, st.LastErrorAt, st.Failed = clip(errText, 300), now, st.Failed+1
		if out == outFail && j.Attempt < len(r.backoff) {
			rec.Status = DeliveryRetrying
			rec.Next = now.Add(r.backoff[j.Attempt])
			r.pending = append(r.pending, &job{Key: j.Key, Channel: j.Channel, N: j.N, Attempt: j.Attempt + 1, NotBefore: rec.Next})
		} else {
			rec.Status = DeliveryFailed
		}
	}
	r.trimLocked(now)
	r.dirty = true
	return out
}

func classifyPush(rep PushReport, err error) (outcome, string, string) {
	detail := fmt.Sprintf("%d of %d delivered", rep.Delivered, rep.Subscribed)
	if rep.Gone > 0 {
		detail += fmt.Sprintf(", %d gone", rep.Gone)
	}
	switch {
	case err != nil:
		return outFail, err.Error(), ""
	case rep.Subscribed == 0:
		return outNone, "", "no push subscriptions"
	case rep.Delivered > 0:
		return outOK, "", detail
	case rep.Gone == rep.Subscribed:
		return outNone, "every push subscription is gone", detail
	}
	msg := rep.Err
	if msg == "" {
		msg = "push failed for every device"
	}
	return outFail, msg, detail
}

// recordFor finds or creates the log record for a job. Callers hold r.mu.
func (r *Router) recordFor(j *job, now time.Time) *DeliveryRecord {
	for i := len(r.log) - 1; i >= 0; i-- {
		if r.log[i].Key == j.Key {
			return r.log[i]
		}
	}
	rec := &DeliveryRecord{Key: j.Key, AlarmID: j.N.ID, Channel: j.Channel, Title: j.N.Title, Severity: j.N.Severity, Time: now}
	r.log = append(r.log, rec)
	return rec
}

func (r *Router) trimLocked(now time.Time) {
	cut := now.Add(-r.logAge)
	keep := r.log[:0]
	for _, rec := range r.log {
		if !rec.Time.Before(cut) {
			keep = append(keep, rec)
		}
	}
	r.log = keep
	if over := len(r.log) - r.maxLog; over > 0 {
		r.log = append([]*DeliveryRecord(nil), r.log[over:]...)
	}
}

// ---- periodic work ----------------------------------------------------------------

// Process runs everything due now: retries whose backoff elapsed, and the
// digest (or the alarms held through quiet hours). It saves state when a
// Path is set. Run calls it on a ticker; tests call it after advancing a fake
// clock.
func (r *Router) Process(ctx context.Context) {
	now := r.clock.Now()
	r.mu.Lock()
	var due []*job
	keep := r.pending[:0]
	for _, j := range r.pending {
		if j.NotBefore.After(now) {
			keep = append(keep, j)
		} else {
			due = append(due, j)
		}
	}
	r.pending = keep
	r.mu.Unlock()
	for _, j := range due {
		r.attempt(ctx, j)
	}
	r.flushDigest(ctx, now)
	r.mu.Lock()
	save := r.dirty && r.path != ""
	r.mu.Unlock()
	if save {
		r.Save()
	}
}

// flushDigest sends one summary of the queued alarms once the oldest is due.
// Alarms held through quiet hours wait for their own end time; the rest ride
// along with any digest that is sent.
func (r *Router) flushDigest(ctx context.Context, now time.Time) {
	r.mu.Lock()
	ready := false
	for _, it := range r.digest {
		if !it.Due.After(now) {
			ready = true
		}
	}
	if !ready {
		r.mu.Unlock()
		return
	}
	// A digest never wakes the household in quiet hours: when one falls due
	// inside a window that holds its highest severity, everything waits for
	// the window to end.
	p := r.src.Preferences()
	loc, err := p.Location()
	if err != nil {
		loc = time.UTC
	}
	top := SeverityInfo
	for _, it := range r.digest {
		if !it.Due.After(now) && it.N.Severity.Rank() > top.Rank() {
			top = it.N.Severity
		}
	}
	if hold := p.QuietUntil(now, top, loc); !hold.IsZero() {
		for _, it := range r.digest {
			if !it.Due.After(now) {
				it.Due, it.Held = hold, true
			}
		}
		r.dirty = true
		r.mu.Unlock()
		return
	}
	var send, keep []*digestItem
	for _, it := range r.digest {
		if it.Held && it.Due.After(now) {
			keep = append(keep, it)
		} else {
			send = append(send, it)
		}
	}
	r.digest = keep
	r.digestSeq++
	seq := r.digestSeq
	r.dirty = true
	r.mu.Unlock()

	n, pushOn, ntfyOn := buildDigest(send, seq)
	if !pushOn && !ntfyOn {
		return
	}
	pushOn = pushOn && r.pusher != nil
	ntfyOn = ntfyOn && r.ntfy != nil
	r.dispatch(ctx, n, pushOn, ntfyOn, p.NtfyAlways)
}

// buildDigest summarizes the items. A single item is sent as itself.
func buildDigest(items []*digestItem, seq int) (Notification, bool, bool) {
	pushOn, ntfyOn := false, false
	for _, it := range items {
		pushOn = pushOn || it.WantPush
		ntfyOn = ntfyOn || it.WantNtfy
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Queued.Before(items[j].Queued) })
	if len(items) == 1 {
		return items[0].N, pushOn, ntfyOn
	}
	n := Notification{ID: fmt.Sprintf("digest-%d", seq), Type: "digest", Digest: true, URL: "/alarms", Tag: "digest", Severity: SeverityLow}
	var lines []string
	for i, it := range items {
		if it.N.Severity.Rank() > n.Severity.Rank() {
			n.Severity = it.N.Severity
		}
		if i < 8 {
			lines = append(lines, "- "+it.N.Title)
		}
	}
	if len(items) > 8 {
		lines = append(lines, fmt.Sprintf("...and %d more", len(items)-8))
	}
	n.Title = fmt.Sprintf("Shepherd: %d alerts", len(items))
	n.Body = strings.Join(lines, "\n")
	n.Click = firstClick(items)
	return n, pushOn, ntfyOn
}

// firstClick derives the digest's absolute link from an item's Click by
// swapping its route for /alarms.
func firstClick(items []*digestItem) string {
	for _, it := range items {
		if it.N.Click != "" && strings.HasSuffix(it.N.Click, it.N.URL) {
			return strings.TrimSuffix(it.N.Click, it.N.URL) + "/alarms"
		}
	}
	return ""
}

// Run processes retries and the digest until ctx ends, then saves.
func (r *Router) Run(ctx context.Context) {
	tk := r.clock.NewTicker(r.poll)
	defer tk.Stop()
	for {
		select {
		case <-tk.C():
			r.Process(ctx)
		case <-ctx.Done():
			r.Wait()
			r.Save()
			return
		}
	}
}

// ---- views -------------------------------------------------------------------------

// Status returns the push and ntfy channel summaries.
func (r *Router) Status() []ChannelStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return []ChannelStatus{*r.status[ChannelPush], *r.status[ChannelNtfy]}
}

// Log returns the delivery log, newest first. channel filters by channel
// name ("" for all); limit <= 0 means 100.
func (r *Router) Log(channel string, limit int) []DeliveryRecord {
	if limit <= 0 {
		limit = 100
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []DeliveryRecord
	for i := len(r.log) - 1; i >= 0 && len(out) < limit; i-- {
		if channel == "" || r.log[i].Channel == channel {
			out = append(out, *r.log[i])
		}
	}
	return out
}

// Pending reports how many retries and digest alarms are waiting.
func (r *Router) Pending() (retries, digestItems int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending), len(r.digest)
}

// ---- persistence ----------------------------------------------------------------------

type routerState struct {
	Version   int                       `json:"version"`
	Log       []*DeliveryRecord         `json:"log"`
	Status    map[string]*ChannelStatus `json:"status"`
	Pending   []*job                    `json:"pending"`
	Digest    []*digestItem             `json:"digest"`
	DigestSeq int                       `json:"digest_seq"`
}

// Save writes the delivery log, channel status, pending retries and digest
// queue to Options.Path (atomic, mode 0600). It is a no-op without a Path.
func (r *Router) Save() error {
	if r.path == "" {
		return nil
	}
	r.mu.Lock()
	st := routerState{Version: snapshotVersion, Log: r.log, Status: r.status, Pending: r.pending, Digest: r.digest, DigestSeq: r.digestSeq}
	r.dirty = false
	// Marshal under the lock: the state shares pointers with live records.
	plainJSON, _ := json.MarshalIndent(st, "", " ")
	r.mu.Unlock()
	data, err := r.codec.Encode(plainJSON)
	if err == nil {
		err = writeFileAtomic(r.path, data)
	} else {
		err = fmt.Errorf("alarms: encode: %w", err)
	}
	if err != nil {
		r.mu.Lock()
		r.dirty = true
		r.mu.Unlock()
	}
	return err
}

// Load restores state saved by Save. A missing file is not an error.
func (r *Router) Load() error {
	if r.path == "" {
		return nil
	}
	var st routerState
	if err := loadJSON(r.codec, r.path, &st); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if st.Version != snapshotVersion {
		return fmt.Errorf("%w: version %d", ErrBadSnapshot, st.Version)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log, r.pending, r.digest, r.digestSeq = st.Log, st.Pending, st.Digest, st.DigestSeq
	for name, s := range st.Status {
		if cur, ok := r.status[name]; ok && s != nil {
			s.Configured = cur.Configured
			r.status[name] = s
		}
	}
	return nil
}

// DefaultRouterPath is where wiring code conventionally keeps the router
// state, next to the engine's files.
func DefaultRouterPath(dir string) string { return filepath.Join(dir, DeliveriesFile) }
