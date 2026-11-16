// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hub runs a backend for the portal (docs/BACKENDS.md): it polls
// what the backend can report, feeds Shepherd's own stores, keeps the
// latest of each for the screen, and is the one place writes pass
// through, so every change is validated, logged and audited the same way.
//
// Reading and writing are separate. The poll only ever reads. A write is
// a deliberate call from the portal, refused up front when the connection
// is read-only, and recorded in an audit trail whether it worked or not.
package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/backends"
	"shepherd/internal/dnsengine"
)

const (
	// DefaultInterval between polls.
	DefaultInterval = 30 * time.Second
	// flowOverlap is how far back each poll reaches past the newest flow
	// already seen, because a product can report a flow a little late.
	flowOverlap = time.Minute
	// firstFlowWindow is how far back the very first poll reaches.
	firstFlowWindow = 10 * time.Minute
	flowPageSize    = 500
	maxFlowPages    = 10
	recentFlows     = 200
	maxAudit        = 200
	// firstAlarmWindow limits which existing alarms are raised when the
	// hub starts, so connecting does not announce a month of old ones.
	firstAlarmWindow = 24 * time.Hour
	alarmPage        = 100
)

// Options configures a Hub. Backend is required.
type Options struct {
	Backend  backends.Backend
	Interval time.Duration

	// FlowSink receives each new flow as a history entry, oldest first.
	// It is the DNS query log's Add, so flows reach the live view and the
	// encrypted history like any lookup. Nil drops them.
	FlowSink func(dnsengine.Entry)
	// AlarmSink receives the backend's alarms. It is the alarm engine's
	// Raise. Nil drops them.
	AlarmSink func(alarms.Event) bool
	// Resolve maps a device's MAC (and address, as a fallback) to the
	// registry's device ID, or "" when it is not known.
	Resolve func(mac, ip string) string

	// StatePath, when set, keeps the newest flow's time across restarts, so
	// a restart resumes where it stopped instead of ingesting the last few
	// minutes a second time. Empty keeps nothing.
	StatePath string

	Now  func() time.Time
	Logf func(string, ...any)
}

// Status is what the portal shows about the hub.
type Status struct {
	Name string `json:"name"`
	// LastPoll is when a poll last read something, nil until one has.
	LastPoll *time.Time `json:"last_poll,omitempty"`
	// Errors maps a resource ("flows", "rules") to its last failure, for
	// the resources whose last read failed. Empty when all is well.
	Errors map[string]string `json:"errors,omitempty"`
	// NeedsToken is true when the credential was refused.
	NeedsToken bool `json:"needs_token"`
}

// AuditEntry records one write attempt.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	// Error is empty when the write succeeded.
	Error string `json:"error,omitempty"`
}

// Snapshot is the latest of everything, copied for the caller.
type Snapshot struct {
	Name         string                `json:"name"`
	ReadOnly     bool                  `json:"read_only"`
	Capabilities []backends.Capability `json:"capabilities"`
	Status       Status                `json:"status"`
	Devices      []backends.Device     `json:"devices"`
	Rules        []backends.Rule       `json:"rules"`
	Alarms       []backends.Alarm      `json:"alarms"`
	Flows        []backends.Flow       `json:"flows"`
	Audit        []AuditEntry          `json:"audit"`
}

// Hub polls one backend.
type Hub struct {
	o Options

	mu       sync.Mutex
	devices  []backends.Device
	rules    []backends.Rule
	alarms   []backends.Alarm
	flows    []backends.Flow // newest first, capped
	audit    []AuditEntry    // newest first, capped
	errs     map[string]error
	lastPoll *time.Time

	totals     map[string]Total
	lastFlow   time.Time
	resumed    bool // lastFlow came from disk: no overlap, the seen set is empty
	seenFlows  map[string]time.Time
	seenAlarms map[string]bool
	started    time.Time
}

// New returns a Hub. Nothing is read until Run or Refresh.
func New(o Options) *Hub {
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	h := &Hub{o: o, errs: map[string]error{}, seenFlows: map[string]time.Time{}, totals: map[string]Total{}, seenAlarms: map[string]bool{}, started: o.Now()}
	h.loadState()
	return h
}

type state struct {
	LastFlow time.Time `json:"last_flow"`
}

func (h *Hub) loadState() {
	if h.o.StatePath == "" {
		return
	}
	b, err := os.ReadFile(h.o.StatePath)
	if err != nil {
		return
	}
	var st state
	if json.Unmarshal(b, &st) == nil && !st.LastFlow.IsZero() && st.LastFlow.Before(h.o.Now().Add(time.Minute)) {
		h.lastFlow, h.resumed = st.LastFlow, true
	}
}

func (h *Hub) saveState() {
	if h.o.StatePath == "" {
		return
	}
	h.mu.Lock()
	st := state{LastFlow: h.lastFlow}
	h.mu.Unlock()
	b, _ := json.Marshal(st)
	tmp := h.o.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		h.o.Logf("backend %s: keeping state: %v", h.o.Backend.Name(), err)
		return
	}
	if err := os.Rename(tmp, h.o.StatePath); err != nil {
		h.o.Logf("backend %s: keeping state: %v", h.o.Backend.Name(), err)
	}
}

// Run polls until ctx ends.
func (h *Hub) Run(ctx context.Context) {
	h.Refresh(ctx)
	t := time.NewTicker(h.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.Refresh(ctx)
		}
	}
}

// Refresh reads everything the backend supports, once. A resource that
// fails does not stop the others.
func (h *Hub) Refresh(ctx context.Context) {
	b := h.o.Backend
	ok := false
	record := func(res string, err error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if err == nil {
			delete(h.errs, res)
			ok = true
			return
		}
		h.errs[res] = err
	}
	if r, is := b.(backends.DeviceReader); is {
		d, err := r.Devices(ctx)
		if err == nil {
			h.mu.Lock()
			h.devices = d
			h.mu.Unlock()
		}
		record("devices", err)
	}
	if _, is := b.(backends.RuleManager); is {
		record("rules", h.refreshRules(ctx))
	}
	if r, is := b.(backends.AlarmReader); is {
		record("alarms", h.pollAlarms(ctx, r))
	}
	if r, is := b.(backends.FlowReader); is {
		record("flows", h.pollFlows(ctx, r))
	}
	h.mu.Lock()
	if ok {
		now := h.o.Now()
		h.lastPoll = &now
	}
	h.mu.Unlock()
}

func (h *Hub) refreshRules(ctx context.Context) error {
	rm, ok := h.o.Backend.(backends.RuleManager)
	if !ok {
		return nil
	}
	rules, err := rm.Rules(ctx)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.rules = rules
	h.mu.Unlock()
	return nil
}

// ---- flows ------------------------------------------------------------------

func flowKey(f backends.Flow) string {
	return fmt.Sprintf("%d|%s|%s|%s|%s|%t|%d|%d", f.Time.UnixNano(), f.DeviceMAC, f.Domain, f.RemoteIP, f.Protocol, f.Blocked, f.Download, f.Upload)
}

func (h *Hub) pollFlows(ctx context.Context, r backends.FlowReader) error {
	h.mu.Lock()
	from := h.lastFlow.Add(-flowOverlap)
	switch {
	case h.lastFlow.IsZero():
		from = h.o.Now().Add(-firstFlowWindow)
	case h.resumed:
		// Nothing remembers which flows were already ingested, so reaching
		// back by the overlap would ingest them again.
		from = h.lastFlow
	}
	h.mu.Unlock()

	var got []backends.Flow
	cursor := ""
	for i := 0; i < maxFlowPages; i++ {
		page, err := r.Flows(ctx, backends.FlowQuery{From: from, To: h.o.Now(), Limit: flowPageSize, Cursor: cursor})
		if err != nil {
			return err
		}
		got = append(got, page.Flows...)
		if page.Next == "" || len(page.Flows) == 0 {
			break
		}
		cursor = page.Next
	}
	// Oldest first, so the history and the live view number them in order.
	sort.SliceStable(got, func(i, j int) bool { return got[i].Time.Before(got[j].Time) })

	h.mu.Lock()
	h.resumed = false
	var fresh []backends.Flow
	for _, f := range got {
		k := flowKey(f)
		if _, dup := h.seenFlows[k]; dup {
			continue
		}
		h.seenFlows[k] = f.Time
		fresh = append(fresh, f)
		// Only traffic since the hub started is counted, so the first
		// poll's backfill is not mistaken for a burst that just happened.
		if f.DeviceMAC != "" && !f.Blocked && !f.Time.Before(h.started) {
			t := h.totals[f.DeviceMAC]
			t.Down += f.Download
			t.Up += f.Upload
			h.totals[f.DeviceMAC] = t
		}
		if f.Time.After(h.lastFlow) {
			h.lastFlow = f.Time
		}
	}
	// Forget keys older than the overlap can ever reach.
	for k, t := range h.seenFlows {
		if h.lastFlow.Sub(t) > 3*flowOverlap {
			delete(h.seenFlows, k)
		}
	}
	for _, f := range fresh {
		h.flows = append([]backends.Flow{f}, h.flows...)
	}
	if len(h.flows) > recentFlows {
		h.flows = h.flows[:recentFlows]
	}
	h.mu.Unlock()

	if h.o.FlowSink != nil {
		for _, f := range fresh {
			h.o.FlowSink(h.flowEntry(f))
		}
	}
	if len(fresh) > 0 {
		h.saveState()
	}
	return nil
}

// flowEntry turns a flow into a history entry, so it shows beside the
// lookups Shepherd answers itself. The type FLOW tells them apart.
func (h *Hub) flowEntry(f backends.Flow) dnsengine.Entry {
	name := f.Domain
	if name == "" {
		name = f.RemoteIP
	}
	e := dnsengine.Entry{
		Time: f.Time, Client: f.DeviceIP, Device: f.Device, Name: name,
		Type: "FLOW", Action: "allowed", Upstream: h.o.Backend.Name(),
	}
	if f.Blocked {
		e.Action, e.Reason = "blocked", h.o.Backend.Name()
	}
	if h.o.Resolve != nil {
		e.DeviceID = h.o.Resolve(f.DeviceMAC, f.DeviceIP)
	}
	return e
}

// ---- alarms -----------------------------------------------------------------

func (h *Hub) pollAlarms(ctx context.Context, r backends.AlarmReader) error {
	page, err := r.Alarms(ctx, backends.AlarmQuery{ActiveOnly: true, Limit: alarmPage})
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.alarms = page.Alarms
	var fresh []backends.Alarm
	for _, a := range page.Alarms {
		k := a.Box + "|" + a.ID
		if h.seenAlarms[k] {
			continue
		}
		h.seenAlarms[k] = true
		// Anything older than the window is shown but not announced.
		if a.Time.Before(h.started.Add(-firstAlarmWindow)) {
			continue
		}
		fresh = append(fresh, a)
	}
	h.mu.Unlock()
	if h.o.AlarmSink == nil {
		return nil
	}
	name := h.o.Backend.Name()
	for _, a := range fresh {
		ev := alarms.Event{
			Type: alarms.TypeBackendAlarm, Title: strings.ToUpper(name[:1]) + name[1:] + ": " + trunc(a.Message, 80),
			Body: a.Message, Key: "backend|" + name + "|" + a.Box + "|" + a.ID + "|", Source: name, Time: a.Time,
		}
		if h.o.Resolve != nil {
			ev.DeviceID = h.o.Resolve(a.DeviceMAC, "")
		}
		h.o.AlarmSink(ev)
	}
	return nil
}

func trunc(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// ---- reading for the portal --------------------------------------------------

// Total is the bytes one device has moved since the hub started, as the
// flows it ingested add up.
type Total struct {
	Down, Up uint64
}

// Totals returns the running per-device byte counts, keyed by MAC, of
// traffic since the hub started. They only grow, which is what makes them a counter a bandwidth reader can
// difference exactly: the backend's own per-device figures are a rolling
// 24 hours and cannot be.
func (h *Hub) Totals() map[string]Total {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]Total, len(h.totals))
	for k, v := range h.totals {
		out[k] = v
	}
	return out
}

// Snapshot returns the latest of everything.
func (h *Hub) Snapshot() Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := Status{Name: h.o.Backend.Name(), LastPoll: h.lastPoll}
	if len(h.errs) > 0 {
		st.Errors = make(map[string]string, len(h.errs))
		for k, v := range h.errs {
			st.Errors[k] = v.Error()
			if errors.Is(v, backends.ErrAuth) {
				st.NeedsToken = true
			}
		}
	}
	return Snapshot{
		Name: h.o.Backend.Name(), ReadOnly: h.o.Backend.ReadOnly(),
		Capabilities: backends.Capabilities(h.o.Backend), Status: st,
		Devices: append([]backends.Device(nil), h.devices...),
		Rules:   append([]backends.Rule(nil), h.rules...),
		Alarms:  append([]backends.Alarm(nil), h.alarms...),
		Flows:   append([]backends.Flow(nil), h.flows...),
		Audit:   append([]AuditEntry(nil), h.audit...),
	}
}

// ---- writing ----------------------------------------------------------------

// RulePreview says what a rule would do before anything is sent.
type RulePreview struct {
	Summary string `json:"summary"`
	// NetworkWide is true when the rule applies to every device.
	NetworkWide bool `json:"network_wide"`
	// Device names the device a scoped rule applies to, when known.
	Device string `json:"device,omitempty"`
}

// PreviewRule validates spec and describes it. It sends nothing.
func (h *Hub) PreviewRule(spec backends.RuleSpec) (RulePreview, error) {
	if _, ok := h.o.Backend.(backends.RuleManager); !ok {
		return RulePreview{}, backends.ErrInvalid
	}
	if err := spec.Validate(); err != nil {
		return RulePreview{}, err
	}
	p := RulePreview{NetworkWide: spec.ScopeType == ""}
	where := "every device on the network"
	switch spec.ScopeType {
	case "":
	case "device":
		where = "one device"
		mac := strings.ToLower(strings.NewReplacer(":", "", "-", "").Replace(spec.Scope))
		h.mu.Lock()
		for _, d := range h.devices {
			if d.MAC == mac {
				p.Device = d.Name
				where = d.Name
				break
			}
		}
		h.mu.Unlock()
	default:
		where = "the " + spec.ScopeType + " " + strings.TrimSpace(spec.Scope)
	}
	verb := "Block"
	if spec.Action == "allow" {
		verb = "Allow"
	}
	how := ""
	switch spec.TargetType {
	case "domain", "category", "app", "targetlist":
		how = ", name lookups only"
		if spec.BlockConnections {
			how = ", lookups and connections"
		}
	}
	p.Summary = fmt.Sprintf("%s %s %s for %s%s", verb, spec.TargetType, strings.TrimSpace(spec.Target), where, how)
	return p, nil
}

func (h *Hub) record(action, target string, err error) {
	e := AuditEntry{Time: h.o.Now(), Action: action, Target: target}
	if err != nil {
		e.Error = err.Error()
	}
	h.mu.Lock()
	h.audit = append([]AuditEntry{e}, h.audit...)
	if len(h.audit) > maxAudit {
		h.audit = h.audit[:maxAudit]
	}
	h.mu.Unlock()
	if err != nil {
		h.o.Logf("backend %s: %s %s: %v", h.o.Backend.Name(), action, target, err)
	} else {
		h.o.Logf("backend %s: %s %s", h.o.Backend.Name(), action, target)
	}
}

var errUnsupported = fmt.Errorf("%w: this backend cannot do that", backends.ErrInvalid)

// CreateRule creates a rule and refreshes the rule list.
func (h *Hub) CreateRule(ctx context.Context, spec backends.RuleSpec) (backends.Rule, error) {
	rm, ok := h.o.Backend.(backends.RuleManager)
	if !ok {
		return backends.Rule{}, errUnsupported
	}
	rule, err := rm.CreateRule(ctx, spec)
	h.record("create rule", fmt.Sprintf("%s %s %s", spec.Action, spec.TargetType, spec.Target), err)
	if err == nil {
		_ = h.refreshRules(ctx)
	}
	return rule, err
}

// SetRulePaused pauses or resumes a rule.
func (h *Hub) SetRulePaused(ctx context.Context, id string, paused bool) error {
	rm, ok := h.o.Backend.(backends.RuleManager)
	if !ok {
		return errUnsupported
	}
	err := rm.SetRulePaused(ctx, id, paused)
	verb := "resume rule"
	if paused {
		verb = "pause rule"
	}
	h.record(verb, id, err)
	if err == nil {
		_ = h.refreshRules(ctx)
	}
	return err
}

// DeleteRule deletes a rule.
func (h *Hub) DeleteRule(ctx context.Context, id string) error {
	rm, ok := h.o.Backend.(backends.RuleManager)
	if !ok {
		return errUnsupported
	}
	err := rm.DeleteRule(ctx, id)
	h.record("delete rule", id, err)
	if err == nil {
		_ = h.refreshRules(ctx)
	}
	return err
}

// RenameDevice renames a device on the backend.
func (h *Hub) RenameDevice(ctx context.Context, ref backends.DeviceRef, name string) error {
	rn, ok := h.o.Backend.(backends.DeviceRenamer)
	if !ok {
		return errUnsupported
	}
	err := rn.RenameDevice(ctx, ref, name)
	h.record("rename device", ref.Native+" to "+name, err)
	if err == nil {
		if dr, is := h.o.Backend.(backends.DeviceReader); is {
			if d, derr := dr.Devices(ctx); derr == nil {
				h.mu.Lock()
				h.devices = d
				h.mu.Unlock()
			}
		}
	}
	return err
}

// DismissAlarm removes an alarm on the backend.
func (h *Hub) DismissAlarm(ctx context.Context, ref backends.AlarmRef) error {
	ad, ok := h.o.Backend.(backends.AlarmDismisser)
	if !ok {
		return errUnsupported
	}
	err := ad.DismissAlarm(ctx, ref)
	h.record("dismiss alarm", ref.Box+"/"+ref.ID, err)
	if err == nil {
		h.mu.Lock()
		kept := h.alarms[:0]
		for _, a := range h.alarms {
			if a.Box != ref.Box || a.ID != ref.ID {
				kept = append(kept, a)
			}
		}
		h.alarms = kept
		h.mu.Unlock()
	}
	return err
}
