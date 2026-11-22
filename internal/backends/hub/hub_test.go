// SPDX-License-Identifier: AGPL-3.0-or-later

package hub

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/backends"
	"shepherd/internal/dnsengine"
)

var ctx = context.Background()

// fake is a backend that implements every ability and records writes.
type fake struct {
	mu       sync.Mutex
	ro       bool
	flows    []backends.Flow // served newest first, whatever the query
	pages    int             // when > 0, flows are served this many per page
	alarms   []backends.Alarm
	rules    []backends.Rule
	devices  []backends.Device
	flowErr  error
	devErr   error
	writeErr error
	queries  []backends.FlowQuery
	calls    []string
}

func (f *fake) Name() string   { return "fakewall" }
func (f *fake) ReadOnly() bool { return f.ro }

func (f *fake) Devices(context.Context) ([]backends.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.devices, f.devErr
}

func (f *fake) Flows(_ context.Context, q backends.FlowQuery) (backends.FlowPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	if f.flowErr != nil {
		return backends.FlowPage{}, f.flowErr
	}
	if f.pages <= 0 {
		return backends.FlowPage{Flows: f.flows}, nil
	}
	start := 0
	if q.Cursor != "" {
		for i, fl := range f.flows {
			if fl.Domain == q.Cursor {
				start = i
			}
		}
	}
	end := start + f.pages
	if end >= len(f.flows) {
		return backends.FlowPage{Flows: f.flows[start:]}, nil
	}
	return backends.FlowPage{Flows: f.flows[start:end], Next: f.flows[end].Domain}, nil
}

func (f *fake) Alarms(context.Context, backends.AlarmQuery) (backends.AlarmPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return backends.AlarmPage{Alarms: append([]backends.Alarm(nil), f.alarms...)}, nil
}

func (f *fake) Rules(context.Context) ([]backends.Rule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]backends.Rule(nil), f.rules...), nil
}

func (f *fake) CreateRule(_ context.Context, s backends.RuleSpec) (backends.Rule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "create "+s.Target)
	if f.writeErr != nil {
		return backends.Rule{}, f.writeErr
	}
	r := backends.Rule{ID: "new", Action: s.Action, TargetType: s.TargetType, Target: s.Target}
	f.rules = append(f.rules, r)
	return r, nil
}

func (f *fake) SetRulePaused(_ context.Context, id string, paused bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "pause "+id)
	if f.writeErr == nil {
		for i := range f.rules {
			if f.rules[i].ID == id {
				f.rules[i].Paused = paused
			}
		}
	}
	return f.writeErr
}

func (f *fake) DeleteRule(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "delete "+id)
	if f.writeErr == nil {
		f.rules = nil
	}
	return f.writeErr
}

func (f *fake) RenameDevice(_ context.Context, d backends.DeviceRef, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "rename "+name)
	if f.writeErr == nil && len(f.devices) > 0 {
		f.devices[0].Name = name
	}
	return f.writeErr
}

func (f *fake) BlockClient(_ context.Context, d backends.DeviceRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "block "+d.Native)
	return f.writeErr
}

func (f *fake) UnblockClient(_ context.Context, d backends.DeviceRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "unblock "+d.Native)
	return f.writeErr
}

func (f *fake) DismissAlarm(_ context.Context, a backends.AlarmRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "dismiss "+a.ID)
	return f.writeErr
}

type sinks struct {
	mu      sync.Mutex
	entries []dnsengine.Entry
	events  []alarms.Event
}

func (s *sinks) flow(e dnsengine.Entry) { s.mu.Lock(); s.entries = append(s.entries, e); s.mu.Unlock() }
func (s *sinks) alarm(e alarms.Event) bool {
	s.mu.Lock()
	s.events = append(s.events, e)
	s.mu.Unlock()
	return true
}

func newHub(t *testing.T, f *fake, s *sinks, now *time.Time) *Hub {
	t.Helper()
	return New(Options{
		Backend: f, FlowSink: s.flow, AlarmSink: s.alarm,
		Resolve: func(mac, ip string) string {
			if mac == "02005e000001" {
				return "dev-tv"
			}
			return ""
		},
		Now: func() time.Time { return *now },
	})
}

func flow(sec int, domain string, blocked bool, down, up uint64) backends.Flow {
	return backends.Flow{
		Time: time.Unix(int64(sec), 0), DeviceMAC: "02005e000001", Device: "TV", DeviceIP: "192.0.2.5",
		Domain: domain, RemoteIP: "198.51.100.7", Protocol: "tcp", Outbound: true, Blocked: blocked, Download: down, Upload: up,
	}
}

func TestFlowsBecomeHistoryEntriesOldestFirstWithTheDeviceResolved(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{flows: []backends.Flow{flow(990, "b.example", true, 0, 0), flow(980, "a.example", false, 100, 10)}}
	s := &sinks{}
	h := newHub(t, f, s, &now)
	h.Refresh(ctx)
	if len(s.entries) != 2 {
		t.Fatalf("entries = %+v", s.entries)
	}
	a, b := s.entries[0], s.entries[1]
	if a.Name != "a.example" || a.Action != "allowed" || a.Type != "FLOW" || a.Client != "192.0.2.5" || a.Device != "TV" || a.DeviceID != "dev-tv" || a.Upstream != "fakewall" {
		t.Fatalf("a = %+v", a)
	}
	if b.Name != "b.example" || b.Action != "blocked" || b.Reason != "fakewall" {
		t.Fatalf("b = %+v", b)
	}
	// A flow with no domain is shown by address.
	f.flows = []backends.Flow{flow(995, "", false, 1, 1)}
	h.Refresh(ctx)
	if got := s.entries[len(s.entries)-1].Name; got != "198.51.100.7" {
		t.Fatalf("name = %q", got)
	}
}

func TestAFlowSeenInTwoPollsIsIngestedOnce(t *testing.T) {
	now := time.Unix(980, 0)
	f := &fake{flows: []backends.Flow{flow(990, "a.example", false, 5, 5)}}
	s := &sinks{}
	h := newHub(t, f, s, &now)
	now = time.Unix(1000, 0)
	h.Refresh(ctx)
	now = now.Add(30 * time.Second)
	h.Refresh(ctx) // the overlap serves the same flow again
	if len(s.entries) != 1 {
		t.Fatalf("%d entries, want 1: %+v", len(s.entries), s.entries)
	}
	if got := h.Totals()["02005e000001"]; got.Down != 5 || got.Up != 5 {
		t.Fatalf("totals counted a repeat: %+v", got)
	}
	// The second poll reaches back by the overlap, not to the beginning.
	last := f.queries[len(f.queries)-1]
	if want := time.Unix(990, 0).Add(-flowOverlap); !last.From.Equal(want) {
		t.Fatalf("from = %v, want %v", last.From, want)
	}
	if first := f.queries[0]; !first.From.Equal(time.Unix(1000, 0).Add(-firstFlowWindow)) {
		t.Fatalf("first from = %v", first.From)
	}
}

func TestTotalsOnlyGrowAndIgnoreBlockedFlowsAndBackfill(t *testing.T) {
	now := time.Unix(900, 0)
	f := &fake{flows: []backends.Flow{flow(990, "x", true, 999, 999), flow(980, "y", false, 100, 10), flow(800, "old", false, 7777, 7777)}}
	h := newHub(t, f, &sinks{}, &now)
	now = time.Unix(1000, 0)
	h.Refresh(ctx)
	f.flows = []backends.Flow{flow(1010, "z", false, 50, 5)}
	now = now.Add(time.Minute)
	h.Refresh(ctx)
	if got := h.Totals()["02005e000001"]; got.Down != 150 || got.Up != 15 {
		t.Fatalf("totals = %+v", got)
	}
}

func TestFlowsPageUntilTheLastPage(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{pages: 2}
	for i := 0; i < 5; i++ {
		f.flows = append(f.flows, flow(990-i, string(rune('a'+i))+".example", false, 1, 1))
	}
	s := &sinks{}
	newHub(t, f, s, &now).Refresh(ctx)
	if len(s.entries) != 5 || len(f.queries) != 3 {
		t.Fatalf("%d entries over %d requests", len(s.entries), len(f.queries))
	}
}

func TestAFailingResourceDoesNotStopTheOthers(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{flowErr: backends.ErrAuth, devices: []backends.Device{{MAC: "02005e000001", Name: "TV"}},
		rules: []backends.Rule{{ID: "r1"}}}
	h := newHub(t, f, &sinks{}, &now)
	h.Refresh(ctx)
	snap := h.Snapshot()
	if len(snap.Devices) != 1 || len(snap.Rules) != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if snap.Status.Errors["flows"] == "" || !snap.Status.NeedsToken || snap.Status.LastPoll == nil {
		t.Fatalf("status = %+v", snap.Status)
	}
	f.flowErr = nil
	f.flows = nil
	h.Refresh(ctx)
	if st := h.Snapshot().Status; len(st.Errors) != 0 || st.NeedsToken {
		t.Fatalf("status after recovery = %+v", st)
	}
}

func TestEverythingFailingLeavesNoLastPoll(t *testing.T) {
	h := New(Options{Backend: failing{}})
	h.Refresh(ctx)
	if st := h.Snapshot().Status; st.LastPoll != nil || len(st.Errors) == 0 {
		t.Fatalf("status = %+v", st)
	}
}

type failing struct{ stubBackend }

func (failing) Devices(context.Context) ([]backends.Device, error) { return nil, errors.New("down") }

func TestAlarmsAreRaisedOnceAndOldOnesAreOnlyShown(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	f := &fake{alarms: []backends.Alarm{
		{ID: "1", Box: "b", Time: now.Add(-time.Hour), Type: "New Device", Message: "Found a new device iPhone", DeviceMAC: "02005e000001"},
		{ID: "2", Box: "b", Time: now.Add(-72 * time.Hour), Message: "Old news"},
	}}
	s := &sinks{}
	h := newHub(t, f, s, &now)
	h.Refresh(ctx)
	h.Refresh(ctx)
	if len(s.events) != 1 {
		t.Fatalf("events = %+v", s.events)
	}
	ev := s.events[0]
	if ev.Type != alarms.TypeBackendAlarm || ev.Source != "fakewall" || ev.DeviceID != "dev-tv" ||
		!strings.HasPrefix(ev.Title, "Fakewall: Found a new device") || !strings.HasSuffix(ev.Key, "|") || ev.Body == "" {
		t.Fatalf("event = %+v", ev)
	}
	if got := len(h.Snapshot().Alarms); got != 2 {
		t.Fatalf("both alarms should be shown, got %d", got)
	}
	// A long message is shortened in the title, not the body.
	f.alarms = []backends.Alarm{{ID: "3", Box: "b", Time: now, Message: strings.Repeat("x", 200)}}
	h.Refresh(ctx)
	if t3 := s.events[len(s.events)-1]; len([]rune(t3.Title)) > 100 || len(t3.Body) != 200 {
		t.Fatalf("title %d body %d", len([]rune(t3.Title)), len(t3.Body))
	}
}

func TestSnapshotCarriesCapabilitiesAndIsACopy(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{rules: []backends.Rule{{ID: "r1"}}}
	h := newHub(t, f, &sinks{}, &now)
	h.Refresh(ctx)
	snap := h.Snapshot()
	if len(snap.Capabilities) != 10 || snap.ReadOnly || snap.Name != "fakewall" {
		t.Fatalf("snapshot = %+v", snap)
	}
	snap.Rules[0].ID = "mutated"
	if h.Snapshot().Rules[0].ID != "r1" {
		t.Fatal("the snapshot shares memory with the hub")
	}
	f.ro = true
	if s := h.Snapshot(); !s.ReadOnly || len(s.Capabilities) != 4 {
		t.Fatalf("read-only snapshot = %+v", s.Capabilities)
	}
}

func TestWritesAreAuditedAndRefreshWhatTheyChanged(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{devices: []backends.Device{{MAC: "02005e000001", Name: "TV", Box: "b", Native: "02:00:5E:00:00:01"}}}
	h := newHub(t, f, &sinks{}, &now)
	h.Refresh(ctx)

	if _, err := h.CreateRule(ctx, backends.RuleSpec{Action: "block", TargetType: "domain", Target: "ads.example"}); err != nil {
		t.Fatal(err)
	}
	if got := h.Snapshot().Rules; len(got) != 1 || got[0].ID != "new" {
		t.Fatalf("rules after create = %+v", got)
	}
	if err := h.SetRulePaused(ctx, "new", true); err != nil || !h.Snapshot().Rules[0].Paused {
		t.Fatalf("pause: %v", err)
	}
	if err := h.SetRulePaused(ctx, "new", false); err != nil || h.Snapshot().Rules[0].Paused {
		t.Fatalf("resume: %v", err)
	}
	if err := h.RenameDevice(ctx, h.Snapshot().Devices[0].Ref(), "Den TV"); err != nil || h.Snapshot().Devices[0].Name != "Den TV" {
		t.Fatalf("rename: %v", err)
	}
	f.alarms = []backends.Alarm{{ID: "9", Box: "b", Time: now}}
	h.Refresh(ctx)
	if err := h.DismissAlarm(ctx, backends.AlarmRef{Box: "b", ID: "9"}); err != nil || len(h.Snapshot().Alarms) != 0 {
		t.Fatalf("dismiss: %v", err)
	}
	if err := h.DeleteRule(ctx, "new"); err != nil || len(h.Snapshot().Rules) != 0 {
		t.Fatalf("delete: %v", err)
	}

	audit := h.Snapshot().Audit
	if len(audit) != 6 || audit[0].Action != "delete rule" || audit[5].Action != "create rule" {
		t.Fatalf("audit = %+v", audit)
	}
	for _, a := range audit {
		if a.Error != "" || a.Time.IsZero() {
			t.Fatalf("entry = %+v", a)
		}
	}
}

func TestAFailedWriteIsAuditedWithItsErrorAndChangesNothing(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{writeErr: backends.ErrReadOnly, rules: []backends.Rule{{ID: "r1"}}}
	var logged []string
	h := New(Options{Backend: f, Now: func() time.Time { return now }, Logf: func(f string, a ...any) { logged = append(logged, f) }})
	h.Refresh(ctx)
	if err := h.DeleteRule(ctx, "r1"); !errors.Is(err, backends.ErrReadOnly) {
		t.Fatalf("err = %v", err)
	}
	if len(h.Snapshot().Rules) != 1 {
		t.Fatal("a failed delete removed the rule from view")
	}
	a := h.Snapshot().Audit
	if len(a) != 1 || !strings.Contains(a[0].Error, "read-only") || len(logged) != 1 {
		t.Fatalf("audit = %+v logged = %v", a, logged)
	}
}

func TestTheAuditTrailIsBounded(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{}
	h := newHub(t, f, &sinks{}, &now)
	for i := 0; i < maxAudit+25; i++ {
		_ = h.DeleteRule(ctx, "r")
	}
	if n := len(h.Snapshot().Audit); n != maxAudit {
		t.Fatalf("audit holds %d", n)
	}
}

func TestPreviewDescribesTheRuleAndSendsNothing(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{devices: []backends.Device{{MAC: "02005e000001", Name: "Living room TV"}}}
	h := newHub(t, f, &sinks{}, &now)
	h.Refresh(ctx)
	p, err := h.PreviewRule(backends.RuleSpec{Action: "block", TargetType: "domain", Target: "ads.example", ScopeType: "device", Scope: "02:00:5E:00:00:01"})
	if err != nil || p.Device != "Living room TV" || p.NetworkWide || !strings.Contains(p.Summary, "Block domain ads.example for Living room TV, name lookups only") {
		t.Fatalf("preview = %+v, %v", p, err)
	}
	p, _ = h.PreviewRule(backends.RuleSpec{Action: "allow", TargetType: "ip", Target: "198.51.100.1"})
	if !p.NetworkWide || p.Summary != "Allow ip 198.51.100.1 for every device on the network" {
		t.Fatalf("preview = %+v", p)
	}
	p, _ = h.PreviewRule(backends.RuleSpec{Action: "block", TargetType: "category", Target: "gamble", BlockConnections: true, ScopeType: "group", Scope: " kids "})
	if !strings.Contains(p.Summary, "the group kids, lookups and connections") {
		t.Fatalf("preview = %+v", p)
	}
	if _, err := h.PreviewRule(backends.RuleSpec{Action: "drop"}); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("a preview wrote: %v", f.calls)
	}
}

// readerOnly implements nothing but devices, so every write is unsupported.
type readerOnly struct{ stubBackend }

type stubBackend struct{}

func (stubBackend) Name() string   { return "reader" }
func (stubBackend) ReadOnly() bool { return false }
func (readerOnly) Devices(context.Context) ([]backends.Device, error) {
	return []backends.Device{{Name: "x"}}, nil
}

func TestABackendThatCannotDoSomethingSaysSo(t *testing.T) {
	h := New(Options{Backend: readerOnly{}})
	h.Refresh(ctx)
	if _, err := h.PreviewRule(backends.RuleSpec{}); err == nil {
		t.Error("preview on a backend with no rules")
	}
	if _, err := h.CreateRule(ctx, backends.RuleSpec{}); !errors.Is(err, backends.ErrInvalid) {
		t.Errorf("create: %v", err)
	}
	for name, err := range map[string]error{
		"pause":   h.SetRulePaused(ctx, "r", true),
		"delete":  h.DeleteRule(ctx, "r"),
		"rename":  h.RenameDevice(ctx, backends.DeviceRef{}, "n"),
		"dismiss": h.DismissAlarm(ctx, backends.AlarmRef{}),
		"block":   h.BlockClient(ctx, backends.DeviceRef{}, true),
		"unblock": h.BlockClient(ctx, backends.DeviceRef{}, false),
	} {
		if !errors.Is(err, backends.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(h.Snapshot().Devices) != 1 {
		t.Fatal("reads still work")
	}
}

func TestRunPollsUntilTheContextEnds(t *testing.T) {
	f := &fake{flows: []backends.Flow{flow(990, "a.example", false, 1, 1)}}
	s := &sinks{}
	h := New(Options{Backend: f, FlowSink: s.flow, Interval: 5 * time.Millisecond})
	c, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { h.Run(c); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.queries)
		f.mu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
	if f.queries == nil || len(f.queries) < 3 {
		t.Fatalf("polled %d times", len(f.queries))
	}
}

func TestARestartResumesWhereItStoppedWithoutRepeatingFlows(t *testing.T) {
	path := t.TempDir() + "/state.json"
	now := time.Unix(1000, 0)
	f := &fake{flows: []backends.Flow{flow(990, "a.example", false, 1, 1)}}
	s := &sinks{}
	h := New(Options{Backend: f, FlowSink: s.flow, StatePath: path, Now: func() time.Time { return now }})
	h.Refresh(ctx)
	if len(s.entries) != 1 {
		t.Fatalf("entries = %d", len(s.entries))
	}

	// A new hub (a restart) reaches back only to the last flow it saw, not
	// by the overlap or the first-poll window.
	f2 := &fake{flows: []backends.Flow{flow(990, "a.example", false, 1, 1), flow(1010, "b.example", false, 1, 1)}}
	s2 := &sinks{}
	now = time.Unix(1020, 0)
	h2 := New(Options{Backend: f2, FlowSink: s2.flow, StatePath: path, Now: func() time.Time { return now }})
	h2.Refresh(ctx)
	if got := f2.queries[0].From; !got.Equal(time.Unix(990, 0)) {
		t.Fatalf("resumed from %v, want the saved watermark", got)
	}
	// The second poll is back to the normal overlap.
	h2.Refresh(ctx)
	if got := f2.queries[1].From; !got.Equal(time.Unix(1010, 0).Add(-flowOverlap)) {
		t.Fatalf("second poll from %v", got)
	}
}

func TestUnreadableOrFutureStateIsIgnored(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	for name, body := range map[string]string{
		"garbage": "{nope",
		"future":  `{"last_flow":"2099-01-01T00:00:00Z"}`,
		"empty":   `{}`,
	} {
		path := dir + "/" + name
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		f := &fake{}
		h := New(Options{Backend: f, StatePath: path, Now: func() time.Time { return now }})
		h.Refresh(ctx)
		if got := f.queries[0].From; !got.Equal(now.Add(-firstFlowWindow)) {
			t.Errorf("%s: from %v", name, got)
		}
	}
	// A state path that cannot be written is logged, not fatal.
	var logged []string
	f := &fake{flows: []backends.Flow{flow(990, "a", false, 1, 1)}}
	h := New(Options{Backend: f, StatePath: dir + "/missing/state.json", Now: func() time.Time { return now },
		Logf: func(format string, a ...any) { logged = append(logged, format) }})
	h.Refresh(ctx)
	if len(logged) != 1 {
		t.Fatalf("logged = %v", logged)
	}
	if err := os.Mkdir(dir+"/blocked", 0o700); err != nil {
		t.Fatal(err)
	}
	h = New(Options{Backend: f, StatePath: dir + "/blocked", Now: func() time.Time { return now }, Logf: func(string, ...any) { logged = append(logged, "x") }})
	f.flows = []backends.Flow{flow(995, "b", false, 1, 1)}
	h.Refresh(ctx)
	if len(logged) < 2 {
		t.Fatalf("a rename failure was not reported: %v", logged)
	}
}

func TestBlockingAndUnblockingADeviceIsAuditedAndAsksTheBackend(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{}
	h := newHub(t, f, &sinks{}, &now)
	ref := backends.DeviceRef{Box: "site", Native: "client-1"}
	if err := h.BlockClient(ctx, ref, true); err != nil {
		t.Fatal(err)
	}
	if err := h.BlockClient(ctx, ref, false); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.calls, ",") != "block client-1,unblock client-1" {
		t.Fatalf("calls = %v", f.calls)
	}
	a := h.Snapshot().Audit
	if len(a) != 2 || a[0].Action != "unblock device" || a[1].Action != "block device" {
		t.Fatalf("audit = %+v", a)
	}
	f.writeErr = backends.ErrReadOnly
	if err := h.BlockClient(ctx, ref, true); !errors.Is(err, backends.ErrReadOnly) {
		t.Fatal(err)
	}
}

func TestABlockedDeviceStaysListedUntilItIsUnblocked(t *testing.T) {
	now := time.Unix(1000, 0)
	path := t.TempDir() + "/blocked.json"
	f := &fake{devices: []backends.Device{{MAC: "02005e000001", Name: "Tablet", Native: "client-1", Box: "site", Online: true}}}
	mk := func() *Hub {
		return New(Options{Backend: f, BlockedPath: path, Now: func() time.Time { return now }})
	}
	h := mk()
	h.Refresh(ctx)
	ref := backends.DeviceRef{Box: "site", Native: "client-1"}
	if err := h.BlockClient(ctx, ref, true); err != nil {
		t.Fatal(err)
	}
	// The console stops listing the client once it is blocked.
	f.devices = nil
	h.Refresh(ctx)
	check := func(h *Hub, want bool) {
		t.Helper()
		var got *backends.Device
		for _, d := range h.Snapshot().Devices {
			if d.Native == "client-1" {
				d := d
				got = &d
			}
		}
		if want && (got == nil || !got.Blocked || got.Online || got.Name != "Tablet") {
			t.Fatalf("blocked device missing or wrong: %+v", got)
		}
		if !want && got != nil {
			t.Fatalf("still listed: %+v", got)
		}
	}
	check(h, true)
	check(mk(), true) // survives a restart
	if err := h.BlockClient(ctx, ref, false); err != nil {
		t.Fatal(err)
	}
	check(h, false)
	check(mk(), false)
}

func TestAFailedBlockIsNotRemembered(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{writeErr: backends.ErrReadOnly}
	h := newHub(t, f, &sinks{}, &now)
	_ = h.BlockClient(ctx, backends.DeviceRef{Native: "client-9"}, true)
	if len(h.Snapshot().Devices) != 0 {
		t.Fatalf("%+v", h.Snapshot().Devices)
	}
}

func TestABlockedDeviceSeenOnlineAgainWasUnblockedElsewhere(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{devices: []backends.Device{{Name: "Tablet", Native: "client-1", Box: "site", Online: true}}}
	h := newHub(t, f, &sinks{}, &now)
	h.Refresh(ctx)
	_ = h.BlockClient(ctx, backends.DeviceRef{Box: "site", Native: "client-1"}, true)
	if d := h.Snapshot().Devices; len(d) != 1 || !d[0].Blocked {
		t.Fatalf("listed but not marked: %+v", d)
	}
	h.Refresh(ctx) // the console still reports it connected: unblocked there
	if d := h.Snapshot().Devices; len(d) != 1 || d[0].Blocked {
		t.Fatalf("not forgotten: %+v", d)
	}
}

// A request read from a router is placed on the map by where it went, like
// a lookup Shepherd answered itself.
func TestFlowsArePlacedOnTheMapWhenTheirAddressIsKnown(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{flows: []backends.Flow{flow(990, "a.example", false, 1, 1)}}
	s := &sinks{}
	var asked []string
	h := New(Options{
		Backend: f, FlowSink: s.flow, Now: func() time.Time { return now },
		Locate: func(ip string) (dnsengine.Dest, bool) {
			asked = append(asked, ip)
			return dnsengine.Dest{IP: ip, Lat: 51.5, Lon: -0.1, City: "London", Country: "GB"}, ip == "198.51.100.7"
		},
	})
	h.Refresh(ctx)
	if len(s.entries) != 1 || len(s.entries[0].Dests) != 1 || s.entries[0].Dests[0].Country != "GB" {
		t.Fatalf("entries = %+v", s.entries)
	}
	// An address the map does not know, and a flow with none, get no place.
	unknown := flow(995, "b.example", false, 1, 1)
	unknown.RemoteIP = "203.0.113.9"
	local := flow(996, "c.example", false, 1, 1)
	local.RemoteIP = ""
	f.flows = []backends.Flow{unknown, local}
	h.Refresh(ctx)
	for _, e := range s.entries[1:] {
		if len(e.Dests) != 0 {
			t.Errorf("%s was placed: %+v", e.Name, e.Dests)
		}
	}
	if len(asked) != 2 {
		t.Errorf("asked about %v", asked)
	}
}

// groupFake is a fake that also has device groups.
type groupFake struct {
	*fake
	groups    []backends.Group
	groupErr  error
	createErr error
	moveErr   error
}

func (g *groupFake) Groups(context.Context) ([]backends.Group, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]backends.Group(nil), g.groups...), g.groupErr
}

func (g *groupFake) CreateGroup(_ context.Context, name string) (backends.Group, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.createErr != nil {
		return backends.Group{}, g.createErr
	}
	ng := backends.Group{ID: "g" + name, Name: name}
	g.groups = append(g.groups, ng)
	g.calls = append(g.calls, "create "+name)
	return ng, nil
}

func (g *groupFake) SetDeviceGroup(_ context.Context, d backends.DeviceRef, id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.moveErr != nil {
		return g.moveErr
	}
	g.calls = append(g.calls, "move "+d.Native+" to "+id)
	return nil
}

func TestADeviceIsMovedIntoAGroupThatIsMadeWhenMissing(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &groupFake{fake: &fake{devices: []backends.Device{{MAC: "02005e000001", Name: "TV", Native: "tv"}}},
		groups: []backends.Group{{ID: "18", Name: "Smart Home"}}}
	h := New(Options{Backend: f, Now: func() time.Time { return now }})
	h.Refresh(ctx)
	snap := h.Snapshot()
	if len(snap.Groups) != 1 || snap.Groups[0].Name != "Smart Home" {
		t.Fatalf("groups = %+v", snap.Groups)
	}
	if !has(snap.Capabilities, backends.CapGroups) || !has(snap.Capabilities, backends.CapGroupWrite) {
		t.Fatalf("capabilities = %v", snap.Capabilities)
	}
	ref := backends.DeviceRef{Native: "tv"}

	// An existing group is found whatever its letter case; nothing is made.
	if err := h.SetDeviceGroup(ctx, ref, " smart home "); err != nil {
		t.Fatal(err)
	}
	// A missing one is made first, then used, and remembered.
	if err := h.SetDeviceGroup(ctx, ref, "Kids"); err != nil {
		t.Fatal(err)
	}
	if err := h.SetDeviceGroup(ctx, ref, "kids"); err != nil {
		t.Fatal(err)
	}
	// No name takes the device out of its group.
	if err := h.SetDeviceGroup(ctx, ref, ""); err != nil {
		t.Fatal(err)
	}
	want := []string{"move tv to 18", "create Kids", "move tv to gKids", "move tv to gKids", "move tv to "}
	if got := strings.Join(f.calls, "|"); got != strings.Join(want, "|") {
		t.Fatalf("calls = %v", f.calls)
	}
	if d := h.Snapshot().Devices[0]; d.Group != "" {
		t.Fatalf("device = %+v", d)
	}
	if err := h.SetDeviceGroup(ctx, ref, "Den"); err != nil || h.Snapshot().Devices[0].Group != "Den" {
		t.Fatalf("the move is not shown at once: %v, %+v", err, h.Snapshot().Devices[0])
	}
	audit := h.Snapshot().Audit
	if len(audit) != 7 || audit[0].Action != "move device" || audit[1].Action != "create group" {
		t.Fatalf("audit = %+v", audit)
	}

	// Failures are reported and recorded, and a failed create moves nothing.
	f.createErr = errors.New("no room")
	if err := h.SetDeviceGroup(ctx, ref, "Office"); err == nil {
		t.Fatal("a failed create was hidden")
	}
	if strings.Contains(strings.Join(f.calls, "|"), "gOffice") {
		t.Fatal("moved into a group that was not made")
	}
	f.moveErr = errors.New("box offline")
	if err := h.SetDeviceGroup(ctx, ref, "Kids"); err == nil || h.Snapshot().Audit[0].Error == "" {
		t.Fatalf("a failed move was hidden: %v", err)
	}

	// Groups that cannot be read are a reported error, not a failed poll.
	f.groupErr = errors.New("HTTP 500")
	h.Refresh(ctx)
	if h.Snapshot().Status.Errors["groups"] != "HTTP 500" {
		t.Fatalf("status = %+v", h.Snapshot().Status)
	}

	// A product with no groups says so.
	plain := New(Options{Backend: &fake{}})
	if err := plain.SetDeviceGroup(ctx, ref, "Kids"); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("no groups = %v", err)
	}
}

func has(caps []backends.Capability, c backends.Capability) bool {
	for _, x := range caps {
		if x == c {
			return true
		}
	}
	return false
}
