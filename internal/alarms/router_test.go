// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

type stubSource struct {
	mu    sync.Mutex
	prefs Preferences
	types map[string]AlarmType
}

func (s *stubSource) Preferences() Preferences {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prefs.Clone()
}

func (s *stubSource) Type(id string) (AlarmType, bool) {
	t, ok := s.types[id]
	return t, ok
}

func (s *stubSource) set(f func(*Preferences)) {
	s.mu.Lock()
	f(&s.prefs)
	s.mu.Unlock()
}

type fakePusher struct {
	mu    sync.Mutex
	calls []Notification
	fn    func(Notification) (PushReport, error)
}

func (p *fakePusher) Push(_ context.Context, n Notification) (PushReport, error) {
	p.mu.Lock()
	p.calls = append(p.calls, n)
	fn := p.fn
	p.mu.Unlock()
	if fn == nil {
		return PushReport{Subscribed: 2, Delivered: 2}, nil
	}
	return fn(n)
}

func (p *fakePusher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *fakePusher) set(fn func(Notification) (PushReport, error)) {
	p.mu.Lock()
	p.fn = fn
	p.mu.Unlock()
}

type fakeNtfy struct {
	mu    sync.Mutex
	calls []Notification
	fn    func(Notification) error
}

func (n *fakeNtfy) Publish(_ context.Context, m Notification) error {
	n.mu.Lock()
	n.calls = append(n.calls, m)
	fn := n.fn
	n.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(m)
}

func (n *fakeNtfy) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.calls)
}

func (n *fakeNtfy) set(fn func(Notification) error) {
	n.mu.Lock()
	n.fn = fn
	n.mu.Unlock()
}

type rig struct {
	r    *Router
	clk  *FakeClock
	push *fakePusher
	nt   *fakeNtfy
	src  *stubSource
}

func newRig(t testing.TB, mod ...func(*RouterOptions)) *rig {
	t.Helper()
	g := &rig{clk: NewFakeClock(t0), push: &fakePusher{}, nt: &fakeNtfy{}}
	g.src = &stubSource{prefs: testPrefs(), types: map[string]AlarmType{}}
	for _, ty := range BuiltinTypes() {
		g.src.types[ty.ID] = ty
	}
	o := RouterOptions{Source: g.src, Pusher: g.push, Ntfy: g.nt, Clock: g.clk}
	for _, m := range mod {
		m(&o)
	}
	g.r = NewRouter(o)
	return g
}

var alarmSeq atomic.Int64

func alarmOf(typ string, sev Severity, key string) Alarm {
	return Alarm{ID: fmt.Sprintf("a%d", alarmSeq.Add(1)), Type: typ, Severity: sev, Title: "Title " + key, Body: "Body " + key, Key: key,
		URL: "/alarms/" + key, State: StateNew, Count: 1}
}

func raisedChange(a Alarm) Change {
	return Change{Kind: ChangeRaised, Alarm: a, Notify: Notify{Send: true}}
}

func (g *rig) send(t testing.TB, a Alarm) {
	t.Helper()
	g.r.Handle(raisedChange(a))
	g.r.Wait()
}

func (g *rig) record(t testing.TB, channel string) DeliveryRecord {
	t.Helper()
	recs := g.r.Log(channel, 1)
	if len(recs) == 0 {
		t.Fatalf("no %s delivery record", channel)
	}
	return recs[0]
}

func statusOf(g *rig, ch string) ChannelStatus {
	for _, s := range g.r.Status() {
		if s.Channel == ch {
			return s
		}
	}
	return ChannelStatus{}
}

// ---- the delivery matrix -------------------------------------------------------------

func TestMatrixPushOK(t *testing.T) {
	g := newRig(t)
	g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "k"))
	if g.push.count() != 1 || g.nt.count() != 0 {
		t.Fatalf("push=%d ntfy=%d: ntfy must stay quiet when push delivered", g.push.count(), g.nt.count())
	}
	rec := g.record(t, ChannelPush)
	if rec.Status != DeliveryOK || rec.Attempts != 1 || rec.Detail != "2 of 2 delivered" {
		t.Fatalf("record = %+v", rec)
	}
	if st := statusOf(g, ChannelPush); !st.Configured || st.OK != 1 || !st.LastOK.Equal(t0) || st.LastError != "" {
		t.Fatalf("status = %+v", st)
	}
	if len(g.r.Log(ChannelNtfy, 10)) != 0 {
		t.Fatal("ntfy logged without being used")
	}
}

func TestMatrixPushGoneThenNtfyFallback(t *testing.T) {
	g := newRig(t)
	g.push.set(func(Notification) (PushReport, error) { return PushReport{Subscribed: 2, Gone: 2}, nil })
	g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "k"))
	if g.push.count() != 1 || g.nt.count() != 1 {
		t.Fatalf("push=%d ntfy=%d", g.push.count(), g.nt.count())
	}
	p := g.record(t, ChannelPush)
	if p.Status != DeliveryFailed || !strings.Contains(p.Error, "gone") {
		t.Fatalf("push record = %+v", p)
	}
	if retries, _ := g.r.Pending(); retries != 0 {
		t.Fatal("a gone endpoint must not be retried")
	}
	if n := g.record(t, ChannelNtfy); n.Status != DeliveryOK {
		t.Fatalf("ntfy record = %+v", n)
	}
	// Partly gone, partly delivered counts as delivered: no fallback.
	g2 := newRig(t)
	g2.push.set(func(Notification) (PushReport, error) { return PushReport{Subscribed: 2, Delivered: 1, Gone: 1}, nil })
	g2.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "k"))
	if g2.nt.count() != 0 || g2.record(t, ChannelPush).Detail != "1 of 2 delivered, 1 gone" {
		t.Fatal("partial delivery")
	}
}

func TestMatrixNoSubscriptionsThenNtfy(t *testing.T) {
	g := newRig(t)
	g.push.set(func(Notification) (PushReport, error) { return PushReport{}, nil })
	g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "k"))
	if g.nt.count() != 1 {
		t.Fatal("ntfy must take over when nobody is subscribed to push")
	}
	p := g.record(t, ChannelPush)
	if p.Status != DeliverySkipped || p.Detail != "no push subscriptions" || p.Error != "" {
		t.Fatalf("push record = %+v", p)
	}
	if st := statusOf(g, ChannelPush); st.Failed != 0 || st.LastError != "" {
		t.Fatalf("no subscriptions is not an error: %+v", st)
	}
}

func TestMatrixPushFailsNtfyFallsBackAndPushRetries(t *testing.T) {
	g := newRig(t)
	g.push.set(func(Notification) (PushReport, error) {
		return PushReport{Subscribed: 1, Failed: 1, Err: "push service answered 503"}, nil
	})
	g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "k"))
	if g.nt.count() != 1 {
		t.Fatal("a failing push must not delay the ntfy fallback")
	}
	p := g.record(t, ChannelPush)
	if p.Status != DeliveryRetrying || p.Attempts != 1 || p.Error != "push service answered 503" || !p.Next.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("push record = %+v", p)
	}
	if retries, _ := g.r.Pending(); retries != 1 {
		t.Fatal("retry not scheduled")
	}
	// Before the backoff elapses nothing happens; afterwards the retry succeeds in place.
	g.clk.Advance(29 * time.Second)
	g.r.Process(context.Background())
	if g.push.count() != 1 {
		t.Fatal("retried too early")
	}
	g.push.set(nil)
	g.clk.Advance(time.Second)
	g.r.Process(context.Background())
	p = g.record(t, ChannelPush)
	if g.push.count() != 2 || p.Status != DeliveryOK || p.Attempts != 2 || len(g.r.Log(ChannelPush, 10)) != 1 {
		t.Fatalf("after retry: %+v (%d records)", p, len(g.r.Log(ChannelPush, 10)))
	}
	if g.nt.count() != 1 {
		t.Fatal("the fallback must not repeat when the push retry succeeds")
	}
	if retries, _ := g.r.Pending(); retries != 0 {
		t.Fatal("retry still pending")
	}
}

func TestMatrixBothFailLoggedRetriedThenFailed(t *testing.T) {
	g := newRig(t)
	g.push.set(func(Notification) (PushReport, error) { return PushReport{}, errors.New("network is down") })
	g.nt.set(func(Notification) error { return errors.New("ntfy: server 503") })
	g.send(t, alarmOf(TypeThreatMatch, SeverityCritical, "k"))
	if g.push.count() != 1 || g.nt.count() != 1 {
		t.Fatalf("push=%d ntfy=%d", g.push.count(), g.nt.count())
	}
	if retries, _ := g.r.Pending(); retries != 2 {
		t.Fatalf("pending retries = %d", retries)
	}
	// Backoff 30s, 2m, 10m, then it gives up.
	waits := []time.Duration{30 * time.Second, 2 * time.Minute, 10 * time.Minute}
	for i, w := range waits {
		g.clk.Advance(w)
		g.r.Process(context.Background())
		want := i + 2
		if g.push.count() != want || g.nt.count() != want {
			t.Fatalf("round %d: push=%d ntfy=%d, want %d", i, g.push.count(), g.nt.count(), want)
		}
	}
	for _, ch := range []string{ChannelPush, ChannelNtfy} {
		rec := g.record(t, ch)
		if rec.Status != DeliveryFailed || rec.Attempts != 4 || rec.Error == "" || len(g.r.Log(ch, 10)) != 1 {
			t.Fatalf("%s record = %+v", ch, rec)
		}
		st := statusOf(g, ch)
		if st.Failed != 4 || st.LastError == "" || st.LastErrorAt.IsZero() || !st.LastOK.IsZero() {
			t.Fatalf("%s status = %+v", ch, st)
		}
	}
	if retries, _ := g.r.Pending(); retries != 0 {
		t.Fatal("gave-up deliveries still pending")
	}
	g.clk.Advance(24 * time.Hour)
	g.r.Process(context.Background())
	if g.push.count() != 4 {
		t.Fatal("kept retrying after giving up")
	}
}

func TestMatrixNtfyAlwaysOn(t *testing.T) {
	g := newRig(t)
	g.src.set(func(p *Preferences) { p.NtfyAlways = true })
	g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "k"))
	if g.push.count() != 1 || g.nt.count() != 1 {
		t.Fatalf("push=%d ntfy=%d: always means both", g.push.count(), g.nt.count())
	}
	// With always on, a failing push does not make ntfy send twice.
	g2 := newRig(t)
	g2.src.set(func(p *Preferences) { p.NtfyAlways = true })
	g2.push.set(func(Notification) (PushReport, error) { return PushReport{Subscribed: 1, Gone: 1}, nil })
	g2.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "k"))
	if g2.nt.count() != 1 {
		t.Fatalf("ntfy sent %d times", g2.nt.count())
	}
}

func TestChannelsAreIndependent(t *testing.T) {
	// A push that never returns must not hold up ntfy when ntfy is always-on...
	release := make(chan struct{})
	g := newRig(t)
	g.src.set(func(p *Preferences) { p.NtfyAlways = true })
	g.push.set(func(Notification) (PushReport, error) { <-release; return PushReport{Subscribed: 1, Delivered: 1}, nil })
	g.r.Handle(raisedChange(alarmOf(TypeUpstreamDown, SeverityHigh, "k")))
	deadline := time.Now().Add(10 * time.Second)
	for g.nt.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if g.nt.count() != 1 {
		t.Fatal("ntfy waited for a stuck push")
	}
	close(release)
	g.r.Wait()
	// ...and a stuck ntfy must not hold up push.
	release2 := make(chan struct{})
	g2 := newRig(t)
	g2.src.set(func(p *Preferences) { p.NtfyAlways = true })
	g2.nt.set(func(Notification) error { <-release2; return nil })
	g2.r.Handle(raisedChange(alarmOf(TypeUpstreamDown, SeverityHigh, "k")))
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if recs := g2.r.Log(ChannelPush, 1); len(recs) == 1 && recs[0].Status == DeliveryOK {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if recs := g2.r.Log(ChannelPush, 1); len(recs) != 1 || recs[0].Status != DeliveryOK {
		t.Fatal("push waited for a stuck ntfy")
	}
	close(release2)
	g2.r.Wait()
}

func TestNtfyPermanentErrorIsNotRetried(t *testing.T) {
	g := newRig(t)
	g.push.set(func(Notification) (PushReport, error) { return PushReport{}, nil })
	g.nt.set(func(Notification) error { return Permanent(errors.New("ntfy: auth (HTTP 401)")) })
	g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "k"))
	rec := g.record(t, ChannelNtfy)
	if rec.Status != DeliveryFailed || rec.Attempts != 1 {
		t.Fatalf("record = %+v", rec)
	}
	if retries, _ := g.r.Pending(); retries != 0 {
		t.Fatal("permanent error retried")
	}
	if !IsPermanent(Permanent(errors.New("x"))) || IsPermanent(errors.New("x")) || Permanent(nil) != nil {
		t.Fatal("Permanent helpers")
	}
	if !errors.Is(Permanent(os.ErrNotExist), os.ErrNotExist) {
		t.Fatal("Permanent must unwrap")
	}
}

func TestChannelsNotConfigured(t *testing.T) {
	// No ntfy: push failure just retries.
	g := newRig(t, func(o *RouterOptions) { o.Ntfy = nil })
	g.push.set(func(Notification) (PushReport, error) { return PushReport{Subscribed: 1, Failed: 1}, nil })
	g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "k"))
	rec := g.record(t, ChannelPush)
	if rec.Status != DeliveryRetrying || rec.Error != "push failed for every device" {
		t.Fatalf("%+v", rec)
	}
	if st := statusOf(g, ChannelNtfy); st.Configured {
		t.Fatal("ntfy reported configured")
	}
	// No push: ntfy carries it alone.
	g2 := newRig(t, func(o *RouterOptions) { o.Pusher = nil })
	g2.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "k"))
	if g2.nt.count() != 1 {
		t.Fatal("ntfy alone")
	}
	// Neither: nothing happens, no panic.
	g3 := newRig(t, func(o *RouterOptions) { o.Pusher, o.Ntfy = nil, nil })
	g3.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "k"))
	if len(g3.r.Log("", 10)) != 0 {
		t.Fatal("logged with no channels")
	}
}

// ---- which alarms are delivered -----------------------------------------------------------

func TestRoutingBySeverityAndSwitches(t *testing.T) {
	g := newRig(t)
	g.src.set(func(p *Preferences) {
		p.Channels[ChannelPush] = ChannelPref{Enabled: true, MinSeverity: SeverityHigh}
		p.Channels[ChannelNtfy] = ChannelPref{Enabled: true, MinSeverity: SeverityCritical}
		p.Digest.Enabled = false
		p.Types = map[string]TypePref{
			TypeUpstreamRecovered: {Off: true},
			TypeNewDevice:         {OffForClasses: []string{"tv"}},
			TypeHistoryError:      {Channels: []string{ChannelPortal}},
		}
	})
	check := func(name string, a Alarm, wantPush, wantNtfy int) {
		t.Helper()
		g.send(t, a)
		if g.push.count() != wantPush || g.nt.count() != wantNtfy {
			t.Fatalf("%s: push=%d ntfy=%d, want %d %d", name, g.push.count(), g.nt.count(), wantPush, wantNtfy)
		}
	}
	check("below both minimums", alarmOf(TypeListUpdateRejected, SeverityMedium, "a"), 0, 0)
	check("push minimum", alarmOf(TypeUpstreamDown, SeverityHigh, "b"), 1, 0)
	check("a type that is off", alarmOf(TypeUpstreamRecovered, SeverityCritical, "c"), 1, 0)
	tv := alarmOf(TypeNewDevice, SeverityHigh, "d")
	tv.DeviceClass = "tv"
	check("off for this device class", tv, 1, 0)
	cam := alarmOf(TypeNewDevice, SeverityHigh, "e")
	cam.DeviceClass = "camera"
	check("on for other classes", cam, 2, 0)
	check("portal-only type override", alarmOf(TypeHistoryError, SeverityCritical, "f"), 2, 0)
	// A critical alarm reaches ntfy only when push did not deliver.
	check("critical, push delivered", alarmOf(TypeThreatMatch, SeverityCritical, "g"), 3, 0)
	g.push.set(func(Notification) (PushReport, error) { return PushReport{}, nil })
	check("critical, no push", alarmOf(TypeThreatMatch, SeverityCritical, "h"), 4, 1)
	check("high, no push, ntfy minimum is critical", alarmOf(TypeUpstreamDown, SeverityHigh, "i"), 5, 1)
	// A disabled channel is skipped.
	g.src.set(func(p *Preferences) { p.Channels[ChannelPush] = ChannelPref{Enabled: false, MinSeverity: SeverityLow} })
	check("push disabled", alarmOf(TypeThreatMatch, SeverityCritical, "j"), 5, 2)
	// Unregistered types use all channels.
	check("unregistered type", alarmOf("third-party", SeverityCritical, "k"), 5, 3)
	// Changes that are not notifications are ignored.
	for _, c := range []Change{
		{Kind: ChangeRaised, Alarm: alarmOf(TypeThreatMatch, SeverityCritical, "l")}, // Send=false
		{Kind: ChangeUpdated, Alarm: alarmOf(TypeThreatMatch, SeverityCritical, "m"), Notify: Notify{Send: true}},
		{Kind: ChangeRule, Notify: Notify{Send: true}},
	} {
		g.r.Handle(c)
	}
	g.r.Wait()
	if g.push.count() != 5 || g.nt.count() != 3 {
		t.Fatal("non-notifications were delivered")
	}
	// Escalations and mute-expiry notifications do deliver.
	g.src.set(func(p *Preferences) { p.Channels[ChannelPush] = ChannelPref{Enabled: true, MinSeverity: SeverityLow} })
	g.push.set(nil)
	for _, k := range []ChangeKind{ChangeEscalated, ChangeState} {
		g.r.Handle(Change{Kind: k, Alarm: alarmOf(TypeThreatMatch, SeverityCritical, string(k)), Notify: Notify{Send: true}})
	}
	g.r.Wait()
	if g.push.count() != 7 {
		t.Fatalf("push = %d", g.push.count())
	}
}

// ---- digest and quiet hours ----------------------------------------------------------------

func TestDigestCollectsLowAndSendsOnInterval(t *testing.T) {
	g := newRig(t)
	for i := 0; i < 3; i++ {
		g.clk.Advance(time.Minute)
		g.send(t, alarmOf(TypeListUpdateRejected, SeverityMedium, fmt.Sprint("m", i)))
	}
	if g.push.count() != 0 || g.nt.count() != 0 {
		t.Fatal("medium alarms must wait for the digest")
	}
	if _, items := g.r.Pending(); items != 3 {
		t.Fatalf("queued = %d", items)
	}
	// Immediate delivery for high and above is unaffected by the queue.
	g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "h"))
	if g.push.count() != 1 {
		t.Fatal("high must be immediate")
	}
	g.clk.Advance(5*time.Hour + 56*time.Minute) // 5:59 after the first was queued
	g.r.Process(context.Background())
	if g.push.count() != 1 {
		t.Fatal("digest sent early")
	}
	g.clk.Advance(5 * time.Minute)
	g.r.Process(context.Background())
	if g.push.count() != 2 {
		t.Fatalf("push = %d", g.push.count())
	}
	d := g.push.calls[1]
	if !d.Digest || d.Title != "Shepherd: 3 alerts" || d.Severity != SeverityMedium || d.URL != "/alarms" || d.Tag != "digest" ||
		!strings.Contains(d.Body, "- Title m0") || !strings.Contains(d.Body, "- Title m2") {
		t.Fatalf("digest = %+v", d)
	}
	if _, items := g.r.Pending(); items != 0 {
		t.Fatal("queue not emptied")
	}
	// A digest is sent once.
	g.clk.Advance(24 * time.Hour)
	g.r.Process(context.Background())
	if g.push.count() != 2 {
		t.Fatal("digest repeated")
	}
}

func TestDigestSingleItemIsSentAsItselfAndLongDigestsAreCut(t *testing.T) {
	g := newRig(t, func(o *RouterOptions) {})
	g.src.set(func(p *Preferences) { p.PortalURL = "https://shepherd.example.com/" })
	g.send(t, alarmOf(TypeListUpdateRejected, SeverityMedium, "only"))
	g.clk.Advance(7 * time.Hour)
	g.r.Process(context.Background())
	if n := g.push.calls[0]; n.Digest || n.Title != "Title only" || n.Click != "https://shepherd.example.com/alarms/only" {
		t.Fatalf("single item: %+v", n)
	}
	for i := 0; i < 12; i++ {
		g.send(t, alarmOf(TypeListUpdateRejected, SeverityLow, fmt.Sprint("l", i)))
	}
	g.clk.Advance(7 * time.Hour)
	g.r.Process(context.Background())
	d := g.push.calls[1]
	if d.Title != "Shepherd: 12 alerts" || !strings.Contains(d.Body, "...and 4 more") || strings.Count(d.Body, "\n") != 8 || d.Severity != SeverityLow {
		t.Fatalf("long digest: %+v", d)
	}
	if d.Click != "https://shepherd.example.com/alarms" {
		t.Fatalf("digest click = %q", d.Click)
	}
}

func TestDigestAtASetTimeInATimeZone(t *testing.T) {
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skip("no tzdata")
	}
	g := newRig(t)
	g.src.set(func(p *Preferences) {
		p.Timezone = "Asia/Tokyo"
		p.Digest = DigestPref{Enabled: true, At: "08:00"}
	})
	// 12:00 UTC is 21:00 in Tokyo; the digest goes out at 08:00 Tokyo the next day.
	g.send(t, alarmOf(TypeListUpdateRejected, SeverityMedium, "a"))
	g.send(t, alarmOf(TypeListUpdateRejected, SeverityMedium, "b"))
	due := time.Date(2030, 3, 5, 8, 0, 0, 0, tokyo)
	g.clk.Set(due.Add(-time.Minute))
	g.r.Process(context.Background())
	if g.push.count() != 0 {
		t.Fatal("early")
	}
	g.clk.Set(due)
	g.r.Process(context.Background())
	if g.push.count() != 1 || !g.push.calls[0].Digest {
		t.Fatalf("push = %d", g.push.count())
	}
	// A bad zone falls back to UTC rather than losing the digest.
	if got := g.r.digestDue(Preferences{Timezone: "Mars/Olympus", Digest: DigestPref{At: "08:00"}}, t0); !got.Equal(time.Date(2030, 3, 5, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("fallback: %v", got)
	}
}

func TestDigestDisabledAndImmediateThreshold(t *testing.T) {
	g := newRig(t)
	g.src.set(func(p *Preferences) { p.Digest.Enabled = false })
	g.send(t, alarmOf(TypeListUpdateRejected, SeverityLow, "a"))
	if g.push.count() != 1 {
		t.Fatal("with the digest off everything is immediate")
	}
	g2 := newRig(t)
	g2.src.set(func(p *Preferences) { p.ImmediateMin = SeverityMedium })
	g2.send(t, alarmOf(TypeListUpdateRejected, SeverityMedium, "m"))
	g2.send(t, alarmOf(TypeListUpdateRejected, SeverityLow, "l"))
	if g2.push.count() != 1 {
		t.Fatalf("immediate threshold: %d", g2.push.count())
	}
	// Digest items remember which channels they were for.
	g3 := newRig(t)
	g3.src.set(func(p *Preferences) { p.Channels[ChannelPush] = ChannelPref{Enabled: false} })
	g3.send(t, alarmOf(TypeListUpdateRejected, SeverityMedium, "n"))
	g3.clk.Advance(7 * time.Hour)
	g3.r.Process(context.Background())
	if g3.push.count() != 0 || g3.nt.count() != 1 {
		t.Fatalf("digest channels: push=%d ntfy=%d", g3.push.count(), g3.nt.count())
	}
	// If the channels are gone by the time the digest is due, nothing is sent.
	g4 := newRig(t)
	g4.send(t, alarmOf(TypeListUpdateRejected, SeverityMedium, "n"))
	g4.r.pusher, g4.r.ntfy = nil, nil
	g4.clk.Advance(7 * time.Hour)
	g4.r.Process(context.Background())
	if g4.push.count() != 0 || g4.nt.count() != 0 {
		t.Fatal("sent without channels")
	}
}

func TestQuietHoursHoldUntilTheWindowEnds(t *testing.T) {
	g := newRig(t)
	g.src.set(func(p *Preferences) {
		p.Quiet = QuietPref{Enabled: true, Windows: []QuietWindow{{Start: "22:00", End: "07:00", Allow: SeverityCritical}}}
	})
	night := time.Date(2030, 3, 4, 23, 0, 0, 0, time.UTC)
	g.clk.Set(night)
	a := alarmOf(TypeUpstreamDown, SeverityHigh, "h")
	g.r.Handle(Change{Kind: ChangeRaised, Alarm: a, Notify: Notify{Send: true, HoldUntil: time.Date(2030, 3, 5, 7, 0, 0, 0, time.UTC), Reason: "quiet-hours"}})
	g.r.Wait()
	if g.push.count() != 0 {
		t.Fatal("a high alarm was delivered in quiet hours")
	}
	g.clk.Set(time.Date(2030, 3, 5, 6, 59, 0, 0, time.UTC))
	g.r.Process(context.Background())
	if g.push.count() != 0 {
		t.Fatal("delivered before the window ended")
	}
	g.clk.Set(time.Date(2030, 3, 5, 7, 0, 0, 0, time.UTC))
	g.r.Process(context.Background())
	if g.push.count() != 1 || g.push.calls[0].Title != "Title h" {
		t.Fatalf("held alarm not delivered at 07:00: %d", g.push.count())
	}
	// Even with the digest off, held alarms wait.
	g.src.set(func(p *Preferences) { p.Digest.Enabled = false })
	g.clk.Set(night.Add(24 * time.Hour))
	g.r.Handle(Change{Kind: ChangeRaised, Alarm: alarmOf(TypeUpstreamDown, SeverityHigh, "h2"), Notify: Notify{Send: true, HoldUntil: time.Date(2030, 3, 6, 7, 0, 0, 0, time.UTC)}})
	g.r.Wait()
	if g.push.count() != 1 {
		t.Fatal("held alarm delivered with the digest off")
	}
}

func TestDigestNeverWakesTheHouseholdInQuietHours(t *testing.T) {
	g := newRig(t)
	g.src.set(func(p *Preferences) {
		p.Quiet = QuietPref{Enabled: true, Windows: []QuietWindow{{Start: "22:00", End: "07:00", Allow: SeverityCritical}}}
		p.Digest = DigestPref{Enabled: true, Every: Duration(4 * time.Hour)}
	})
	g.clk.Set(time.Date(2030, 3, 4, 20, 0, 0, 0, time.UTC))
	g.send(t, alarmOf(TypeListUpdateRejected, SeverityMedium, "a"))
	g.send(t, alarmOf(TypeListUpdateRejected, SeverityMedium, "b"))
	// The digest falls due at 00:00, inside quiet hours: it waits for 07:00.
	g.clk.Set(time.Date(2030, 3, 5, 0, 0, 0, 0, time.UTC))
	g.r.Process(context.Background())
	if g.push.count() != 0 {
		t.Fatal("a digest woke the household")
	}
	g.clk.Set(time.Date(2030, 3, 5, 7, 0, 0, 0, time.UTC))
	g.r.Process(context.Background())
	if g.push.count() != 1 || !g.push.calls[0].Digest {
		t.Fatalf("morning digest: %d", g.push.count())
	}
	// A critical item in the digest is allowed through the window.
	g2 := newRig(t)
	g2.src.set(func(p *Preferences) {
		p.Quiet = QuietPref{Enabled: true, Windows: []QuietWindow{{Start: "22:00", End: "07:00", Allow: SeverityCritical}}}
		p.ImmediateMin = SeverityCritical
		p.Digest = DigestPref{Enabled: true, Every: Duration(time.Hour)}
	})
	g2.clk.Set(time.Date(2030, 3, 4, 23, 0, 0, 0, time.UTC))
	g2.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "h"))
	g2.clk.Advance(2 * time.Hour)
	g2.r.Process(context.Background())
	if g2.push.count() != 0 {
		t.Fatal("high digest item sent in quiet hours")
	}
}

// ---- payload ------------------------------------------------------------------------------

func TestPushPayloadShape(t *testing.T) {
	n := Notification{ID: "a1", Title: "New device: <Tablet> & co", Body: "line one\nline two", URL: "/alarms/a1", Tag: "new-device|dev-1|", Severity: SeverityHigh}
	var got map[string]string
	if err := json.Unmarshal(n.PushPayload(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"title": n.Title, "body": n.Body, "url": "/alarms/a1", "tag": n.Tag, "severity": "high", "id": "a1"}
	if len(got) != len(want) {
		t.Fatalf("fields: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q want %q", k, got[k], v)
		}
	}
	if strings.Contains(string(n.PushPayload()), "\\u003c") {
		t.Fatal("HTML escaping inflates the payload")
	}
}

// Property: whatever the text, the payload is valid JSON and far below the
// 4 KB Web Push limit (the encrypted body adds only 103 bytes).
func TestPushPayloadStaysSmall(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	alphabet := []rune("ab<>&\"\\\n\t\x00\x07é世🙂 ")
	gen := func(n int) string {
		r := make([]rune, n)
		for i := range r {
			r[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(r)
	}
	for i := 0; i < 300; i++ {
		n := Notification{ID: gen(200), Title: gen(rng.Intn(3000)), Body: gen(rng.Intn(6000)), URL: "/" + gen(rng.Intn(2000)), Tag: gen(rng.Intn(1000)), Severity: SeverityCritical}
		b := n.PushPayload()
		if len(b) > 3000 {
			t.Fatalf("payload is %d bytes", len(b))
		}
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		for k, v := range m {
			if !utf8.ValidString(v) {
				t.Fatalf("%s is not valid UTF-8", k)
			}
		}
	}
	if len(Notification{Title: strings.Repeat("a", 5000)}.PushPayload()) > 700 {
		t.Fatal("title not bounded")
	}
}

func TestNotificationForAlarm(t *testing.T) {
	a := alarmOf(TypeNewDevice, SeverityHigh, "k")
	a.Body = ""
	a.Evidence = []Evidence{{"Client", "192.0.2.10"}, {"MAC", "02:00:5e:00:00:01"}}
	p := testPrefs()
	p.PortalURL = "https://shepherd.example.com"
	n := notificationFor(a, p)
	if n.Body != "Client: 192.0.2.10; MAC: 02:00:5e:00:00:01" || n.Click != "https://shepherd.example.com/alarms/k" || n.Tag != "k" || n.ID != a.ID || n.URL != "/alarms/k" {
		t.Fatalf("n = %+v", n)
	}
	if n := notificationFor(a, testPrefs()); n.Click != "" {
		t.Fatalf("click without a portal URL: %q", n.Click)
	}
}

// ---- persistence, log bounds, run loop -------------------------------------------------------

func TestRouterStatePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), DeliveriesFile)
	g := newRig(t, func(o *RouterOptions) { o.Path = path })
	g.push.set(func(Notification) (PushReport, error) { return PushReport{Subscribed: 1, Failed: 1, Err: "503"}, nil })
	g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "h"))
	g.send(t, alarmOf(TypeListUpdateRejected, SeverityMedium, "m"))
	if err := g.r.Save(); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	g2 := newRig(t, func(o *RouterOptions) { o.Path = path; o.Codec = PlainCodec{} })
	if err := g2.r.Load(); err != nil {
		t.Fatal(err)
	}
	retries, items := g2.r.Pending()
	if retries != 1 || items != 1 || len(g2.r.Log("", 10)) != 2 || statusOf(g2, ChannelPush).Failed != 1 {
		t.Fatalf("restored: retries=%d items=%d log=%d", retries, items, len(g2.r.Log("", 10)))
	}
	// A restart does not lose the retry: it runs when due.
	g2.push.set(nil)
	g2.clk.Advance(7 * time.Hour)
	g2.r.Process(context.Background())
	if g2.push.count() != 2 { // the retry and the digest item
		t.Fatalf("push = %d", g2.push.count())
	}
	// Process saves when there is a Path and something changed.
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"status": "ok"`) {
		t.Fatal("Process did not save")
	}
	// Errors: no path is a no-op; a missing file is fine; bad files are errors.
	mem := newRig(t)
	if mem.r.Save() != nil || mem.r.Load() != nil {
		t.Fatal("memory-only")
	}
	missing := newRig(t, func(o *RouterOptions) { o.Path = filepath.Join(t.TempDir(), "none.json") })
	if err := missing.r.Load(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte(`{"version":9}`), 0o600)
	if err := g2.r.Load(); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("version: %v", err)
	}
	os.WriteFile(path, []byte(`nope`), 0o600)
	if err := g2.r.Load(); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("json: %v", err)
	}
	enc := newRig(t, func(o *RouterOptions) { o.Path = path; o.Codec = failCodec{} })
	if err := enc.r.Save(); err == nil {
		t.Fatal("encode error swallowed")
	}
	if retries, _ := enc.r.Pending(); retries != 0 {
		t.Fatal("pending")
	}
	enc.r.mu.Lock()
	dirty := enc.r.dirty
	enc.r.mu.Unlock()
	if !dirty {
		t.Fatal("failed save cleared dirty")
	}
	if DefaultRouterPath("/state") != "/state/deliveries.json" {
		t.Fatal("DefaultRouterPath")
	}
}

func TestDeliveryLogIsBounded(t *testing.T) {
	g := newRig(t, func(o *RouterOptions) { o.MaxLog = 5; o.LogAge = time.Hour })
	for i := 0; i < 8; i++ {
		g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, fmt.Sprint("k", i)))
	}
	log := g.r.Log("", 0)
	if len(log) != 5 || log[0].Title != "Title k7" || log[4].Title != "Title k3" {
		t.Fatalf("log = %d entries, newest %q", len(log), log[0].Title)
	}
	if len(g.r.Log("", 2)) != 2 || len(g.r.Log(ChannelNtfy, 10)) != 0 {
		t.Fatal("limit/channel filter")
	}
	g.clk.Advance(2 * time.Hour)
	g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "fresh"))
	if got := g.r.Log("", 10); len(got) != 1 {
		t.Fatalf("old records not trimmed by age: %d", len(got))
	}
}

func TestRunLoopProcessesRetriesAndSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.json")
	g := newRig(t, func(o *RouterOptions) { o.Path = path; o.PollEvery = time.Minute })
	g.push.set(func(Notification) (PushReport, error) { return PushReport{Subscribed: 1, Failed: 1}, nil })
	g.nt.set(nil)
	g.send(t, alarmOf(TypeUpstreamDown, SeverityHigh, "h"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.r.Run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond) // let Run create its ticker
	g.push.set(nil)
	g.clk.Advance(time.Minute) // the poll fires; the 30s backoff has elapsed
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if g.push.count() >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if g.push.count() < 2 {
		t.Fatal("Run did not retry")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("Run did not save on shutdown")
	}
}

func TestRouterConcurrentHandle(t *testing.T) {
	g := newRig(t, func(o *RouterOptions) { o.Parallel = 3 })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				g.r.Handle(raisedChange(alarmOf(TypeUpstreamDown, SeverityHigh, fmt.Sprint(i, "-", j))))
				g.r.Status()
				g.r.Log("", 5)
				g.r.Pending()
			}
		}()
	}
	wg.Wait()
	g.r.Wait()
	if g.push.count() != 200 {
		t.Fatalf("push = %d", g.push.count())
	}
}

// ---- end to end: engine -> router -------------------------------------------------------------

func TestEngineToRouterEndToEnd(t *testing.T) {
	e, clk, _ := newTestEngine(t)
	push, nt := &fakePusher{}, &fakeNtfy{}
	r := NewRouter(RouterOptions{Source: e, Pusher: push, Ntfy: nt, Clock: clk})
	e.Subscribe(r.Handle)
	// New device (high): immediate. Repeat: no second notification. Muted: none.
	mustRaise(t, e, Event{Type: TypeNewDevice, DeviceID: dev(1), Title: "New device: Tablet"})
	mustRaise(t, e, Event{Type: TypeNewDevice, DeviceID: dev(1), Title: "New device: Tablet"})
	e.CreateRule(RuleSpec{Match: RuleMatch{DeviceIDs: []string{dev(2)}}, Duration: forever()})
	mustRaise(t, e, Event{Type: TypeNewDevice, DeviceID: dev(2)})
	r.Wait()
	if push.count() != 1 {
		t.Fatalf("push = %d, want 1", push.count())
	}
	// A medium alarm waits for the digest; an info alarm (portal only) never goes out.
	mustRaise(t, e, Event{Type: TypeListUpdateRejected})
	mustRaise(t, e, Event{Type: TypePrivateRelay, DeviceID: dev(3)})
	r.Wait()
	if push.count() != 1 {
		t.Fatal("digest item delivered at once")
	}
	if _, items := r.Pending(); items != 1 {
		t.Fatalf("digest items = %d", items)
	}
	// The test notification bypasses everything.
	e.CreateRule(RuleSpec{Match: RuleMatch{Types: []string{TypeTest}}, Duration: forever()})
	mustRaise(t, e, Event{Type: TypeTest, Title: "Test from the portal"})
	r.Wait()
	if push.count() != 2 || push.calls[1].Title != "Test from the portal" {
		t.Fatalf("test notification: %d", push.count())
	}
	// Quiet hours hold a high alarm, which is delivered when they end.
	p := e.Preferences()
	p.Quiet = QuietPref{Enabled: true, Windows: []QuietWindow{{Start: "12:00", End: "13:00", Allow: SeverityCritical}}}
	if err := e.SetPreferences(p); err != nil {
		t.Fatal(err)
	}
	mustRaise(t, e, Event{Type: TypeUpstreamDown})
	r.Wait()
	if push.count() != 2 {
		t.Fatal("delivered inside quiet hours")
	}
	clk.Advance(time.Hour)
	r.Process(context.Background())
	if push.count() != 3 {
		t.Fatalf("held alarm not delivered: %d", push.count())
	}
}
