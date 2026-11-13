// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shepherd/internal/dnsengine"
	"shepherd/internal/traffic"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// rig is an Engine with a clock the test moves and a list of what it found.
type rig struct {
	t   *testing.T
	e   *Engine
	now time.Time
	mu  sync.Mutex
	got []Finding
	dev map[string]DeviceInfo
	tr  *fakeTraffic
}

type fakeTraffic struct {
	totals func(from, to time.Time) map[string]traffic.Delta
	series map[string][]traffic.Point
}

func (f *fakeTraffic) Totals(from, to time.Time) map[string]traffic.Delta { return f.totals(from, to) }
func (f *fakeTraffic) Series(ids []string, from, to time.Time, b traffic.Bucket) []traffic.Point {
	var out []traffic.Point
	for _, p := range f.series[ids[0]] {
		if !p.Time.Before(from) && !p.Time.After(to) {
			out = append(out, p)
		}
	}
	return out
}

func newRig(t *testing.T, withTraffic bool, lim Limits) *rig {
	t.Helper()
	r := &rig{t: t, now: t0, dev: map[string]DeviceInfo{}}
	opt := Options{
		Now:       func() time.Time { return r.now },
		OnFinding: func(f Finding) { r.mu.Lock(); r.got = append(r.got, f); r.mu.Unlock() },
		Device:    func(id string) (DeviceInfo, bool) { d, ok := r.dev[id]; return d, ok },
		Limits:    lim,
	}
	if withTraffic {
		r.tr = &fakeTraffic{totals: func(time.Time, time.Time) map[string]traffic.Delta { return nil }, series: map[string][]traffic.Point{}}
		opt.Traffic = r.tr
	}
	e, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	r.e = e
	return r
}

func (r *rig) ask(dev, name string, mut ...func(*dnsengine.Entry)) {
	q := dnsengine.Entry{Time: r.now, Client: "192.0.2.7", DeviceID: dev, Device: "Dev " + dev, Name: name, Type: "A", Action: "allowed", Rcode: "NOERROR"}
	for _, m := range mut {
		m(&q)
	}
	r.e.Observe(q)
}

func (r *rig) kinds() []Kind {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Kind
	for _, f := range r.got {
		out = append(out, f.Kind)
	}
	return out
}

func (r *rig) only(k Kind) Finding {
	r.t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var hit []Finding
	for _, f := range r.got {
		if f.Kind == k {
			hit = append(hit, f)
		}
	}
	if len(hit) != 1 {
		r.t.Fatalf("want exactly one %s finding, got %d (all: %v)", k, len(hit), r.got)
	}
	return hit[0]
}

func nx(q *dnsengine.Entry) { q.Rcode = "NXDOMAIN" }

func TestEncryptedDNSLookupIsReportedOncePerDay(t *testing.T) {
	r := newRig(t, false, Limits{})
	r.ask("tv", "Chrome.Cloudflare-DNS.com.")
	r.ask("tv", "chrome.cloudflare-dns.com")
	r.ask("tv", "example.com")
	r.ask("tv", "notdns.google.example")
	f := r.only(KindEncryptedDNS)
	if f.Subject != "cloudflare-dns.com" || f.DeviceID != "tv" || !strings.Contains(f.Summary, "Dev tv looked up chrome.cloudflare-dns.com") {
		t.Errorf("finding = %+v", f)
	}
	r.now = r.now.Add(25 * time.Hour)
	r.ask("tv", "dns.google")
	r.ask("tv", "cloudflare-dns.com")
	if got := r.kinds(); len(got) != 3 {
		t.Errorf("a different resolver and a day later should both report, got %v", got)
	}
	// A client the registry cannot name is still reported, by address.
	r.ask("", "dns.quad9.net", func(q *dnsengine.Entry) { q.Device = "" })
	if f := r.got[len(r.got)-1]; f.Device != "192.0.2.7" || f.DeviceID != "" {
		t.Errorf("unnamed client finding = %+v", f)
	}
}

func TestLocalAndEmptyNamesAreIgnored(t *testing.T) {
	r := newRig(t, false, Limits{RandomNames: 2})
	for _, n := range []string{"", "printer", "7.8.9.10.in-addr.arpa", "kq3v9x7ztp2m.local", "x.lan"} {
		r.ask("a", n, nx)
	}
	if len(r.kinds()) != 0 || r.e.Status().Domains != 0 {
		t.Errorf("local names were counted: %v, %d domains", r.kinds(), r.e.Status().Domains)
	}
}

func TestRandomNameBurst(t *testing.T) {
	r := newRig(t, false, Limits{RandomNames: 6})
	random := []string{"kq3v9x7ztp2m.com", "zx81vbnq7rtw.net", "pq9d8f7g6h5j.org", "mnbvcxzlkjhg.info", "wq2e4r6t8y0u.biz", "t5y7u9i1o3pq.com"}
	// Blocked lookups and names that exist do not count.
	r.ask("pc", random[0], nx, func(q *dnsengine.Entry) { q.Action = "blocked" })
	r.ask("pc", "www.example.com")
	for _, n := range random[:5] {
		r.ask("pc", "a."+n, nx)
		r.ask("pc", "b."+n, nx) // the same registrable domain twice is one
	}
	if len(r.kinds()) != 0 {
		t.Fatalf("reported below the threshold: %v", r.kinds())
	}
	r.ask("pc", random[5], nx)
	r.ask("pc", "onemore-kq3v9x7z.com", nx)
	f := r.only(KindRandomNames)
	if !strings.Contains(f.Summary, "6 different domains") || !strings.Contains(f.Summary, "10 minutes") {
		t.Errorf("summary = %q", f.Summary)
	}
	// A new window reports again.
	r.now = r.now.Add(11 * time.Minute)
	for _, n := range random {
		r.ask("pc", n, nx)
	}
	if got := r.kinds(); len(got) != 2 {
		t.Errorf("second window: %v", got)
	}
}

func TestMistypedNamesAreNotABurst(t *testing.T) {
	r := newRig(t, false, Limits{RandomNames: 4})
	for _, n := range []string{"gooogle.com", "facebok.com", "wikipedia-mirror.org", "myoldwebsite.net", "holidayphotos.org"} {
		r.ask("pc", n, nx)
	}
	if len(r.kinds()) != 0 {
		t.Errorf("ordinary names that do not exist were called machine-made: %v", r.kinds())
	}
}

func TestLooksRandom(t *testing.T) {
	for label, want := range map[string]bool{
		"kq3v9x7ztp2m": true, "zxcvbnmlkjhgfd": true, "a1b2c3d4e5": true,
		"google": false, "googleusercontent": false, "wikipedia": false, "short1": false, "aaaaaaaaaaaa": false,
		"my-holiday-photos": false,
	} {
		if got := looksRandom(label); got != want {
			t.Errorf("looksRandom(%q) = %v, want %v", label, got, want)
		}
	}
}

func TestTunnelNames(t *testing.T) {
	r := newRig(t, false, Limits{TunnelNames: 5})
	long := func(i int) string { return fmt.Sprintf("%030d.t.exfil.example.co.uk", i) }
	r.ask("pc", "short.exfil.example.co.uk")
	for i := 0; i < 4; i++ {
		r.ask("pc", long(i))
		r.ask("pc", long(i)) // repeats are one name
	}
	if len(r.kinds()) != 0 {
		t.Fatalf("reported below the threshold: %v", r.kinds())
	}
	r.ask("pc", long(4))
	for i := 5; i < 20; i++ {
		r.ask("pc", long(i)) // reported once per window
	}
	f := r.only(KindTunnel)
	if f.Subject != "example.co.uk" || !strings.Contains(f.Summary, "5 different long names under example.co.uk") {
		t.Errorf("finding = %+v", f)
	}
}

func TestBeacon(t *testing.T) {
	lim := Limits{Learning: 24 * time.Hour, BeaconIntervals: 5}
	r := newRig(t, false, lim)
	// During learning, a name asked on a metronome is just part of the
	// network's past.
	for i := 0; i < 10; i++ {
		r.ask("cam", "old.vendor-cloud.example")
		r.now = r.now.Add(time.Minute)
	}
	r.now = t0.Add(25 * time.Hour)
	for i := 0; i < 10; i++ {
		r.ask("cam", "old.vendor-cloud.example") // known since learning: never a beacon
		r.ask("cam", "c2.newthing.example")
		r.ask("cam", "c2.newthing.example") // an immediate repeat is the same event
		r.now = r.now.Add(time.Minute)
	}
	f := r.only(KindBeacon)
	if f.Subject != "c2.newthing.example" || !strings.Contains(f.Summary, "Dev cam has looked up c2.newthing.example every 1m0s, 6 times in a row") {
		t.Errorf("finding = %+v", f)
	}
}

func TestBeaconNeedsOneDeviceAndAnEvenRhythm(t *testing.T) {
	lim := Limits{Learning: time.Hour, BeaconIntervals: 5}
	r := newRig(t, false, lim)
	r.now = t0.Add(2 * time.Hour)
	// Two devices asking for the same new name: a service.
	for i := 0; i < 10; i++ {
		r.ask("a", "api.newservice.example")
		r.ask("b", "api.newservice.example")
		r.now = r.now.Add(time.Minute)
	}
	// One device, uneven gaps: a person.
	for _, gap := range []int{30, 400, 55, 900, 120, 31, 600, 45, 300, 77} {
		r.ask("a", "www.newsite.example")
		r.now = r.now.Add(time.Duration(gap) * time.Second)
	}
	// One device, even gaps, then a pause longer than any rhythm, which
	// starts the count again.
	for i := 0; i < 4; i++ {
		r.ask("a", "poll.paused.example")
		r.now = r.now.Add(time.Minute)
	}
	r.now = r.now.Add(3 * time.Hour)
	for i := 0; i < 4; i++ {
		r.ask("a", "poll.paused.example")
		r.now = r.now.Add(time.Minute)
	}
	// A blocked name never reached anything.
	for i := 0; i < 10; i++ {
		r.ask("a", "blocked.newbad.example", func(q *dnsengine.Entry) { q.Action = "blocked" })
		r.now = r.now.Add(time.Minute)
	}
	if len(r.kinds()) != 0 {
		t.Errorf("findings = %v", r.got)
	}
}

func TestNewCountryOnlyForNarrowMatureDevices(t *testing.T) {
	lim := Limits{Learning: 24 * time.Hour, MatureQueries: 3}
	r := newRig(t, false, lim)
	r.dev["cam"] = DeviceInfo{Name: "Camera", Narrow: true}
	r.dev["mac"] = DeviceInfo{Name: "Laptop"}
	to := func(c string) func(*dnsengine.Entry) {
		return func(q *dnsengine.Entry) { q.Dests = []dnsengine.Dest{{IP: "192.0.2.1", Country: c}} }
	}
	for _, d := range []string{"cam", "mac"} {
		r.ask(d, "cloud.vendor.example", to("US"))
		r.ask(d, "cdn.vendor.example", to("de"))
		r.ask(d, "x.vendor.example", to("")) // no country: nothing to learn
	}
	r.now = t0.Add(25 * time.Hour)
	r.ask("cam", "cloud.vendor.example", to("US"))
	r.ask("cam", "blocked.example", to("RU"), func(q *dnsengine.Entry) { q.Action = "blocked" })
	if len(r.kinds()) != 0 {
		t.Fatalf("known country or blocked lookup reported: %v", r.got)
	}
	r.ask("cam", "upload.elsewhere.example", to("CN"))
	r.ask("cam", "upload.elsewhere.example", to("CN")) // once per country
	r.ask("mac", "upload.elsewhere.example", to("CN")) // a laptop goes everywhere
	r.ask("ghost", "upload.elsewhere.example", to("CN"))
	f := r.only(KindNewCountry)
	if f.DeviceID != "cam" || f.Subject != "CN" || !strings.Contains(f.Summary, "only ever resolved to US, DE") {
		t.Errorf("finding = %+v", f)
	}
}

func TestSilentDevice(t *testing.T) {
	r := newRig(t, true, Limits{})
	r.dev["tv"] = DeviceInfo{Name: "TV"}
	r.dev["chatty"] = DeviceInfo{Name: "Phone"}
	r.dev["nas"] = DeviceInfo{Name: "NAS", Skip: true}
	big := traffic.Delta{Up: 100 << 20, Down: 400 << 20}
	r.tr.totals = func(from, to time.Time) map[string]traffic.Delta {
		if to.Sub(from) != 24*time.Hour {
			return nil
		}
		return map[string]traffic.Delta{"tv": big, "chatty": big, "nas": big, "stranger": big, "idle": {Up: 1 << 20}}
	}
	r.ask("chatty", "example.com")
	r.e.Tick(r.now.Add(time.Hour))
	if len(r.kinds()) != 0 {
		t.Fatalf("reported before a full day of watching: %v", r.got)
	}
	// The first tick only starts the device's clock: it has not been
	// watched for a day yet.
	r.now = t0.Add(25 * time.Hour)
	r.ask("chatty", "example.com")
	r.e.Tick(r.now)
	if len(r.kinds()) != 0 {
		t.Fatalf("reported a device first seen this tick: %v", r.got)
	}
	r.now = t0.Add(50 * time.Hour)
	r.ask("chatty", "example.com")
	r.e.Tick(r.now)
	f := r.only(KindSilentDNS)
	if f.DeviceID != "tv" || !strings.Contains(f.Summary, "TV moved 500.0 MiB in the last 24 hours") || f.Evidence[2].Value != "never" {
		t.Errorf("finding = %+v", f)
	}
	r.e.Tick(r.now.Add(time.Hour)) // quiet for a week
	r.e.Tick(r.now.Add(8 * 24 * time.Hour))
	if got := r.kinds(); len(got) != 3 { // tv again, and chatty, silent for 8 days
		t.Errorf("after a week: %v", r.got)
	}
	if last := r.got[len(r.got)-2]; last.DeviceID != "chatty" || !strings.Contains(last.Evidence[2].Value, "2026") {
		t.Errorf("a device that went silent should say when it last asked: %+v", last)
	}
}

func TestUploadSpike(t *testing.T) {
	r := newRig(t, true, Limits{})
	for _, id := range []string{"steady", "spike", "new", "newbig", "skip"} {
		r.dev[id] = DeviceInfo{Name: "Dev " + id, Skip: id == "skip"}
	}
	hours := func(n int, up uint64) []traffic.Point {
		var out []traffic.Point
		for i := 0; i < n; i++ {
			out = append(out, traffic.Point{Time: t0.Add(-time.Duration(i+3) * time.Hour), Up: up})
		}
		// The hour being judged must not count as its own history.
		return append(out, traffic.Point{Time: t0.Add(-30 * time.Minute), Up: 50 << 30})
	}
	r.tr.series["steady"] = hours(48, 2<<30)
	r.tr.series["spike"] = hours(48, 500<<20)
	r.tr.series["new"] = hours(3, 1<<20)
	r.tr.series["newbig"] = hours(3, 1<<20)
	r.tr.totals = func(from, to time.Time) map[string]traffic.Delta {
		if to.Sub(from) != time.Hour {
			return nil
		}
		return map[string]traffic.Delta{
			"steady": {Up: 3 << 30}, "spike": {Up: 2 << 30}, "new": {Up: 4 << 30}, "newbig": {Up: 12 << 30},
			"skip": {Up: 90 << 30}, "small": {Up: 1 << 20}, "stranger": {Up: 90 << 30},
		}
	}
	r.e.Tick(r.now)
	r.e.Tick(r.now.Add(time.Hour)) // quiet for six hours
	got := map[string]Finding{}
	for _, f := range r.got {
		if f.Kind != KindUploadSpike {
			t.Fatalf("unexpected %+v", f)
		}
		got[f.DeviceID] = f
	}
	if len(r.got) != 2 || got["spike"].DeviceID == "" || got["newbig"].DeviceID == "" {
		t.Fatalf("findings = %+v", r.got)
	}
	if s := got["spike"].Summary; !strings.Contains(s, "uploaded 2.0 GiB in the last hour") || !strings.Contains(s, "busiest hour on record before this was 500.0 MiB") {
		t.Errorf("summary = %q", s)
	}
	if !strings.Contains(got["newbig"].Summary, "under a day of history") {
		t.Errorf("summary = %q", got["newbig"].Summary)
	}
	// After the quiet period the device with no history reports again. The
	// other does not: the 50 GiB hour is now part of its record, so 2 GiB
	// is no longer out of the ordinary.
	r.e.Tick(r.now.Add(7 * time.Hour))
	if len(r.got) != 3 || r.got[2].DeviceID != "newbig" {
		t.Errorf("after the quiet period: %+v", r.got)
	}
}

func TestTickWithoutTrafficDoesNothing(t *testing.T) {
	r := newRig(t, false, Limits{})
	r.e.Tick(r.now.Add(100 * time.Hour))
	if len(r.kinds()) != 0 || r.e.Status().Traffic {
		t.Error("traffic checks ran without a traffic source")
	}
}

func TestStateSurvivesARestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub")
	now := t0
	opt := Options{Dir: dir, Now: func() time.Time { return now }}
	e, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	e.Observe(dnsengine.Entry{Time: now, DeviceID: "cam", Name: "cloud.vendor.example", Action: "allowed", Dests: []dnsengine.Dest{{Country: "US"}}})
	if err := e.Save(); err != nil {
		t.Fatal(err)
	}
	if err := e.Save(); err != nil { // nothing changed: nothing written
		t.Fatal(err)
	}
	now = t0.Add(48 * time.Hour)
	e2, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	st := e2.Status()
	if !st.Started.Equal(t0) || st.Devices != 1 || st.Domains != 1 || !st.Learning || !st.LearningUntil.Equal(t0.Add(7*24*time.Hour)) {
		t.Errorf("status after restart = %+v", st)
	}
	if got := e2.st.Devices["cam"].Countries; len(got) != 1 || got[0] != "US" {
		t.Errorf("countries = %v", got)
	}
	if len(e2.Recent()) != 0 {
		t.Error("recent findings should start empty")
	}
}

func TestUnreadableStateStartsFresh(t *testing.T) {
	for name, body := range map[string]string{
		"garbage": "{", "version": `{"version":9,"started":"2026-01-01T00:00:00Z"}`,
		"nulls": `{"version":1,"started":"2026-01-01T00:00:00Z","devices":{"x":null}}`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		e, err := New(Options{Dir: dir, Now: func() time.Time { return t0 }})
		if name == "nulls" {
			if err != nil || len(e.st.Devices) != 0 || e.st.Domains == nil {
				t.Errorf("%s: err=%v state=%+v", name, err, e.st)
			}
			continue
		}
		if err == nil || !e.st.Started.Equal(t0) {
			t.Errorf("%s: err=%v started=%v", name, err, e.st.Started)
		}
		e.Observe(dnsengine.Entry{Name: "example.com", Client: "10.0.0.9"}) // usable, and the clock fills a zero time
		if e.Status().Domains != 1 {
			t.Errorf("%s: engine not usable after a bad state file", name)
		}
	}
	// A state path that is a directory is an error to report, not a crash.
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, stateFile), 0o750)
	e, err := New(Options{Dir: dir})
	if err == nil || e == nil {
		t.Errorf("directory as state file: err=%v", err)
	}
	if err := e.Save(); err == nil {
		t.Error("saving over a directory should fail")
	}
	e2, _ := New(Options{Dir: filepath.Join(dir, stateFile, "x", "\x00")})
	if err := e2.Save(); err == nil {
		t.Error("saving into an impossible directory should fail")
	}
}

func TestRunTicksAndSavesOnExit(t *testing.T) {
	dir := t.TempDir()
	r := &rig{t: t, now: t0.Add(100 * time.Hour), dev: map[string]DeviceInfo{"tv": {Name: "TV"}}}
	ticked := make(chan struct{}, 8)
	tr := &fakeTraffic{totals: func(time.Time, time.Time) map[string]traffic.Delta {
		select {
		case ticked <- struct{}{}:
		default:
		}
		return nil
	}}
	e, err := New(Options{Dir: dir, Now: func() time.Time { return r.now }, Traffic: tr})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx, time.Millisecond); close(done) }()
	<-ticked
	e.Observe(dnsengine.Entry{Time: r.now, DeviceID: "tv", Name: "example.com"})
	cancel()
	<-done
	if _, err := os.Stat(filepath.Join(dir, stateFile)); err != nil {
		t.Errorf("state not saved on exit: %v", err)
	}
}

func TestBoundsHold(t *testing.T) {
	r := newRig(t, false, Limits{Learning: time.Hour, RandomNames: 1 << 30, TunnelNames: 1 << 30})
	// More recent findings than are kept.
	for i := 0; i < recentMax+10; i++ {
		r.ask(fmt.Sprintf("d%d", i), "dns.google")
	}
	if got := r.e.Recent(); len(got) != recentMax || got[0].DeviceID != fmt.Sprintf("d%d", recentMax+9) {
		t.Errorf("recent: %d, newest %s", len(got), got[0].DeviceID)
	}
	if r.e.Status().Findings != recentMax+10 {
		t.Errorf("total = %d", r.e.Status().Findings)
	}
	// Burst maps stop growing at their cap.
	for i := 0; i < maxWindowKeys+20; i++ {
		r.ask("pc", fmt.Sprintf("n%d.example", i), nx)
		r.ask("pc", fmt.Sprintf("%040d.t%d.example", i, i))
	}
	if w := r.e.wins["pc"]; len(w.nx) != maxWindowKeys || len(w.tun) != maxWindowKeys {
		t.Errorf("window grew to %d / %d", len(w.nx), len(w.tun))
	}
	// The rhythm tables reset rather than grow without bound.
	r.now = t0.Add(2 * time.Hour)
	for i := 0; i < maxBeats+5; i++ {
		r.ask("pc", fmt.Sprintf("b%d.example", i))
	}
	if len(r.e.beats) > maxBeats || len(r.e.askers) > maxBeats {
		t.Errorf("beats %d askers %d", len(r.e.beats), len(r.e.askers))
	}
	// The quiet table sheds entries older than the longest quiet period.
	r.e.mu.Lock()
	for i := 0; i < maxBeats; i++ {
		r.e.quiet[fmt.Sprint("old", i)] = t0.Add(-30 * 24 * time.Hour)
	}
	r.e.quietLocked("fresh", r.now, time.Hour)
	n := len(r.e.quiet)
	r.e.mu.Unlock()
	if n > recentMax+20 {
		t.Errorf("quiet table kept %d entries", n)
	}
	// Idle burst windows are dropped once there are too many devices.
	r.e.mu.Lock()
	for i := 0; i < maxDevices; i++ {
		r.e.wins[fmt.Sprint("w", i)] = &window{start: t0.Add(-time.Hour)}
	}
	r.e.windowLocked("another", r.now)
	n = len(r.e.wins)
	// And the device table stops taking new devices at its cap.
	for i := len(r.e.st.Devices); i < maxDevices; i++ {
		r.e.st.Devices[fmt.Sprint("x", i)] = &devState{}
	}
	full := r.e.deviceLocked("one-too-many", r.now)
	r.e.mu.Unlock()
	if n > 10 || full != nil {
		t.Errorf("windows kept %d, device past the cap = %v", n, full)
	}
	r.ask("one-too-many", "example.org") // must not panic without a device record
}

func TestWording(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Hour: "1 hour", 24 * time.Hour: "24 hours", time.Minute: "1 minute", 10 * time.Minute: "10 minutes", 90 * time.Second: "1m30s"} {
		if got := span(d); got != want {
			t.Errorf("span(%v) = %q, want %q", d, got, want)
		}
	}
	for n, want := range map[uint64]string{512: "512 B", 2048: "2.0 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB", 2 << 40: "2.0 TiB", 4096 << 40: "4096.0 TiB"} {
		if got := bytesText(n); got != want {
			t.Errorf("bytesText(%d) = %q, want %q", n, got, want)
		}
	}
	if registrable("com") != "com" || firstLabel("single") != "single" {
		t.Error("names without a registrable domain should pass through")
	}
	if s := sample(map[string]bool{"c": true, "a": true, "b": false}, 2); s != "a, b" {
		t.Errorf("sample = %q", s)
	}
}
