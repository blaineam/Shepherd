// SPDX-License-Identifier: AGPL-3.0-or-later

package classify

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"shepherd/internal/devices"
)

// lab is a registry plus a classifier wired together over a fake clock.
type lab struct {
	t    *testing.T
	reg  *devices.Registry
	c    *Classifier
	clk  *fakeClock
	n    int
	vend map[string]string
}

func newLab(t *testing.T, mod ...func(*Options)) *lab {
	t.Helper()
	l := &lab{t: t, vend: map[string]string{}}
	clk := &fakeClock{t: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	l.clk = clk
	seq := 0
	l.reg = devices.New(devices.Options{
		NodeID: "node-a", Now: clk.Now,
		NewID:  func() string { seq++; return fmt.Sprintf("t-%d", seq) },
		Vendor: func(mac string) string { return l.vend[mac] },
	})
	o := Options{Now: clk.Now, ASN: fakeASN}
	for _, m := range mod {
		m(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	c.UseRegistry(l.reg)
	l.c = c
	return l
}

// device adds a device; vendor "" with random=true makes a locally administered MAC.
func (l *lab) device(vendor string, random bool) (id, ip string) {
	l.n++
	ip = fmt.Sprintf("192.0.2.%d", 10+l.n)
	mac := fmt.Sprintf("00:00:5e:00:00:%02x", l.n)
	if random {
		mac = fmt.Sprintf("02:00:5e:00:00:%02x", l.n)
	}
	l.vend[mac] = vendor
	id = l.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: mac, IP: ip})
	return id, ip
}

func (l *lab) get(id string) devices.Device {
	d, ok := l.reg.Get(id)
	if !ok {
		l.t.Fatalf("device %s missing", id)
	}
	return d
}

func TestApplyWritesGuessesButNeverOverTheUsersChoice(t *testing.T) {
	l := newLab(t)
	cam, camIP := l.device("Reolink Innovation", false)
	tv, tvIP := l.device("", true)
	unk, _ := l.device("Obscure Widgets", false)
	mine, mineIP := l.device("Hangzhou Hikvision Digital Technology", false)

	look(l.c, camIP, "p2p.reolink.com", "203.0.113.10", 40)
	look(l.c, tvIP, "app.lgappstv.com", "203.0.113.11", 30)
	look(l.c, tvIP, "us.lgtvsdp.com", "203.0.113.12", 30)
	look(l.c, mineIP, "ius.hik-connect.com", "203.0.113.13", 50)

	if err := l.reg.SetType(mine, "tv"); err != nil { // the user says it is a TV, whatever the evidence says
		t.Fatal(err)
	}
	rep := l.c.Apply(l.reg)
	if rep.Examined != 4 || rep.Changed != 2 || rep.Skipped != 1 || rep.Cleared != 0 {
		t.Errorf("report = %+v", rep)
	}

	d := l.get(cam)
	if d.Type != devices.TypeCamera || !d.TypeAuto || d.TypeUser || d.TypeConfidence < 0.8 || !strings.Contains(d.TypeReason, "camera cloud") {
		t.Errorf("camera = %+v", d)
	}
	d = l.get(tv)
	if d.Type != devices.TypeTV || !d.TypeAuto || d.TypeConfidence < 0.8 {
		t.Errorf("tv = %+v", d)
	}
	if d := l.get(unk); d.TypeAuto || d.Type != devices.TypeUnknown {
		t.Errorf("an unclassifiable device must stay unknown: %+v", d)
	}
	d = l.get(mine)
	if d.Type != devices.TypeTV || !d.TypeUser || d.TypeAuto {
		t.Errorf("the user's choice must win: %+v", d)
	}

	// More camera evidence, many passes: the user's choice survives all of it.
	for i := 0; i < 5; i++ {
		look(l.c, mineIP, "ius.hik-connect.com", "203.0.113.13", 50)
		l.c.Apply(l.reg)
	}
	if d := l.get(mine); d.Type != devices.TypeTV || !d.TypeUser {
		t.Errorf("the user's choice did not survive: %+v", d)
	}
	if got := l.c.Classify(mine); got.Type != devices.TypeCamera {
		t.Errorf("the classifier still has its own opinion: %s", describe(got))
	}

	// Handing the choice back to automatic lets the classifier speak again.
	if err := l.reg.SetType(mine, "auto"); err != nil {
		t.Fatal(err)
	}
	l.c.Apply(l.reg)
	if d := l.get(mine); d.Type != devices.TypeCamera || !d.TypeAuto || d.TypeUser {
		t.Errorf("after auto: %+v", d)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	l := newLab(t)
	id, ip := l.device("Sonos", false)
	look(l.c, ip, "update.sonos.com", "203.0.113.20", 25)
	if rep := l.c.Apply(l.reg); rep.Changed != 1 {
		t.Fatalf("first pass: %+v", rep)
	}
	stamp := l.get(id).Updated
	for i := 0; i < 3; i++ {
		if rep := l.c.Apply(l.reg); rep.Changed != 0 || rep.Cleared != 0 {
			t.Errorf("pass %d changed things: %+v", i+2, rep)
		}
	}
	if l.get(id).Updated != stamp {
		t.Error("an idempotent pass must not re-stamp the device (it would churn the sync log)")
	}
}

func TestHysteresisDoesNotFlap(t *testing.T) {
	l := newLab(t)
	id, ip := l.device("", true)
	// A device whose lookups swing between two classes of nearly equal weight.
	look(l.c, ip, "app.lgappstv.com", "203.0.113.30", 12)
	look(l.c, ip, "update.sonos.com", "203.0.113.31", 2)
	l.c.Apply(l.reg)
	first := l.get(id).Type
	mustType(t, first, devices.TypeTV, "starting guess")

	changes := 0
	prev := first
	for round := 0; round < 40; round++ {
		if round%2 == 0 {
			look(l.c, ip, "update.sonos.com", "203.0.113.31", 3)
		} else {
			look(l.c, ip, "app.lgappstv.com", "203.0.113.30", 3)
		}
		l.clk.Advance(10 * time.Minute)
		l.c.Apply(l.reg)
		if cur := l.get(id).Type; cur != prev {
			changes++
			prev = cur
		}
	}
	if changes > 1 {
		t.Errorf("the type flapped %d times (final %s)", changes, prev)
	}
}

func TestEvidenceThatClearlyChangesTheStoryChangesTheGuess(t *testing.T) {
	l := newLab(t)
	id, ip := l.device("", true)
	look(l.c, ip, "app.lgappstv.com", "203.0.113.30", 30)
	l.c.Apply(l.reg)
	mustType(t, l.get(id).Type, devices.TypeTV, "starting guess")
	// The same address is now a camera: weeks of camera traffic, no TV traffic.
	for week := 0; week < 6; week++ {
		l.clk.Advance(7 * 24 * time.Hour)
		look(l.c, ip, "ius.hik-connect.com", "203.0.113.31", 60)
		look(l.c, ip, "dev.ezvizlife.com", "203.0.113.32", 60)
		l.c.Apply(l.reg)
	}
	d := l.get(id)
	if d.Type != devices.TypeCamera || !d.TypeAuto {
		t.Errorf("a real change of behaviour must change the guess: %+v", d)
	}
}

func TestStaleGuessIsWithdrawnOnlyWhenThereIsEvidenceAgainstIt(t *testing.T) {
	l := newLab(t)
	id, ip := l.device("", true)
	look(l.c, ip, "app.lgappstv.com", "203.0.113.30", 30)
	l.c.Apply(l.reg)
	mustType(t, l.get(id).Type, devices.TypeTV, "starting guess")

	// A restart loses the in-memory evidence; that is not evidence against the guess.
	fresh, _ := New(Options{Now: l.clk.Now, ASN: fakeASN})
	fresh.UseRegistry(l.reg)
	if rep := fresh.Apply(l.reg); rep.Cleared != 0 {
		t.Errorf("no evidence is not evidence against: %+v", rep)
	}
	if d := l.get(id); d.Type != devices.TypeTV || !d.TypeAuto {
		t.Errorf("the stored guess must survive a restart: %+v", d)
	}

	// Weeks later the device only does unrelated things: now the guess is stale.
	l.clk.Advance(28 * 24 * time.Hour)
	for i := 0; i < 12; i++ {
		l.c.Observe(ip, fmt.Sprintf("site%d.example.com", i), ips("203.0.113.40"))
	}
	rep := l.c.Apply(l.reg)
	if rep.Cleared != 1 {
		t.Fatalf("a guess whose evidence has faded should be withdrawn: %+v", rep)
	}
	if d := l.get(id); d.TypeAuto || d.TypeConfidence != 0 || d.Type != devices.TypeUnknown {
		t.Errorf("after withdrawal the registry's own guess returns: %+v", d)
	}
}

func TestFoldMovesIPKeyedEvidenceOntoTheDevice(t *testing.T) {
	l := newLab(t)
	l.c.SetResolver(nil) // nothing resolves, so evidence is kept under the client IP
	id, ip := l.device("", true)
	look(l.c, ip, "ius.hik-connect.com", "203.0.113.50", 60)
	if _, ok := l.c.Retained(ip); !ok {
		t.Fatal("evidence should be kept under the IP until a device claims it")
	}
	mustType(t, l.c.Classify(id).Type, devices.TypeUnknown, "before folding")
	l.c.Apply(l.reg)
	if _, ok := l.c.Retained(ip); ok {
		t.Error("the IP-keyed entry should have been folded away")
	}
	if d := l.get(id); d.Type != devices.TypeCamera {
		t.Errorf("folded evidence should classify the device: %+v", d)
	}
	ret, _ := l.c.Retained(id)
	if len(ret.Domains) != 1 || ret.Domains[0].Domain != "hik-connect.com" || ret.Lookups < 50 {
		t.Errorf("folded retention = %+v", ret)
	}
	// Folding into itself or from nothing is harmless.
	l.c.fold(id, id)
	l.c.fold("192.0.2.222", id)
}

func TestUseRegistryResolvesClientsToDevices(t *testing.T) {
	l := newLab(t)
	id, ip := l.device("", true)
	look(l.c, ip, "www.example.com", "203.0.113.5", 3)
	if _, ok := l.c.Retained(id); !ok {
		t.Error("a lookup from a known client should land on its device")
	}
	if _, ok := l.c.Retained(ip); ok {
		t.Error("nothing should be kept under the bare IP for a known device")
	}
	look(l.c, "192.0.2.199", "www.example.com", "203.0.113.5", 1)
	if _, ok := l.c.Retained("192.0.2.199"); !ok {
		t.Error("an unknown client is kept under its IP until the registry learns it")
	}
}

func TestSuggestionsOfferGroupsFromClasses(t *testing.T) {
	l := newLab(t)
	var cams []string
	for i := 0; i < 3; i++ {
		id, ip := l.device("", true)
		look(l.c, ip, "p2p.hik-connect.com", "203.0.113.60", 40)
		cams = append(cams, id)
	}
	// A doorbell joins the camera group.
	bell, bellIP := l.device("", true)
	look(l.c, bellIP, "fw.ring.com", "203.0.113.61", 60)
	look(l.c, bellIP, "api.ring.com", "203.0.113.62", 30)
	tv1, tv1IP := l.device("Vizio", false)
	look(l.c, tv1IP, "tvinteract.vizio.com", "203.0.113.63", 30)
	tv2, ip2 := l.device("Roku", false)
	look(l.c, ip2, "scribe.roku.com", "203.0.113.64", 30)
	lonely, ip3 := l.device("Brother Industries", false)
	l.reg.Observe(devices.Observation{Source: devices.SourceMDNS, IP: ip3, Services: []string{"_ipp._tcp"}})
	userTV, userIP := l.device("", true)
	_ = userIP
	if err := l.reg.SetType(userTV, "tv"); err != nil {
		t.Fatal(err)
	}
	unk, _ := l.device("Obscure Widgets", false)

	if got := l.c.Suggestions(); len(got) != 0 {
		t.Errorf("nothing has been classified yet: %v", got)
	}
	l.c.Apply(l.reg)
	sug := l.c.Suggestions()
	byName := map[string]Suggestion{}
	for _, s := range sug {
		byName[s.Name] = s
	}
	cm := byName["Cameras"]
	if cm.Count != 4 || cm.Label != "Cameras (4 devices)" || len(cm.DeviceIDs) != 4 {
		t.Errorf("cameras = %+v", cm)
	}
	for _, id := range append(cams, bell) {
		if !containsStr(cm.DeviceIDs, id) {
			t.Errorf("%s missing from the camera group", id)
		}
	}
	if len(cm.Types) != 2 {
		t.Errorf("cameras and doorbells fold together: %v", cm.Types)
	}
	tvs := byName["TVs and streaming"]
	if tvs.Count != 3 || tvs.Label != "TVs and streaming (3 devices)" || !containsStr(tvs.DeviceIDs, tv1) || !containsStr(tvs.DeviceIDs, tv2) || !containsStr(tvs.DeviceIDs, userTV) {
		t.Errorf("tvs = %+v (the user's TV counts like a guessed one)", tvs)
	}
	if _, ok := byName["Printers"]; ok {
		t.Errorf("a group of one is not worth a click: %v (%s)", byName["Printers"], lonely)
	}
	for _, s := range sug {
		if containsStr(s.DeviceIDs, unk) {
			t.Errorf("unknown devices are never grouped: %+v", s)
		}
	}
	if len(sug) != 2 || sug[0].Name != "Cameras" {
		t.Errorf("suggestions should be ordered by size: %+v", sug)
	}

	// A group the user already has is not offered again.
	if _, err := l.reg.CreateGroup("cameras", ""); err != nil {
		t.Fatal(err)
	}
	l.c.Apply(l.reg)
	for _, s := range l.c.Suggestions() {
		if s.Name == "Cameras" {
			t.Errorf("an existing group was suggested again: %+v", s)
		}
	}
}

func TestRunAppliesPeriodicallyAndStops(t *testing.T) {
	l := newLab(t)
	id, ip := l.device("", true)
	look(l.c, ip, "ius.hik-connect.com", "203.0.113.70", 60)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.c.Run(ctx, l.reg, 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for l.get(id).Type != devices.TypeCamera && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// New evidence is picked up by a later pass without anyone calling Apply.
	id2, ip2 := l.device("", true)
	look(l.c, ip2, "api.wyzecam.com", "203.0.113.71", 40)
	look(l.c, ip2, "api.wyzecam.com", "203.0.113.71", 40)
	for l.get(id2).Type != devices.TypeCamera && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
	if l.get(id).Type != devices.TypeCamera || l.get(id2).Type != devices.TypeCamera {
		t.Error("Run should have classified both devices")
	}
	// A zero interval falls back to a default rather than spinning.
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { l.c.Run(ctx2, l.reg, 0); close(done2) }()
	cancel2()
	<-done2
}

func TestApplyToleratesTargetsWithoutOptionalMethods(t *testing.T) {
	// A target with only the three required methods works; folding and
	// group-awareness are simply skipped.
	l := newLab(t)
	id, ip := l.device("Sonos", false)
	look(l.c, ip, "update.sonos.com", "203.0.113.20", 25)
	var plain Target = struct{ Target }{l.reg}
	if rep := l.c.Apply(plain); rep.Changed != 1 {
		t.Errorf("report = %+v", rep)
	}
	if l.get(id).Type != devices.TypeSpeaker {
		t.Error("speaker expected")
	}
}

type failingTarget struct{ Target }

func (failingTarget) SetGuessedType(string, devices.DeviceType, string, float64) (bool, error) {
	return false, devices.ErrNotFound
}
func (failingTarget) ClearGuessedType(string) (bool, error) { return false, devices.ErrNotFound }

func TestApplyCountsOnlyWhatActuallyChanged(t *testing.T) {
	l := newLab(t)
	_, ip := l.device("Sonos", false)
	look(l.c, ip, "update.sonos.com", "203.0.113.20", 25)
	if rep := l.c.Apply(failingTarget{l.reg}); rep.Changed != 0 || rep.Examined != 1 {
		t.Errorf("errors are not changes: %+v", rep)
	}
	// Withdrawing fails too: counted as nothing.
	id2, ip2 := l.device("", true)
	look(l.c, ip2, "app.lgappstv.com", "203.0.113.30", 30)
	l.c.Apply(l.reg)
	l.clk.Advance(28 * 24 * time.Hour)
	for i := 0; i < 12; i++ {
		l.c.Observe(ip2, fmt.Sprintf("s%d.example.com", i), nil)
	}
	if rep := l.c.Apply(failingTarget{l.reg}); rep.Cleared != 0 {
		t.Errorf("a failed clear is not a clear: %+v", rep)
	}
	_ = id2
}

func TestPruneAndForgetBoundRetention(t *testing.T) {
	l := newLab(t)
	_, ip := l.device("", true)
	look(l.c, ip, "www.example.com", "203.0.113.5", 3)
	look(l.c, "192.0.2.201", "www.example.com", "203.0.113.5", 3)
	if s := l.c.Stats(); s.Devices != 2 {
		t.Fatalf("stats = %+v", s)
	}
	l.clk.Advance(10 * 24 * time.Hour)
	look(l.c, "192.0.2.201", "www.example.com", "203.0.113.5", 1) // still active
	l.clk.Advance(25 * 24 * time.Hour)                            // the first is now 35 days idle, the second 25
	if n := l.c.Prune(); n != 1 {
		t.Errorf("pruned %d, want 1", n)
	}
	if s := l.c.Stats(); s.Devices != 1 {
		t.Errorf("stats after prune = %+v", s)
	}
	l.c.Forget("192.0.2.201")
	if s := l.c.Stats(); s.Devices != 0 {
		t.Errorf("stats after forget = %+v", s)
	}
}

func TestEvidenceDecaysAndFades(t *testing.T) {
	c, clk := newClassifier(t, func(o *Options) { o.HalfLife = 24 * time.Hour })
	c.SetResolver(func(string) string { return "d" })
	c.ObserveDevice("d", "", nil, false)
	look(c, "192.0.2.80", "ius.hik-connect.com", "203.0.113.10", 50)
	r0 := c.Classify("d")
	mustType(t, r0.Type, devices.TypeCamera, describe(r0))
	clk.Advance(24 * time.Hour)
	r1 := c.Classify("d")
	if !(r1.Score(devices.TypeCamera) < r0.Score(devices.TypeCamera)) {
		t.Errorf("evidence should fade: %.3f -> %.3f", r0.Score(devices.TypeCamera), r1.Score(devices.TypeCamera))
	}
	ret, _ := c.Retained("d")
	if ret.Lookups > 26 || ret.Lookups < 24 {
		t.Errorf("one half-life should halve the lookups: %v", ret.Lookups)
	}
	clk.Advance(20 * 24 * time.Hour)
	ret, _ = c.Retained("d")
	if len(ret.Domains) != 0 || ret.Lookups > 0.001 {
		t.Errorf("long-faded evidence should be gone: %+v", ret)
	}
	// Short gaps do not pay for decay at all.
	e := c.st.shardFor("d").m["d"]
	at := e.decayAt
	clk.Advance(10 * time.Second)
	c.Observe("192.0.2.80", "ius.hik-connect.com", nil)
	if !e.decayAt.Equal(at) {
		t.Error("decay should be skipped for gaps under a minute")
	}
}

func TestDefaultsAndOptions(t *testing.T) {
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if c.threshold != DefaultThreshold || c.release != DefaultRelease || c.margin != DefaultSwitchMargin ||
		c.minGroup != DefaultMinGroupSize || c.cfg.halfLife != DefaultHalfLife || c.cfg.idleTTL != DefaultIdleTTL ||
		c.cfg.maxDomains != DefaultMaxDomains || c.cfg.maxASNs != DefaultMaxASNs || c.cfg.now == nil {
		t.Errorf("defaults not applied: %+v", c.cfg)
	}
	if c.Rules() == nil || len(c.Rules().Classes()) < 15 {
		t.Error("the embedded rules should be in use")
	}
	c2, _ := New(Options{Threshold: 0.9, Release: 0.8, SwitchMargin: 0.3, MinGroupSize: 5, HalfLife: time.Hour,
		IdleTTL: time.Minute, MaxDevices: 3, MaxDomains: 2, MaxASNs: 1, NonBlocking: true,
		Resolve: func(string) string { return "r" }, ASN: fakeASN})
	if c2.threshold != 0.9 || c2.minGroup != 5 || c2.cfg.maxDomains != 2 || !c2.cfg.nonBlock || c2.resolver.Load() == nil || c2.asnFn.Load() == nil {
		t.Errorf("options not applied: %+v", c2.cfg)
	}
	c2.SetResolver(nil)
	c2.SetASN(nil)
	if c2.resolver.Load() != nil || c2.asnFn.Load() != nil {
		t.Error("nil should clear the hooks")
	}
	bad := RuleFiles{[]byte("{"), nil, nil, nil, nil}
	if _, err := ParseRules(bad); err == nil {
		t.Error("broken rules must be an error")
	}
	if _, err := New(Options{Rules: &RuleSet{}}); err != nil {
		t.Errorf("an empty but valid rule set is allowed: %v", err)
	}
}

func TestHigherThresholdMakesTheClassifierMoreCautious(t *testing.T) {
	c, _ := newClassifier(t, func(o *Options) { o.Threshold = 0.95 })
	c.ObserveDevice("a", "Brother Industries", nil, false)
	if r := c.Classify("a"); r.Type != devices.TypeUnknown || r.Confidence < 0.6 {
		t.Errorf("a 0.7 vendor prior must not pass a 0.95 threshold: %s", describe(r))
	}
}

var _ = atomic.Int32{}
