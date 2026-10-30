// SPDX-License-Identifier: AGPL-3.0-or-later

package geo

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"shepherd/internal/dnsengine"
	"shepherd/internal/settings"
)

// whoamiServer answers the way the real "who am I" services do.
func whoamiServer(t *testing.T, handler func(w dns.ResponseWriter, r *dns.Msg)) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(handler)}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func txtReply(strs ...string) func(w dns.ResponseWriter, r *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: r.Question[0].Qclass}, Txt: strs})
		_ = w.WriteMsg(m)
	}
}

func aReply(ip string) func(w dns.ResponseWriter, r *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(ip).To4()})
		_ = w.WriteMsg(m)
	}
}

func silent(w dns.ResponseWriter, r *dns.Msg) {} // never answers

func refuse(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	_ = w.WriteMsg(m)
}

func TestEachMethodAsksTheRightQuestionAndParsesTheAnswer(t *testing.T) {
	asked := make(chan string, 3)
	cf := whoamiServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		asked <- "cloudflare " + dns.ClassToString[r.Question[0].Qclass] + " " + r.Question[0].Name
		txtReply("198.51.100.23")(w, r)
	})
	g := whoamiServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		asked <- "google " + dns.ClassToString[r.Question[0].Qclass] + " " + r.Question[0].Name
		txtReply("203.0.113.9", "edns0-client-subnet 203.0.113.0/24")(w, r)
	})
	od := whoamiServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		asked <- "opendns " + dns.ClassToString[r.Question[0].Qclass] + " " + r.Question[0].Name
		aReply("192.0.2.77")(w, r)
	})
	wantIP := []string{"198.51.100.23", "203.0.113.9", "192.0.2.77"}
	wantQ := []string{"cloudflare CH whoami.cloudflare.", "google IN o-o.myaddr.l.google.com.", "opendns IN myip.opendns.com."}
	for i, m := range whoamiMethods(cf, g, od) {
		got, err := m.Query(context.Background())
		if err != nil || got.String() != wantIP[i] {
			t.Errorf("%s: got %v err %v, want %s", m.Name, got, err, wantIP[i])
		}
		if q := <-asked; q != wantQ[i] {
			t.Errorf("%s asked %q, want %q (Cloudflare needs a CHAOS TXT question)", m.Name, q, wantQ[i])
		}
	}
}

func TestDetectFallsBackAndRejectsNonPublicAnswers(t *testing.T) {
	good := whoamiServer(t, aReply("198.51.100.44"))
	cases := map[string][]Method{
		"first fails, second works": whoamiMethods("127.0.0.1:1", "127.0.0.1:1", good),
		"private answer is skipped": whoamiMethods(whoamiServer(t, txtReply("10.1.2.3")), whoamiServer(t, txtReply("not an ip")), good),
		"refused is skipped":        whoamiMethods(whoamiServer(t, refuse), whoamiServer(t, txtReply("")), good),
	}
	for name, methods := range cases {
		d := &WANDetector{Methods: methods, Timeout: 300 * time.Millisecond}
		ip, err := d.Detect(context.Background())
		if err != nil || ip.String() != "198.51.100.44" {
			t.Errorf("%s: got %v err %v", name, ip, err)
		}
	}
}

func TestDetectReportsEveryFailure(t *testing.T) {
	d := &WANDetector{
		Methods: whoamiMethods(whoamiServer(t, txtReply("10.0.0.1")), "127.0.0.1:1", whoamiServer(t, silent)),
		Timeout: 200 * time.Millisecond,
	}
	_, err := d.Detect(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"cloudflare", "google", "opendns", "non-public"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
	if _, err := (&WANDetector{}).Detect(context.Background()); err == nil {
		t.Error("no methods configured must be an error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&WANDetector{Methods: whoamiMethods("127.0.0.1:1", "127.0.0.1:1", "127.0.0.1:1")}).Detect(ctx); err == nil {
		t.Error("a cancelled context must stop detection")
	}
	if len(NewWANDetector().Methods) != 3 {
		t.Error("the default detector has three methods")
	}
	empty := whoamiServer(t, func(w dns.ResponseWriter, r *dns.Msg) { m := new(dns.Msg); m.SetReply(r); _ = w.WriteMsg(m) })
	if _, err := whoamiMethods(empty, empty, empty)[0].Query(context.Background()); err == nil {
		t.Error("an answer without an address must be an error")
	}
}

type fakeDetector struct {
	ip    string
	err   error
	calls atomic.Int32
}

func (f *fakeDetector) Detect(context.Context) (net.IP, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return net.ParseIP(f.ip), nil
}

type fakePlacer struct {
	ready atomic.Bool
	dest  dnsengine.Dest
	found bool
}

func (p *fakePlacer) Ready() bool                          { return p.ready.Load() }
func (p *fakePlacer) Locate(net.IP) (dnsengine.Dest, bool) { return p.dest, p.found }

var settingsPath string

func store(t *testing.T) *settings.Store {
	settingsPath = filepath.Join(t.TempDir(), "s.json")
	s, err := settings.Open(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newAuto(t *testing.T, det Detector, pl Placer) (*AutoHome, *settings.Store) {
	st := store(t)
	return &AutoHome{Detector: det, Placer: pl, Store: st, Now: func() time.Time { return october }}, st
}

func TestOnceDetectsRoundsAndSavesWithoutTheAddress(t *testing.T) {
	pl := &fakePlacer{found: true, dest: dnsengine.Dest{Lat: 40.76123, Lon: -111.89456, City: "Testville", Country: "ZZ"}}
	pl.ready.Store(true)
	a, st := newAuto(t, &fakeDetector{ip: "198.51.100.5"}, pl)
	if err := a.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := st.Home()
	if h == nil || h.Source != settings.SourceAuto || h.Label != "Testville, ZZ" || h.Lat != 40.76 || h.Lon != -111.89 || !h.At.Equal(october) {
		t.Errorf("auto home = %+v (coordinates are rounded to about a kilometre)", h)
	}
	for name, d := range map[string]dnsengine.Dest{
		"country only": {Lat: 1, Lon: 1, Country: "ZZ"},
		"city only":    {Lat: 1, Lon: 1, City: "Nowhere"},
	} {
		pl.dest = d
		a.Once(context.Background())
		want := map[string]string{"country only": "ZZ", "city only": "Nowhere"}[name]
		if got := st.Home().Label; got != want {
			t.Errorf("%s label = %q, want %q", name, got, want)
		}
	}
	// The saved file holds a place, never the address it came from.
	b, _ := os.ReadFile(settingsPath)
	if strings.Contains(string(b), "198.51.100.5") {
		t.Error("the public IP must never be persisted")
	}
}

func TestOnceFailureModes(t *testing.T) {
	pl := &fakePlacer{found: true, dest: dnsengine.Dest{Lat: 1, Lon: 1, Country: "ZZ"}}
	a, st := newAuto(t, &fakeDetector{ip: "198.51.100.5"}, pl)
	if err := a.Once(context.Background()); !errors.Is(err, errMapNotReady) {
		t.Errorf("without map data: %v", err)
	}
	pl.ready.Store(true)
	a.Detector = &fakeDetector{err: errors.New("offline")}
	if err := a.Once(context.Background()); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Errorf("detector failure: %v", err)
	}
	a.Detector = &fakeDetector{ip: "198.51.100.5"}
	pl.found = false
	if err := a.Once(context.Background()); err == nil || !strings.Contains(err.Error(), "not in the map data") {
		t.Errorf("unknown location: %v", err)
	}
	pl.found, pl.dest = true, dnsengine.Dest{Lat: 999}
	if err := a.Once(context.Background()); err == nil || !strings.Contains(err.Error(), "saving") {
		t.Errorf("an invalid location must not be saved: %v", err)
	}
	if st.Home() != nil {
		t.Error("a failed detection must leave home unset")
	}
}

func TestRunWaitsForMapDataThenKeepsHomeCurrent(t *testing.T) {
	pl := &fakePlacer{found: true, dest: dnsengine.Dest{Lat: 2, Lon: 3, City: "Testville", Country: "ZZ"}}
	det := &fakeDetector{ip: "198.51.100.5"}
	a, st := newAuto(t, det, pl)
	a.WaitForDB, a.Every = 10*time.Millisecond, 10*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()

	time.Sleep(60 * time.Millisecond)
	if det.calls.Load() != 0 || st.Home() != nil {
		t.Error("nothing is looked up until the map data is ready")
	}
	pl.ready.Store(true)
	waitFor(t, func() bool { return st.Home() != nil })
	waitFor(t, func() bool { return det.calls.Load() >= 3 }) // it keeps re-checking
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRunDoesNothingWhileTheUserHasChosenHome(t *testing.T) {
	pl := &fakePlacer{found: true, dest: dnsengine.Dest{Lat: 2, Lon: 3, Country: "ZZ"}}
	pl.ready.Store(true)
	det := &fakeDetector{ip: "198.51.100.5"}
	a, st := newAuto(t, det, pl)
	st.SetHome(settings.Home{Lat: 9, Lon: 9, Label: "Mine"})
	a.Every = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	time.Sleep(80 * time.Millisecond)
	if det.calls.Load() != 0 {
		t.Errorf("no public-address lookup may happen while the user's home is set (%d calls)", det.calls.Load())
	}
	st.ClearHome() // resetting to automatic resumes detection
	waitFor(t, func() bool { return det.calls.Load() > 0 })
	cancel()
	<-done
}

func TestRunRetriesAfterFailure(t *testing.T) {
	pl := &fakePlacer{found: true, dest: dnsengine.Dest{Lat: 2, Lon: 3, Country: "ZZ"}}
	pl.ready.Store(true)
	det := &fakeDetector{err: errors.New("offline")}
	a, _ := newAuto(t, det, pl)
	a.Retry = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	waitFor(t, func() bool { return det.calls.Load() >= 3 })
	cancel()
	<-done
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not reached in time")
	}
}

func TestAutoHomeDefaults(t *testing.T) {
	a := &AutoHome{}
	a.defaults()
	if a.Every != 6*time.Hour || a.Retry != 15*time.Minute || a.WaitForDB != 20*time.Second || a.Now == nil {
		t.Errorf("defaults = %+v", a)
	}
	custom := &AutoHome{Every: time.Second, Retry: time.Second, WaitForDB: time.Second, Now: func() time.Time { return october }}
	custom.defaults()
	if custom.Every != time.Second || !custom.Now().Equal(october) {
		t.Error("explicit values must be kept")
	}
}
