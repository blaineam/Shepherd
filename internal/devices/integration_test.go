// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type recSink struct {
	mu  sync.Mutex
	obs []Observation
}

func (s *recSink) Observe(o Observation) string {
	s.mu.Lock()
	s.obs = append(s.obs, o)
	s.mu.Unlock()
	return ""
}

func (s *recSink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.obs) }

func TestLookupFollowsTheRegistry(t *testing.T) {
	reg, _ := newReg(t)
	l := NewLookup(reg)
	defer l.Close()
	if got := l.DeviceFor("192.0.2.10"); got.ID != "" {
		t.Errorf("unknown client = %+v", got)
	}
	if got := l.DeviceFor("not an ip"); got.ID != "" {
		t.Errorf("bad address = %+v", got)
	}
	id := reg.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:53:01", IP: "192.0.2.10"})
	got := l.DeviceFor("192.0.2.10")
	if got.ID != id || got.Name != "ExampleCo device" || got.Excluded {
		t.Fatalf("new device = %+v", got)
	}
	// A rename, and an exclusion, are visible on the very next query.
	if err := reg.Rename(id, "Kitchen tablet"); err != nil {
		t.Fatal(err)
	}
	if got := l.DeviceFor("192.0.2.10"); got.Name != "Kitchen tablet" {
		t.Errorf("after rename = %+v", got)
	}
	if err := reg.SetExcluded(id, true); err != nil {
		t.Fatal(err)
	}
	if got := l.DeviceFor("192.0.2.10"); !got.Excluded {
		t.Errorf("after exclude = %+v", got)
	}
	// Learned later from mDNS: only the alias outranks nothing here, but a
	// brand new device must appear without a restart.
	id2 := reg.Observe(Observation{Source: SourceMDNS, IP: "192.0.2.11", Hostname: "printer.local"})
	if got := l.DeviceFor("192.0.2.11"); got.ID != id2 || got.Name == "" {
		t.Errorf("mdns device = %+v", got)
	}
	// Close detaches: later changes no longer mark it stale.
	l.Close()
	if err := reg.Rename(id, "Changed"); err != nil {
		t.Fatal(err)
	}
	if got := l.DeviceFor("192.0.2.10"); got.Name != "Kitchen tablet" {
		t.Errorf("a closed lookup must not follow: %+v", got)
	}
}

func TestLookupRebuildIsSkippedWhileAnotherIsRunning(t *testing.T) {
	reg, _ := newReg(t)
	id := reg.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:53:01", IP: "192.0.2.10"})
	l := NewLookup(reg)
	defer l.Close()
	l.build.Lock()
	if got := l.DeviceFor("192.0.2.10"); got.ID != "" { // nothing built yet, builder busy
		t.Errorf("got %+v while the builder is busy", got)
	}
	l.build.Unlock()
	if got := l.DeviceFor("192.0.2.10"); got.ID != id {
		t.Errorf("got %+v after the builder finished", got)
	}
	l.rebuild() // not stale: a second rebuild is a no-op
}

func TestDNSFeederRateLimitsPerAddress(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	sink := &recSink{}
	f := &DNSFeeder{Sink: sink, Interval: time.Minute, Now: clk.Now}
	for i := 0; i < 5; i++ {
		f.Seen("192.0.2.10")
	}
	f.Seen("192.0.2.11")
	if sink.count() != 2 {
		t.Fatalf("observations = %d, want 1 per address", sink.count())
	}
	clk.Advance(61 * time.Second)
	f.Seen("192.0.2.10")
	if sink.count() != 3 {
		t.Errorf("after the interval = %d", sink.count())
	}
	if o := sink.obs[0]; o.Source != SourceDNS || o.IP != "192.0.2.10" {
		t.Errorf("observation = %+v", o)
	}
	// Defaults: the real clock and a one minute interval.
	g := &DNSFeeder{Sink: sink}
	g.Seen("192.0.2.12")
	g.Seen("192.0.2.12")
	if sink.count() != 4 {
		t.Errorf("default feeder count = %d", sink.count())
	}
}

func TestDNSFeederTableIsBounded(t *testing.T) {
	sink := &recSink{}
	f := &DNSFeeder{Sink: sink}
	f.n.Store(maxFeederAddrs)
	f.Seen("192.0.2.1") // pushes the table over its bound: it resets and still reports
	if sink.count() != 1 || f.n.Load() != 1 {
		t.Errorf("count %d n %d", sink.count(), f.n.Load())
	}
}

func TestDNSFeederConcurrentCallsReportOnce(t *testing.T) {
	sink := &recSink{}
	f := &DNSFeeder{Sink: sink}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.Seen("192.0.2.77") }()
	}
	wg.Wait()
	if sink.count() != 1 {
		t.Errorf("observations = %d, want exactly 1", sink.count())
	}
}

func TestAllowLoopbackOption(t *testing.T) {
	r := New(Options{})
	if id := r.Observe(Observation{Source: SourceDNS, IP: "127.0.0.1"}); id != "" {
		t.Error("loopback must not become a device by default")
	}
	r = New(Options{AllowLoopback: true})
	id := r.Observe(Observation{Source: SourceDNS, IP: "127.0.0.1"})
	id6 := r.Observe(Observation{Source: SourceDNS, IP: "::1"})
	if id == "" || id6 == "" || id == id6 {
		t.Fatalf("ids %q %q", id, id6)
	}
	if got, _ := r.ScopesFor("::1"); got != id6 {
		t.Errorf("ScopesFor(::1) = %q", got)
	}
	if r.Observe(Observation{Source: SourceDNS, IP: "0.0.0.0"}) != "" {
		t.Error("unspecified is never a device")
	}
}

func TestRegistryClockMovesOnWrites(t *testing.T) {
	r, _ := newReg(t)
	c0 := r.Clock()
	r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:53:01", IP: "192.0.2.10"})
	if r.Clock().Compare(c0) <= 0 {
		t.Error("clock did not advance")
	}
}

func TestDefaultGateway(t *testing.T) {
	route := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	if gw, ok := DefaultGateway([]byte(route)); !ok || gw != "192.0.2.1" {
		t.Errorf("gateway = %q %v", gw, ok)
	}
	for name, in := range map[string]string{
		"empty":       "",
		"header only": "Iface\tDestination\n",
		"no gateway flag": "Iface\tDestination\tGateway\tFlags\n" +
			"eth0\t00000000\t010200C0\t0001\n",
		"zero gateway": "Iface\tDestination\tGateway\tFlags\n" +
			"eth0\t00000000\t00000000\t0003\n",
		"bad hex": "Iface\tDestination\tGateway\tFlags\n" +
			"eth0\t00000000\tZZ\t0003\n",
		"bad flags": "Iface\tDestination\tGateway\tFlags\n" +
			"eth0\t00000000\t010200C0\tZZ\n",
		"short line": "Iface\tDestination\tGateway\tFlags\neth0\t00000000\n",
	} {
		if gw, ok := DefaultGateway([]byte(in)); ok {
			t.Errorf("%s: gateway = %q", name, gw)
		}
	}
	p := filepath.Join(t.TempDir(), "route")
	os.WriteFile(p, []byte(route), 0o600)
	if gw, ok := ReadDefaultGateway(p); !ok || gw != "192.0.2.1" {
		t.Errorf("ReadDefaultGateway = %q %v", gw, ok)
	}
	if _, ok := ReadDefaultGateway(filepath.Join(t.TempDir(), "missing")); ok {
		t.Error("missing file")
	}
}

func fakePTRServer(t *testing.T, h func(q dns.Question, m *dns.Msg)) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		h(r.Question[0], m)
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestPTRLookup(t *testing.T) {
	var asked []string
	var mu sync.Mutex
	addr := fakePTRServer(t, func(q dns.Question, m *dns.Msg) {
		mu.Lock()
		asked = append(asked, q.Name)
		mu.Unlock()
		if q.Name == "10.2.0.192.in-addr.arpa." {
			m.Answer = append(m.Answer, &dns.PTR{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}, Ptr: "tablet.example."})
		}
		if q.Name == "11.2.0.192.in-addr.arpa." {
			m.Rcode = dns.RcodeNameError
		}
	})
	look := PTRLookup(addr)
	names, err := look(context.Background(), "192.0.2.10")
	if err != nil || !slices.Equal(names, []string{"tablet.example"}) {
		t.Fatalf("names = %v, %v", names, err)
	}
	if names, err := look(context.Background(), "192.0.2.12"); err != nil || len(names) != 0 {
		t.Errorf("no PTR record: %v %v", names, err)
	}
	if _, err := look(context.Background(), "192.0.2.11"); err == nil || !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Errorf("NXDOMAIN should be an error: %v", err)
	}
	if _, err := look(context.Background(), "nope"); err == nil {
		t.Error("an invalid address must fail")
	}
	// Dead server: the error comes back, quickly because the context ends.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := PTRLookup("127.0.0.1:1")(ctx, "192.0.2.10"); err == nil {
		t.Error("a dead server must fail")
	}
	// A bare host gets port 53 appended; IPv6 brackets are tolerated.
	if _, err := PTRLookup("[::1]")(ctx, "2001:db8::1"); err == nil {
		t.Log("something answered on ::1:53") // fine either way; the call must not panic
	}
}
