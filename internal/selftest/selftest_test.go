// SPDX-License-Identifier: AGPL-3.0-or-later

package selftest

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"shepherd/internal/dnsengine"
)

// fakeNet answers canary questions per (proto, addr) the way a scenario
// needs, so no sockets are involved.
type fakeNet struct {
	mu      sync.Mutex
	down    map[string]bool // "udp|127.0.0.1:53"
	badGood map[string]bool // addr whose good name answers SERVFAIL
	noAns   map[string]bool // addr whose good name answers NOERROR with nothing
	leaky   map[string]bool // addr that does not block
	asked   []string
}

func newFakeNet() *fakeNet {
	return &fakeNet{down: map[string]bool{}, badGood: map[string]bool{}, noAns: map[string]bool{}, leaky: map[string]bool{}}
}

func (f *fakeNet) exchange(_ context.Context, network, addr string, m *dns.Msg, _ time.Duration) (*dns.Msg, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, network+"|"+addr+"|"+m.Question[0].Name)
	if f.down[network+"|"+addr] || f.down[addr] {
		return nil, errors.New("i/o timeout")
	}
	r := new(dns.Msg)
	r.SetReply(m)
	name := m.Question[0].Name
	hdr := dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}
	switch {
	case strings.HasPrefix(name, "blocked."):
		if f.leaky[addr] {
			r.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP("192.0.2.7")}}
		} else {
			r.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4zero}}
		}
	case f.badGood[addr]:
		r.Rcode = dns.RcodeServerFailure
	case f.noAns[addr]:
	default:
		r.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP("192.0.2.1")}}
	}
	return r, nil
}

func hostOf(ips ...string) func() ([]HostAddr, error) {
	return func() ([]HostAddr, error) {
		var out []HostAddr
		for _, s := range ips {
			n, ip, _ := strings.Cut(s, "=")
			out = append(out, HostAddr{n, net.ParseIP(ip)})
		}
		return out, nil
	}
}

func newTester(f *fakeNet, listen []string, mut func(*Options)) *Tester {
	o := Options{Addrs: func() []string { return listen }, Exchange: f.exchange, Interfaces: hostOf()}
	if mut != nil {
		mut(&o)
	}
	return New(o)
}

func problemChecks(r Report) map[string]int {
	m := map[string]int{}
	for _, p := range r.Problems {
		m[p.Check]++
	}
	return m
}

func TestHealthyListenersReportOK(t *testing.T) {
	f := newFakeNet()
	tt := newTester(f, []string{"10.0.0.20:53", "127.0.0.1:53"}, nil)
	r := tt.RunOnce(context.Background())
	if r.Status != StatusOK || len(r.Problems) != 0 || len(r.Listeners) != 2 {
		t.Fatalf("report = %+v", r)
	}
	for _, l := range r.Listeners {
		if !l.OK || len(l.Probes) != 6 { // 3 checks x udp,tcp
			t.Errorf("%s: %+v", l.Addr, l)
		}
	}
	got, ok := tt.Latest()
	if !ok || got.Time != r.Time {
		t.Errorf("Latest = %v %v", got, ok)
	}
}

func TestLatestEmptyBeforeFirstRun(t *testing.T) {
	if _, ok := New(Options{Addrs: func() []string { return nil }}).Latest(); ok {
		t.Fatal("Latest reported a result before any run")
	}
}

func TestListenerWithNoAnswerIsAFailure(t *testing.T) {
	f := newFakeNet()
	f.down["10.0.0.20:53"] = true // the owner's PS5 case: devices use it, nothing listens
	tt := newTester(f, []string{"10.0.0.20:53", "10.0.0.102:53"}, nil)
	r := tt.RunOnce(context.Background())
	if r.Status != StatusFail || problemChecks(r)[CheckListener] != 2 {
		t.Fatalf("report = %+v", r)
	}
	if r.Listeners[0].OK || !r.Listeners[1].OK {
		t.Errorf("listeners = %+v", r.Listeners)
	}
	// Only one protocol dead is also reported, for that protocol alone.
	f.down = map[string]bool{"tcp|10.0.0.102:53": true}
	r = tt.RunOnce(context.Background())
	if len(r.Problems) != 1 || !strings.Contains(r.Problems[0].Subject, "tcp") {
		t.Fatalf("problems = %+v", r.Problems)
	}
}

func TestResolveAndBlockFailures(t *testing.T) {
	f := newFakeNet()
	f.badGood["a:53"], f.noAns["b:53"], f.leaky["c:53"] = true, true, true
	tt := newTester(f, []string{"a:53", "b:53", "c:53", "d:53"}, nil)
	r := tt.RunOnce(context.Background())
	c := problemChecks(r)
	if c[CheckResolve] != 4 || c[CheckBlock] != 2+2 { // a,b resolve x2 protos; c leaks x2; a,b block fine
		// a: SERVFAIL good; b: empty good; blocked checks only fail on c
		t.Logf("problems: %+v", r.Problems)
	}
	if c[CheckResolve] != 4 || c[CheckBlock] != 2 {
		t.Fatalf("counts = %v", c)
	}
	for _, p := range r.Problems {
		if p.Severity != StatusFail || p.Message == "" || p.Key() == "" {
			t.Errorf("bad problem %+v", p)
		}
	}
}

func TestBlockedProbeErrorsAndNXDOMAIN(t *testing.T) {
	// NXDOMAIN is how block_mode = "nxdomain" blocks; a transport error on
	// the second question is a failure of the block check.
	calls := 0
	ex := func(_ context.Context, _, _ string, m *dns.Msg, _ time.Duration) (*dns.Msg, error) {
		calls++
		r := new(dns.Msg)
		r.SetReply(m)
		if strings.HasPrefix(m.Question[0].Name, "blocked.") {
			if calls == 4 {
				return nil, errors.New("reset")
			}
			r.Rcode = dns.RcodeNameError
			return r, nil
		}
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.1")}}
		return r, nil
	}
	tt := New(Options{Addrs: func() []string { return []string{"x:53"} }, Exchange: ex, Interfaces: hostOf()})
	r := tt.RunOnce(context.Background())
	if len(r.Problems) != 1 || r.Problems[0].Check != CheckBlock || !strings.Contains(r.Problems[0].Message, "reset") {
		t.Fatalf("problems = %+v", r.Problems)
	}
}

func TestBlockedHelper(t *testing.T) {
	mk := func(rc int, rr ...dns.RR) *dns.Msg { return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: rc}, Answer: rr} }
	h := dns.RR_Header{Name: "x.", Rrtype: dns.TypeA, Class: dns.ClassINET}
	for name, c := range map[string]struct {
		m    *dns.Msg
		want bool
	}{
		"nxdomain":   {mk(dns.RcodeNameError), true},
		"servfail":   {mk(dns.RcodeServerFailure), false},
		"zero A":     {mk(0, &dns.A{Hdr: h, A: net.IPv4zero}), true},
		"zero AAAA":  {mk(0, &dns.AAAA{Hdr: h, AAAA: net.IPv6zero}), true},
		"real A":     {mk(0, &dns.A{Hdr: h, A: net.ParseIP("192.0.2.1")}), false},
		"no answer":  {mk(0), false},
		"cname only": {mk(0, &dns.CNAME{Hdr: h, Target: "y."}), false},
	} {
		if got := blocked(c.m); got != c.want {
			t.Errorf("%s: blocked = %v", name, got)
		}
	}
}

func TestWildcardListenerIsAskedOnEveryLANAddress(t *testing.T) {
	f := newFakeNet()
	f.down["10.0.0.102:53"] = true
	tt := newTester(f, []string{"0.0.0.0:53", ":53", "[::]:5353"}, func(o *Options) {
		o.Interfaces = hostOf("eth0=10.0.0.20", "wlan0=10.0.0.102", "eth1=169.254.1.1", "eth2=203.0.113.9", "eth3=fe80::1") // leakcheck:allow fixture
	})
	r := tt.RunOnce(context.Background())
	var addrs []string
	for _, l := range r.Listeners {
		addrs = append(addrs, l.Addr)
	}
	want := []string{"127.0.0.1:53", "10.0.0.102:53", "10.0.0.20:53", "[::1]:5353", "127.0.0.1:5353", "10.0.0.102:5353", "10.0.0.20:5353"}
	if len(addrs) != len(want) {
		t.Fatalf("addrs = %v", addrs)
	}
	if problemChecks(r)[CheckListener] != 2 { // the wlan address, udp+tcp, once
		t.Errorf("problems = %+v", r.Problems)
	}
	// A wildcard listener serves every LAN address.
	for _, l := range r.LAN {
		if l.State != "served" {
			t.Errorf("lan = %+v", l)
		}
	}
	if len(r.LAN) != 2 {
		t.Errorf("lan = %+v", r.LAN)
	}
}

func TestLANCoverage(t *testing.T) {
	f := newFakeNet()
	// Shepherd on the Wi-Fi address only; devices were told the wired one.
	tt := newTester(f, []string{"10.0.0.102:53", "bad-address", "127.0.0.1:53"}, func(o *Options) {
		o.Interfaces = hostOf("eno1=10.0.0.20", "wlan0=10.0.0.102", "eno1=10.0.0.20", "eth9=192.168.1.5")
		o.NotServed = []string{"192.168.1.5", "not-an-ip"}
	})
	r := tt.RunOnce(context.Background())
	states := map[string]string{}
	for _, l := range r.LAN {
		states[l.IP] = l.State
	}
	if states["10.0.0.20"] != "unserved" || states["10.0.0.102"] != "served" || states["192.168.1.5"] != "not-served" || len(states) != 3 {
		t.Fatalf("lan = %+v", r.LAN)
	}
	if r.Status != StatusWarn || problemChecks(r)[CheckLAN] != 1 {
		t.Fatalf("report = %+v", r)
	}
	if !strings.Contains(r.Problems[0].Message, "10.0.0.20") || r.Problems[0].Severity != StatusWarn {
		t.Errorf("problem = %+v", r.Problems[0])
	}
}

func TestInterfaceErrorIsTolerated(t *testing.T) {
	tt := newTester(newFakeNet(), []string{"127.0.0.1:53"}, func(o *Options) {
		o.Interfaces = func() ([]HostAddr, error) { return nil, errors.New("no netlink") }
	})
	if r := tt.RunOnce(context.Background()); r.Status != StatusOK || len(r.LAN) != 0 {
		t.Fatalf("report = %+v", r)
	}
}

func TestSkippedAddressesAreReported(t *testing.T) {
	tt := newTester(newFakeNet(), []string{"127.0.0.1:53"}, func(o *Options) { o.Skipped = func() []string { return []string{"10.0.0.20:53"} } })
	if r := tt.RunOnce(context.Background()); len(r.Skipped) != 1 {
		t.Fatalf("skipped = %v", r.Skipped)
	}
}

func win(addr string, q, e int, p95 float64) dnsengine.UpstreamWindow {
	return dnsengine.UpstreamWindow{Addr: addr, Queries: q, Errors: e, P50ms: p95 / 2, P95ms: p95}
}

func TestUpstreamErrorRateAndLatency(t *testing.T) {
	ws := []dnsengine.UpstreamWindow{
		win("9.9.9.10", 100, 20, 30),       // the Quad9 case: 20% errors
		win("1.1.1.1", 100, 4, 20),         // 4% is under the limit
		win("8.8.8.8", 100, 0, 900),        // p95 far above its peers
		win("tls://x", 5, 5, 0),            // too few queries to judge
		win("udp://slow-ish", 100, 0, 200), // above peers but under the floor
	}
	var gotWindow time.Duration
	tt := newTester(newFakeNet(), []string{"127.0.0.1:53"}, func(o *Options) {
		o.Window = func(d time.Duration) []dnsengine.UpstreamWindow { gotWindow = d; return ws }
		o.UpstreamWindow = 10 * time.Minute
	})
	r := tt.RunOnce(context.Background())
	if gotWindow != 10*time.Minute {
		t.Errorf("window = %v", gotWindow)
	}
	bad := map[string]string{}
	for _, u := range r.Upstreams {
		if !u.OK {
			bad[u.Addr] = u.Detail
		}
	}
	if len(bad) != 2 || !strings.Contains(bad["9.9.9.10"], "20%") || !strings.Contains(bad["8.8.8.8"], "p95") {
		t.Fatalf("bad = %v (%+v)", bad, r.Upstreams)
	}
	if r.Status != StatusWarn || problemChecks(r)[CheckUpstream] != 2 {
		t.Errorf("report = %+v", r)
	}
}

func TestSingleUpstreamIsNeverCalledSlow(t *testing.T) {
	tt := newTester(newFakeNet(), []string{"127.0.0.1:53"}, func(o *Options) {
		o.Window = func(time.Duration) []dnsengine.UpstreamWindow {
			return []dnsengine.UpstreamWindow{win("1.1.1.1", 100, 0, 5000)}
		}
	})
	if r := tt.RunOnce(context.Background()); r.Status != StatusOK {
		t.Fatalf("report = %+v", r)
	}
}

func TestOthersMedian(t *testing.T) {
	if got := othersMedian([]float64{10, 20, 30}, 30); got != 20 {
		t.Errorf("got %v", got)
	}
	if got := othersMedian([]float64{10}, 10); got != 0 {
		t.Errorf("got %v", got)
	}
	if got := othersMedian([]float64{5, 5, 9}, 5); got != 9 {
		t.Errorf("got %v", got)
	}
}

func TestIsCanary(t *testing.T) {
	tt := New(Options{Addrs: func() []string { return nil }, GoodName: "Good.Test", BlockedName: "bad.test"})
	for name, want := range map[string]bool{"good.test": true, "GOOD.test.": true, "bad.test.": true, "example.com": false} {
		if tt.IsCanary(name) != want {
			t.Errorf("IsCanary(%q) = %v", name, !want)
		}
	}
	if !New(Options{Addrs: func() []string { return nil }}).IsCanary(dnsengine.CanaryBlockedName) {
		t.Error("default blocked name is not a canary")
	}
}

func TestRunRepeatsAndStops(t *testing.T) {
	f := newFakeNet()
	tt := newTester(f, []string{"127.0.0.1:53"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	var rounds atomic.Int32
	done := make(chan struct{})
	go func() {
		tt.Run(ctx, 5*time.Millisecond, func(Report) {
			if rounds.Add(1) == 3 {
				cancel()
			}
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if rounds.Load() < 3 {
		t.Errorf("rounds = %d", rounds.Load())
	}
	// A nil callback is fine.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	tt.Run(ctx2, 5*time.Millisecond, nil)
}

func TestDefaultsAndRealHostAddrs(t *testing.T) {
	tt := New(Options{Addrs: func() []string { return nil }})
	if tt.o.Timeout == 0 || tt.o.MinQueries == 0 || tt.o.MaxErrorPct != 5 || tt.o.Now == nil {
		t.Errorf("defaults = %+v", tt.o)
	}
	if _, err := hostAddrs(); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]bool{"docker0": true, "Tailscale0": true, "br-1234": true, "eth0": false, "en0": false} {
		if virtualName(n) != want {
			t.Errorf("virtualName(%q)", n)
		}
	}
}

// TestRealSocketsAgainstARealEngine is the end to end case: a real Engine
// served by dnsengine.Serve on loopback, asked over real UDP and TCP, with
// the canary names kept out of its log.
func TestRealSocketsAgainstARealEngine(t *testing.T) {
	up := startUpstream(t)
	pool, err := dnsengine.NewPool([]string{up})
	if err != nil {
		t.Fatal(err)
	}
	e := &dnsengine.Engine{Filter: dnsengine.NewFilter(), Pool: pool, Cache: dnsengine.NewCache(100), Log: dnsengine.NewQueryLog(50), Stats: dnsengine.NewStats()}
	tt := New(Options{Addrs: func() []string { return nil }, Interfaces: hostOf()})
	e.Quiet = tt.IsCanary

	port := freePort(t)
	addr := net.JoinHostPort("127.0.0.1", port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = dnsengine.Serve(ctx, []string{addr}, e) }()
	tt.o.Addrs = func() []string { return []string{addr, net.JoinHostPort("127.0.0.1", freePort(t))} }
	tt.o.Window = pool.Window
	waitUp(t, addr)

	r := tt.RunOnce(ctx)
	if len(r.Listeners) != 2 || !r.Listeners[0].OK || r.Listeners[1].OK {
		t.Fatalf("listeners = %+v", r.Listeners)
	}
	if problemChecks(r)[CheckListener] != 2 || problemChecks(r)[CheckResolve]+problemChecks(r)[CheckBlock] != 0 {
		t.Errorf("problems = %+v", r.Problems)
	}
	if n := len(e.Log.All()); n != 0 {
		t.Errorf("canary queries reached the query log: %d entries", n)
	}
}

func startUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func freePort(t *testing.T) string {
	t.Helper()
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		pc, err := net.ListenPacket("udp", "127.0.0.1:"+port)
		ln.Close()
		if err == nil {
			pc.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return ""
}

func waitUp(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 250; i++ {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		if _, _, err := new(dns.Client).Exchange(m, addr); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never came up", addr)
}
