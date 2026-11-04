// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ---- upstream failover and hedging -------------------------------------

func TestQA_FailsOverFromAServfailingUpstream(t *testing.T) {
	bad, good := newQAResolver(t), newQAResolver(t)
	bad.set(qaServfail)
	_, addr := qaEngine(t, qaPool(t, time.Second, bad.Addr, good.Addr), nil)

	resp, _ := qaQuery(t, "udp", addr, "failover.example.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || !slices.Equal(qaIPs(resp), []string{qaA}) {
		t.Fatalf("answer = %v rcode %s", qaIPs(resp), dns.RcodeToString[resp.Rcode])
	}
	if bad.seen("failover.example.") != 1 || good.seen("failover.example.") != 1 {
		t.Errorf("bad saw %d, good saw %d", bad.seen("failover.example."), good.seen("failover.example."))
	}
}

func TestQA_AllUpstreamsFailingGivesServfailNotAHang(t *testing.T) {
	a, b := newQAResolver(t), newQAResolver(t)
	a.set(qaServfail)
	b.set(qaServfail)
	e, addr := qaEngine(t, qaPool(t, time.Second, a.Addr, b.Addr), nil)
	resp, rtt := qaQuery(t, "udp", addr, "allbad.example.", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if rtt > 2*time.Second {
		t.Errorf("took %v", rtt)
	}
	if en := qaLastEntry(t, e, "allbad.example"); en.Action != "allowed" && en.Action != "error" {
		t.Errorf("entry = %+v", en)
	}
}

func TestQA_StalledUpstreamCostsOnlyTheHedgeDelay(t *testing.T) {
	stalled, fast := newQAResolver(t), newQAResolver(t)
	stalled.setDelay(1500 * time.Millisecond)
	_, addr := qaEngine(t, qaPool(t, 3*time.Second, stalled.Addr, fast.Addr), nil)

	resp, rtt := qaQuery(t, "udp", addr, "stall.example.", dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Fatalf("no answer: %v", resp)
	}
	// hedgeDelay is 150ms for an upstream with no history; the fast one
	// answers a few ms later. Far below the stall, and not instant either:
	// the hedge really waited for the first upstream.
	if rtt < 100*time.Millisecond || rtt > 700*time.Millisecond {
		t.Fatalf("answer took %v; want roughly the 150ms hedge delay, not the stall", rtt)
	}
	if fast.seen("stall.example.") != 1 || stalled.seen("stall.example.") != 1 {
		t.Errorf("fast saw %d, stalled saw %d", fast.seen("stall.example."), stalled.seen("stall.example."))
	}
}

func TestQA_HedgeIsNotPaidWhenTheFirstUpstreamIsFast(t *testing.T) {
	a, b := newQAResolver(t), newQAResolver(t)
	_, addr := qaEngine(t, qaPool(t, time.Second, a.Addr, b.Addr), nil)
	_, rtt := qaQuery(t, "udp", addr, "quick.example.", dns.TypeA)
	if rtt > 100*time.Millisecond {
		t.Errorf("took %v", rtt)
	}
	time.Sleep(250 * time.Millisecond) // past the hedge delay
	if b.seen("quick.example.") != 0 {
		t.Error("the second upstream was asked although the first answered at once")
	}
}

func TestQA_BlackholedUpstreamIsMarkedUnhealthyAndStopsCostingTime(t *testing.T) {
	hole, good := newQAResolver(t), newQAResolver(t)
	hole.set(qaDrop)
	pool := qaPool(t, 200*time.Millisecond, hole.Addr, good.Addr)
	var changes atomic.Int32
	pool.OnHealthChange = func(addr string, healthy bool) {
		if addr == hole.Addr && !healthy {
			changes.Add(1)
		}
	}
	_, addr := qaEngine(t, pool, nil)

	// While it is believed healthy and listed first, every cold query pays
	// the hedge delay.
	if _, rtt := qaQuery(t, "udp", addr, "hole1.example.", dns.TypeA); rtt < 100*time.Millisecond {
		t.Fatalf("first query took %v, expected the hedge delay", rtt)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pool.Probe(ctx, 50*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for pool.Status()[0].Healthy && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	st := pool.Status()
	if st[0].Healthy || !st[1].Healthy {
		t.Fatalf("status = %+v", st)
	}
	if changes.Load() != 1 {
		t.Errorf("OnHealthChange fired %d times for the blackhole", changes.Load())
	}
	// Now the healthy one is asked first: no hedge delay.
	if _, rtt := qaQuery(t, "udp", addr, "hole2.example.", dns.TypeA); rtt > 100*time.Millisecond {
		t.Errorf("query after the blackhole was marked unhealthy took %v", rtt)
	}
}

func TestQA_UpstreamRecoversAndIsUsedAgain(t *testing.T) {
	flaky, steady := newQAResolver(t), newQAResolver(t)
	flaky.set(qaServfail)
	pool := qaPool(t, time.Second, flaky.Addr, steady.Addr)
	_, addr := qaEngine(t, pool, nil)
	ctx := context.Background()
	u := pool.snapshot()[0]
	u.probe(ctx, time.Second)
	if !pool.Status()[0].Healthy {
		t.Fatal("one SERVFAIL must not mark an upstream unhealthy")
	}
	u.probe(ctx, time.Second)
	if pool.Status()[0].Healthy {
		t.Fatal("two SERVFAILs in a row should mark it unhealthy")
	}
	// Unhealthy: the steady one is asked first and the flaky one not at all.
	qaQuery(t, "udp", addr, "while-down.example.", dns.TypeA)
	if flaky.seen("while-down.example.") != 0 {
		t.Error("an unhealthy upstream was asked while a healthy one was available")
	}
	flaky.set(qaAnswer)
	u.probe(ctx, time.Second)
	if !pool.Status()[0].Healthy {
		t.Fatal("a probe that is answered should mark it healthy again")
	}
}

func TestQA_WindowReportsErrorRateAndLatencyPerUpstream(t *testing.T) {
	bad, good := newQAResolver(t), newQAResolver(t)
	bad.set(qaServfail)
	pool := qaPool(t, time.Second, bad.Addr, good.Addr)
	for i := 0; i < 20; i++ {
		u := pool.snapshot()[0]
		u.probe(context.Background(), time.Second)
		pool.snapshot()[1].probe(context.Background(), time.Second)
		_ = u
	}
	ws := pool.Window(time.Minute)
	if ws[0].Queries != 20 || ws[0].Errors != 20 || ws[0].ErrorRate() != 100 {
		t.Errorf("bad upstream window = %+v", ws[0])
	}
	if ws[1].Queries != 20 || ws[1].Errors != 0 || ws[1].P95ms <= 0 || ws[1].P50ms > ws[1].P95ms {
		t.Errorf("good upstream window = %+v", ws[1])
	}
	if got := pool.Window(time.Nanosecond); got[0].Queries != 0 || got[0].ErrorRate() != 0 {
		t.Errorf("an empty window should report nothing: %+v", got[0])
	}
	// The ring forgets: overflowing it keeps only the latest.
	for i := 0; i < sampleRingSize+10; i++ {
		pool.snapshot()[1].record(true, time.Millisecond, nil)
	}
	if got := pool.Window(time.Minute)[1].Queries; got != sampleRingSize {
		t.Errorf("window holds %d samples, want %d", got, sampleRingSize)
	}
}

// ---- encrypted upstreams ------------------------------------------------

func TestQA_DoHAndDoTUpstreamsFailOverAndServe(t *testing.T) {
	var dohHits atomic.Int32
	doh := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		dohHits.Add(1)
		http.Error(w, "upstream broke", http.StatusBadGateway)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	startDoT(t, ln, doh.cert())
	_, dotPort, _ := net.SplitHostPort(ln.Addr().String())

	pool := testPool(t, nil, doh.roots, doh.url("127.0.0.1"), "tls://127.0.0.1:"+dotPort)
	e, addr := qaEngine(t, pool, nil)

	resp, _ := qaQuery(t, "udp", addr, "encrypted.example.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || !slices.Equal(qaIPs(resp), []string{"192.0.2.77"}) {
		t.Fatalf("answer = %v", qaIPs(resp))
	}
	if dohHits.Load() == 0 {
		t.Error("the DoH upstream was never tried")
	}
	if en := qaLastEntry(t, e, "encrypted.example"); !strings.HasPrefix(en.Upstream, "tls://") {
		t.Errorf("answered by %q, want the DoT upstream", en.Upstream)
	}
}

func TestQA_DoHUpstreamServesWhenHealthy(t *testing.T) {
	doh := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) { answerA(w, q, nil) })
	pool := testPool(t, nil, doh.roots, doh.url("127.0.0.1"))
	_, addr := qaEngine(t, pool, nil)
	resp, _ := qaQuery(t, "tcp", addr, "doh.example.", dns.TypeA)
	if !slices.Equal(qaIPs(resp), []string{"192.0.2.1"}) {
		t.Fatalf("answer = %v", qaIPs(resp))
	}
}

// ---- truncation and TCP --------------------------------------------------

func TestQA_TruncatedUpstreamAnswerIsRetriedOverTCP(t *testing.T) {
	r := newQAResolver(t)
	r.set(qaTruncate)
	r.many.Store(8)
	_, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), nil)
	resp, _ := qaQuery(t, "udp", addr, "tc.example.", dns.TypeA)
	if resp.Truncated || len(resp.Answer) != 8 {
		t.Fatalf("truncated=%v answers=%d; the engine should have retried over TCP", resp.Truncated, len(resp.Answer))
	}
	if r.udp.Load() != 1 || r.tcp.Load() != 1 {
		t.Errorf("upstream saw udp=%d tcp=%d, want one of each", r.udp.Load(), r.tcp.Load())
	}
}

func TestQA_LargeAnswerIsTruncatedToUDPClientsAndWholeOverTCP(t *testing.T) {
	r := newQAResolver(t)
	r.many.Store(60) // ~ 960 bytes: over 512
	_, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), nil)

	udp, _ := qaQuery(t, "udp", addr, "big.example.", dns.TypeA)
	if !udp.Truncated {
		t.Errorf("a %d-record answer reached a plain UDP client untruncated", len(udp.Answer))
	}
	tcp, _ := qaQuery(t, "tcp", addr, "big.example.", dns.TypeA)
	if tcp.Truncated || len(tcp.Answer) != 60 {
		t.Errorf("tcp truncated=%v answers=%d", tcp.Truncated, len(tcp.Answer))
	}
}

func TestQA_BothTransportsServeTheSameAnswers(t *testing.T) {
	r := newQAResolver(t)
	e, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), nil)
	e.Filter.SetList("ads", set("ads.example"))
	for _, proto := range []string{"udp", "tcp"} {
		ok, _ := qaQuery(t, proto, addr, "fine.example.", dns.TypeA)
		bl, _ := qaQuery(t, proto, addr, "x.ads.example.", dns.TypeA)
		if !slices.Equal(qaIPs(ok), []string{qaA}) || !slices.Equal(qaIPs(bl), []string{"0.0.0.0"}) {
			t.Errorf("%s: allowed=%v blocked=%v", proto, qaIPs(ok), qaIPs(bl))
		}
	}
}

// ---- AAAA filtering and the IPv6 probe -----------------------------------

func TestQA_AAAAFilterAnswersEmptyAndNeverAsksTheUpstream(t *testing.T) {
	r := newQAResolver(t)
	var on atomic.Bool
	e, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), func(e *Engine) { e.FilterAAAA = func(string) bool { return on.Load() } })

	on.Store(true)
	resp, _ := qaQuery(t, "udp", addr, "v6.example.", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("filtered AAAA = rcode %s answers %v", dns.RcodeToString[resp.Rcode], resp.Answer)
	}
	if r.seen("v6.example.") != 0 {
		t.Error("a filtered AAAA query reached the upstream")
	}
	if en := qaLastEntry(t, e, "v6.example"); en.Reason != "ipv6-filtered" {
		t.Errorf("entry = %+v", en)
	}
	// A still works while AAAA is filtered.
	if a, _ := qaQuery(t, "udp", addr, "v6.example.", dns.TypeA); len(a.Answer) != 1 {
		t.Error("A answers must be untouched by the AAAA filter")
	}
	on.Store(false)
	if resp, _ := qaQuery(t, "udp", addr, "v6.example.", dns.TypeAAAA); !slices.Equal(qaIPs(resp), []string{qaAAAA}) {
		t.Errorf("unfiltered AAAA = %v", qaIPs(resp))
	}
}

func TestQA_AAAAFilterStripsIPv6HintsFromHTTPSAndSVCBButKeepsTheRest(t *testing.T) {
	r := newQAResolver(t)
	var on atomic.Bool
	_, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), func(e *Engine) { e.FilterAAAA = func(string) bool { return on.Load() } })

	keys := func(resp *dns.Msg) (all []dns.SVCBKey) {
		for _, rr := range resp.Answer {
			if h, ok := rr.(*dns.HTTPS); ok {
				for _, kv := range h.Value {
					all = append(all, kv.Key())
				}
			}
		}
		return all
	}
	on.Store(true)
	resp, _ := qaQuery(t, "udp", addr, "svc.example.", dns.TypeHTTPS)
	got := keys(resp)
	if slices.Contains(got, dns.SVCB_IPV6HINT) || !slices.Contains(got, dns.SVCB_IPV4HINT) || !slices.Contains(got, dns.SVCB_ALPN) {
		t.Fatalf("filtered HTTPS keys = %v; want ipv6hint gone, ipv4hint and alpn kept", got)
	}
	// The cache holds the upstream's answer: turning the filter off brings
	// the hint back without another upstream query.
	before := r.total()
	on.Store(false)
	resp, _ = qaQuery(t, "udp", addr, "svc.example.", dns.TypeHTTPS)
	if !slices.Contains(keys(resp), dns.SVCB_IPV6HINT) {
		t.Errorf("unfiltered HTTPS keys = %v; the cached answer was modified in place", keys(resp))
	}
	if r.total() != before {
		t.Error("the second HTTPS query should have come from the cache")
	}
}

func TestQA_IPv6ProbeDrivesTheFilterEndToEnd(t *testing.T) {
	r := newQAResolver(t)
	reachable := atomic.Bool{}
	probe := &IPv6Probe{Targets: []string{"[::1]:1"}, Dial: func(context.Context, string, string) (net.Conn, error) {
		if reachable.Load() {
			c, _ := net.Pipe()
			return c, nil
		}
		return nil, errors.New("network is unreachable")
	}}
	_, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), func(e *Engine) { e.FilterAAAA = func(string) bool { return probe.Filtering() } })
	ctx := context.Background()

	probe.Check(ctx) // one failed round is not believed
	if resp, _ := qaQuery(t, "udp", addr, "p1.example.", dns.TypeAAAA); len(resp.Answer) != 1 {
		t.Fatal("one failed probe round must not start filtering")
	}
	probe.Check(ctx)
	if resp, _ := qaQuery(t, "udp", addr, "p2.example.", dns.TypeAAAA); len(resp.Answer) != 0 {
		t.Fatal("two failed rounds should start filtering")
	}
	reachable.Store(true)
	probe.Check(ctx)
	if resp, _ := qaQuery(t, "udp", addr, "p3.example.", dns.TypeAAAA); len(resp.Answer) != 1 {
		t.Fatal("one successful round should stop filtering at once")
	}
}

// ---- blocklists, allowlist and Private Relay -----------------------------

func TestQA_BlocklistCorrectness(t *testing.T) {
	r := newQAResolver(t)
	e, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), nil)
	e.Filter.SetList("ads", set("ads.example", "tracker.example"))

	for name, wantBlocked := range map[string]bool{
		"ads.example.":          true,
		"deep.sub.ads.example.": true,
		"TRACKER.example.":      true,
		"notads.example.":       false, // a suffix of the label, not a parent domain
		"example.":              false,
		"ads.example.org.":      false,
		"adsexample.":           false,
	} {
		resp, _ := qaQuery(t, "udp", addr, name, dns.TypeA)
		isBlocked := slices.Equal(qaIPs(resp), []string{"0.0.0.0"})
		if isBlocked != wantBlocked {
			t.Errorf("%s: blocked=%v, want %v (answer %v)", name, isBlocked, wantBlocked, qaIPs(resp))
		}
	}
	if r.seen("ads.example.") != 0 || r.seen("deep.sub.ads.example.") != 0 {
		t.Error("a blocked name reached the upstream")
	}
	// Other types: AAAA sinkholes to ::, anything else is an empty NOERROR.
	if resp, _ := qaQuery(t, "udp", addr, "ads.example.", dns.TypeAAAA); !slices.Equal(qaIPs(resp), []string{"::"}) {
		t.Errorf("blocked AAAA = %v", qaIPs(resp))
	}
	if resp, _ := qaQuery(t, "udp", addr, "ads.example.", dns.TypeTXT); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Errorf("blocked TXT = %v", resp)
	}
	if en := qaLastEntry(t, e, "ads.example"); en.Action != "blocked" || en.Reason != "ads" {
		t.Errorf("entry = %+v", en)
	}
}

func TestQA_BlockModeNXDOMAIN(t *testing.T) {
	r := newQAResolver(t)
	e, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), func(e *Engine) { e.BlockNXDOMAIN = true })
	e.Filter.SetList("ads", set("ads.example"))
	if resp, _ := qaQuery(t, "udp", addr, "ads.example.", dns.TypeA); resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestQA_AllowlistBeatsEveryBlock(t *testing.T) {
	r := newQAResolver(t)
	e, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), nil)
	e.Filter.SetList("ads", set("ads.example"))
	e.Filter.SetPolicy(PolicyPrivateRelay, []string{"mask.icloud.com"})
	e.Filter.SetRules([]string{"ok.ads.example", "mask.icloud.com"}, []string{"custom.example"})

	for name, want := range map[string]string{
		"ok.ads.example.":        qaA, // allowlisted inside a blocked list
		"deeper.ok.ads.example.": qaA, // subdomains of the allowed name too
		"other.ads.example.":     "0.0.0.0",
		"custom.example.":        "0.0.0.0",
	} {
		resp, _ := qaQuery(t, "udp", addr, name, dns.TypeA)
		if got := qaIPs(resp); !slices.Equal(got, []string{want}) {
			t.Errorf("%s = %v, want %s", name, got, want)
		}
	}
	// And over a policy block: the allowlisted relay name resolves.
	if resp, _ := qaQuery(t, "udp", addr, "mask.icloud.com.", dns.TypeA); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("allowlisted mask.icloud.com = %s", dns.RcodeToString[resp.Rcode])
	}
	if en := qaLastEntry(t, e, "ok.ads.example"); en.Action != "allowed" || en.Reason != "allowlist" {
		t.Errorf("entry = %+v", en)
	}
}

func TestQA_PrivateRelayHostnamesAreNXDOMAINWhenThePolicyIsOn(t *testing.T) {
	r := newQAResolver(t)
	e, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), nil)
	relay := []string{"mask.icloud.com.", "mask-h2.icloud.com.", "mask-api.icloud.com.", "sub.mask.icloud.com."}

	// Policy off: they resolve like any name.
	for _, h := range relay {
		if resp, _ := qaQuery(t, "udp", addr, h, dns.TypeA); resp.Rcode != dns.RcodeSuccess {
			t.Errorf("policy off: %s = %s", h, dns.RcodeToString[resp.Rcode])
		}
	}
	e.Filter.SetPolicy(PolicyPrivateRelay, policyDomains[PolicyPrivateRelay])
	seen := r.total()
	for _, proto := range []string{"udp", "tcp"} {
		for _, h := range relay {
			resp, _ := qaQuery(t, proto, addr, h, dns.TypeA)
			if resp.Rcode != dns.RcodeNameError || len(resp.Answer) != 0 {
				t.Errorf("%s %s = %s, want NXDOMAIN", proto, h, dns.RcodeToString[resp.Rcode])
			}
		}
	}
	if r.total() != seen {
		t.Error("a Private Relay query reached the upstream")
	}
	if resp, _ := qaQuery(t, "udp", addr, "www.icloud.com.", dns.TypeA); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("www.icloud.com = %s; only the relay hostnames may be blocked", dns.RcodeToString[resp.Rcode])
	}
	if en := qaLastEntry(t, e, "mask.icloud.com"); en.Reason != PolicyPrivateRelay {
		t.Errorf("entry = %+v", en)
	}
	e.Filter.SetPolicy(PolicyPrivateRelay, nil) // switched off again
	if resp, _ := qaQuery(t, "udp", addr, "mask.icloud.com.", dns.TypeA); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("policy off again: %s", dns.RcodeToString[resp.Rcode])
	}
}

// ---- cache TTL ------------------------------------------------------------

func TestQA_CacheHonoursAndCountsDownTheTTL(t *testing.T) {
	r := newQAResolver(t)
	r.ttl.Store(2)
	_, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), nil)

	first, _ := qaQuery(t, "udp", addr, "ttl.example.", dns.TypeA)
	if first.Answer[0].Header().Ttl != 2 {
		t.Fatalf("first TTL = %d", first.Answer[0].Header().Ttl)
	}
	qaQuery(t, "udp", addr, "ttl.example.", dns.TypeA)
	if r.seen("ttl.example.") != 1 {
		t.Fatalf("an immediate repeat should be cached; upstream saw %d", r.seen("ttl.example."))
	}
	time.Sleep(1100 * time.Millisecond)
	again, _ := qaQuery(t, "udp", addr, "ttl.example.", dns.TypeA)
	if ttl := again.Answer[0].Header().Ttl; ttl != 1 {
		t.Errorf("TTL after 1.1s = %d, want it counted down to 1", ttl)
	}
	if r.seen("ttl.example.") != 1 {
		t.Error("still inside the TTL, so still cached")
	}
	time.Sleep(1000 * time.Millisecond)
	qaQuery(t, "udp", addr, "ttl.example.", dns.TypeA)
	if r.seen("ttl.example.") != 2 {
		t.Errorf("after the TTL the upstream should be asked again; saw %d", r.seen("ttl.example."))
	}
}

func TestQA_CacheRules(t *testing.T) {
	r := newQAResolver(t)
	_, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), nil)

	// NXDOMAIN is cached (it carries no records, so its TTL falls back to 30s).
	r.set(qaNXDomain)
	qaQuery(t, "udp", addr, "nx.example.", dns.TypeA)
	qaQuery(t, "tcp", addr, "nx.example.", dns.TypeA)
	if r.seen("nx.example.") != 1 {
		t.Errorf("NXDOMAIN asked %d times, want 1 (cached)", r.seen("nx.example."))
	}
	// SERVFAIL is not cached: a recovered upstream is used at once.
	r.set(qaServfail)
	qaQuery(t, "udp", addr, "sf.example.", dns.TypeA)
	r.set(qaAnswer)
	if resp, _ := qaQuery(t, "udp", addr, "sf.example.", dns.TypeA); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("after recovery: %s", dns.RcodeToString[resp.Rcode])
	}
	// A zero TTL is not cached.
	r.ttl.Store(0)
	qaQuery(t, "udp", addr, "zero.example.", dns.TypeA)
	qaQuery(t, "udp", addr, "zero.example.", dns.TypeA)
	if r.seen("zero.example.") != 2 {
		t.Errorf("TTL 0 asked %d times, want 2", r.seen("zero.example."))
	}
	// Different types and the DO bit are different cache entries.
	r.ttl.Store(300)
	qaQuery(t, "udp", addr, "types.example.", dns.TypeA)
	qaQuery(t, "udp", addr, "types.example.", dns.TypeAAAA)
	if r.seen("types.example.") != 2 {
		t.Errorf("A and AAAA shared a cache entry")
	}
}

// ---- the self-test's own plumbing in the engine --------------------------

func TestQA_CanaryBlockedNameIsAlwaysBlockedAndQuiet(t *testing.T) {
	r := newQAResolver(t)
	var seen atomic.Int32
	e, addr := qaEngine(t, qaPool(t, time.Second, r.Addr), func(e *Engine) {
		e.Quiet = func(name string) bool { return name == "quiet.example" || name == CanaryBlockedName }
		e.ClientSeen = func(string) { seen.Add(1) }
	})
	for _, proto := range []string{"udp", "tcp"} {
		resp, _ := qaQuery(t, proto, addr, CanaryBlockedName+".", dns.TypeA)
		if !slices.Equal(qaIPs(resp), []string{"0.0.0.0"}) {
			t.Errorf("%s: canary = %v", proto, qaIPs(resp))
		}
	}
	_, nxAddr := qaEngine(t, qaPool(t, time.Second, r.Addr), func(e *Engine) { e.BlockNXDOMAIN = true })
	if resp, _ := qaQuery(t, "udp", nxAddr, CanaryBlockedName+".", dns.TypeA); resp.Rcode != dns.RcodeNameError {
		t.Errorf("canary under block_mode nxdomain = %s", dns.RcodeToString[resp.Rcode])
	}
	qaQuery(t, "udp", addr, "quiet.example.", dns.TypeA)
	qaQuery(t, "udp", addr, "loud.example.", dns.TypeA)
	qaLastEntry(t, e, "loud.example")
	for _, en := range e.Log.All() {
		if en.Name == "quiet.example" || en.Name == CanaryBlockedName {
			t.Errorf("quiet name was logged: %+v", en)
		}
	}
	if seen.Load() != 1 {
		t.Errorf("ClientSeen called %d times; quiet queries must not teach the registry", seen.Load())
	}
	if r.seen(CanaryBlockedName+".") != 0 {
		t.Error("the canary blocked name reached the upstream")
	}
}

func TestQA_PublicIPClassification(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "10.0.0.1": false, "127.0.0.1": false, "169.254.1.1": false,
		"100.64.0.1": false, "224.0.0.1": false, "0.0.0.0": false, "2001:db8::1": true, "fe80::1": false, // leakcheck:allow classification fixtures
	} {
		if PublicIP(net.ParseIP(ip)) != want {
			t.Errorf("PublicIP(%s) = %v", ip, !want)
		}
	}
	if PublicIP(nil) {
		t.Error("nil is not public")
	}
}
