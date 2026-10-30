// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeGeo map[string]Dest

func (g fakeGeo) Locate(ip net.IP) (Dest, bool) {
	d, ok := g[ip.String()]
	return d, ok
}

func answerWith(ips ...string) *dns.Msg {
	m := new(dns.Msg)
	for _, s := range ips {
		ip := net.ParseIP(s)
		if v4 := ip.To4(); v4 != nil {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: "x.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: v4})
		} else {
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: "x.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: ip})
		}
	}
	return m
}

func TestDestsOfPlacesOnlyPublicAddressesAndCapsAtThree(t *testing.T) {
	geo := fakeGeo{}
	for i := 1; i <= 6; i++ {
		geo[fmt.Sprintf("198.51.100.%d", i)] = Dest{Lat: float64(i), Lon: float64(-i), City: "Testville", Country: "ZZ"}
	}
	geo["2001:db8::7"] = Dest{Lat: 10, Lon: 10, Country: "ZZ"}
	e := &Engine{Geo: geo}

	got := e.destsOf(answerIPs(answerWith("10.1.2.3", "127.0.0.1", "169.254.1.1", "100.64.0.9", "0.0.0.0", "224.0.0.1", "198.51.100.1", "198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4")))
	if len(got) != 3 || got[0].IP != "198.51.100.1" || got[1].IP != "198.51.100.2" || got[2].IP != "198.51.100.3" {
		t.Errorf("want three distinct public addresses in order, got %+v", got)
	}
	if got[0].City != "Testville" || got[0].Country != "ZZ" {
		t.Errorf("location fields lost: %+v", got[0])
	}
	if v6 := e.destsOf(answerIPs(answerWith("2001:db8::7"))); len(v6) != 1 || v6[0].IP != "2001:db8::7" {
		t.Errorf("IPv6 answers must be placed too: %+v", v6)
	}
	if none := e.destsOf(answerIPs(answerWith("198.51.100.99"))); len(none) != 0 {
		t.Errorf("an address the database does not know is skipped: %+v", none)
	}
	if (&Engine{}).destsOf(answerIPs(answerWith("198.51.100.1"))) != nil {
		t.Error("no Geo means no destinations")
	}
	if e.destsOf(nil) != nil {
		t.Error("nil ips means no destinations")
	}
	if answerIPs(nil) != nil {
		t.Error("a nil response has no answer ips")
	}
}

func TestPublicIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"198.51.100.1": true, "8.8.8.8": true, "2001:db8::1": true,
		"10.0.0.1": false, "172.16.5.5": false, // leakcheck:allow private-range fixtures
		"192.168.9.9": false, "127.0.0.1": false, "::1": false,
		"169.254.0.1": false, "fe80::1": false, "100.64.0.1": false, "100.127.255.255": false, "100.128.0.1": true, // leakcheck:allow range fixtures
		"0.0.0.0": false, "224.0.0.251": false, "fd00::1": false, // leakcheck:allow ULA fixture
	} {
		if got := publicIP(net.ParseIP(ip)); got != want {
			t.Errorf("publicIP(%s) = %v, want %v", ip, got, want)
		}
	}
	if publicIP(nil) {
		t.Error("nil is not public")
	}
}

func TestEngineAttachesDestsToAllowedAndCachedButNotBlocked(t *testing.T) {
	var hits atomicInt
	up := fakeUpstreamAnswering(t, "198.51.100.7", &hits)
	pool, _ := NewPool([]string{up})
	e := &Engine{
		Filter: NewFilter(), Pool: pool, Cache: NewCache(10), Log: NewQueryLog(20), Stats: NewStats(),
		Geo: fakeGeo{"198.51.100.7": {Lat: 48.8, Lon: 2.3, City: "Paris", Country: "FR"}},
	}
	e.Filter.SetList("ads", set("ads.example"))

	e.ServeDNS(udpWriter(), query("site.example.", dns.TypeA)) // allowed
	e.ServeDNS(udpWriter(), query("site.example.", dns.TypeA)) // cached
	e.ServeDNS(udpWriter(), query("ads.example.", dns.TypeA))  // blocked
	entries, _ := e.Log.After(0, 10)
	if len(entries) != 3 {
		t.Fatalf("entries = %d", len(entries))
	}
	for i, wantAction := range []string{"allowed", "cached", "blocked"} {
		if entries[i].Action != wantAction {
			t.Fatalf("entry %d action = %s, want %s", i, entries[i].Action, wantAction)
		}
	}
	for _, i := range []int{0, 1} {
		if len(entries[i].Dests) != 1 || entries[i].Dests[0].City != "Paris" || entries[i].Dests[0].IP != "198.51.100.7" {
			t.Errorf("entry %d dests = %+v", i, entries[i].Dests)
		}
	}
	if len(entries[2].Dests) != 0 {
		t.Errorf("a blocked query has no destination: %+v", entries[2].Dests)
	}
}

// fakeUpstreamAnswering answers every A query with ip.
func fakeUpstreamAnswering(t *testing.T, ip string, hits *atomicInt) string {
	return fakeUpstream(t, ip, hits)
}

func TestQueryLogSubscribeSinkAndAll(t *testing.T) {
	l := NewQueryLog(3)
	var sunk []Entry
	var mu sync.Mutex
	l.SetSink(func(e Entry) { mu.Lock(); sunk = append(sunk, e); mu.Unlock() })
	ch, cancel := l.Subscribe(2)

	for i := 0; i < 4; i++ { // the subscriber's buffer holds 2: extras must be dropped, not block
		l.Add(Entry{Name: fmt.Sprintf("n%d", i)})
	}
	if len(ch) != 2 {
		t.Errorf("slow subscriber should hold its buffer and drop the rest, has %d", len(ch))
	}
	first := <-ch
	if first.ID != 1 || first.Name != "n0" {
		t.Errorf("subscriber saw %+v", first)
	}
	mu.Lock()
	if len(sunk) != 4 || sunk[3].ID != 4 {
		t.Errorf("sink must see every entry with its ID: %+v", sunk)
	}
	mu.Unlock()

	cancel()
	cancel() // idempotent
	l.Add(Entry{Name: "after-cancel"})
	<-ch // the one buffered entry that was already queued
	select {
	case e := <-ch:
		if e.Name == "after-cancel" {
			t.Error("a cancelled subscription must not receive new entries")
		}
	default:
	}

	all := l.All()
	if len(all) != 3 || all[0].Name != "n2" || all[2].Name != "after-cancel" {
		t.Errorf("All() = %+v", all)
	}
	if got := NewQueryLog(5).All(); got != nil {
		t.Errorf("empty log All() = %v", got)
	}
	ch2, cancel2 := l.Subscribe(0) // a zero buffer is bumped to one
	defer cancel2()
	l.Add(Entry{Name: "x"})
	if len(ch2) != 1 {
		t.Error("buffer of 0 should become 1")
	}
}

func TestHistoryQueryMatchAndMemoryHistory(t *testing.T) {
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	l := NewQueryLog(10)
	l.Add(Entry{Time: base, Client: "192.0.2.1", Name: "a.example.com", Action: "allowed"})
	l.Add(Entry{Time: base.Add(time.Minute), Client: "192.0.2.2", Name: "b.example.net", Action: "blocked", Reason: "ads-list"})
	l.Add(Entry{Time: base.Add(2 * time.Minute), Client: "192.0.2.1", Name: "c.example.com", Action: "cached"})
	h := MemoryHistory{Log: l}

	if h.Mode() != "memory" || h.Locked() || !h.Initialized() {
		t.Error("memory history is always unlocked")
	}
	if err := h.Unlock("x"); !errors.Is(err, ErrNotSupported) {
		t.Errorf("memory history has no passphrase: %v", err)
	}
	cases := []struct {
		name string
		q    HistoryQuery
		want int
	}{
		{"all", HistoryQuery{}, 3},
		{"client", HistoryQuery{Client: "192.0.2.1"}, 2},
		{"action", HistoryQuery{Action: "blocked"}, 1},
		{"domain substring", HistoryQuery{Contains: "EXAMPLE.COM"}, 2},
		{"reason substring", HistoryQuery{Contains: "ads-"}, 1},
		{"from", HistoryQuery{From: base.Add(time.Minute)}, 2},
		{"to", HistoryQuery{To: base.Add(time.Minute)}, 2},
		{"limit", HistoryQuery{Limit: 1}, 1},
		{"no match", HistoryQuery{Client: "198.51.100.9"}, 0},
	}
	for _, c := range cases {
		got, span, err := h.Query(c.q)
		if err != nil || len(got) != c.want {
			t.Errorf("%s: got %d (err %v), want %d", c.name, len(got), err, c.want)
		}
		if !span.Oldest.Equal(base) || !span.Newest.Equal(base.Add(2*time.Minute)) {
			t.Errorf("%s: span = %+v", c.name, span)
		}
	}
	if got, _, _ := h.Query(HistoryQuery{Limit: 1}); got[0].Name != "c.example.com" {
		t.Errorf("limit keeps the newest, got %s", got[0].Name)
	}
	if got, span, _ := (MemoryHistory{Log: NewQueryLog(2)}).Query(HistoryQuery{}); got != nil || !span.Oldest.IsZero() {
		t.Errorf("empty history = %v %+v", got, span)
	}
	if Newest([]Entry{{Name: "a"}}, 0)[0].Name != "a" || len(Newest([]Entry{{}, {}}, 5)) != 2 {
		t.Error("Newest must be a no-op when the limit is not exceeded")
	}
}

func TestPreloadFillsTheRingQuietly(t *testing.T) {
	l := NewQueryLog(3)
	var sunk int
	l.SetSink(func(Entry) { sunk++ })
	ch, cancel := l.Subscribe(4)
	defer cancel()
	l.Preload([]Entry{{Name: "p1"}, {Name: "p2"}, {Name: "p3"}, {Name: "p4"}})
	if sunk != 0 || len(ch) != 0 {
		t.Error("preloading must not notify the sink or subscribers")
	}
	all := l.All()
	if len(all) != 3 || all[0].Name != "p2" || all[2].Name != "p4" || all[2].ID != 4 {
		t.Errorf("preloaded ring = %+v", all)
	}
	l.Add(Entry{Name: "live"})
	if got, _ := l.After(4, 10); len(got) != 1 || got[0].Name != "live" {
		t.Errorf("live entries continue after the preload: %+v", got)
	}
}

func TestObserveHookSeesRealAnswersNotBlockedSinkholes(t *testing.T) {
	var hits atomicInt
	up := fakeUpstreamAnswering(t, "198.51.100.7", &hits)
	pool, _ := NewPool([]string{up})
	e := &Engine{Filter: NewFilter(), Pool: pool, Cache: NewCache(10), Log: NewQueryLog(20), Stats: NewStats()}
	e.Filter.SetList("ads", set("ads.example"))

	var calls []struct {
		client, name string
		ips          []net.IP
	}
	e.Observe = func(client, name string, ips []net.IP) {
		calls = append(calls, struct {
			client, name string
			ips          []net.IP
		}{client, name, ips})
	}

	e.ServeDNS(udpWriter(), query("site.example.", dns.TypeA))  // allowed
	e.ServeDNS(udpWriter(), query("site.example.", dns.TypeA))  // cached
	e.ServeDNS(udpWriter(), query("x.ads.example.", dns.TypeA)) // blocked: must not be observed

	if len(calls) != 2 {
		t.Fatalf("Observe called %d times, want 2 (allowed + cached, never blocked)", len(calls))
	}
	for i, c := range calls {
		if c.name != "site.example" || len(c.ips) != 1 || c.ips[0].String() != "198.51.100.7" {
			t.Errorf("call %d: %+v", i, c)
		}
	}
	if e.Observe == nil {
		t.Fatal("sanity")
	}
	// A nil Observe must never be called (no panic).
	e.Observe = nil
	e.ServeDNS(udpWriter(), query("other.example.", dns.TypeA))
}

func TestOnAccessSeesBlockedAndAllowedQueriesThatMatchAWatchedItem(t *testing.T) {
	var hits atomicInt
	up := fakeUpstreamAnswering(t, "198.51.100.7", &hits)
	pool, _ := NewPool([]string{up})
	e := &Engine{Filter: NewFilter(), Pool: pool, Cache: NewCache(10), Log: NewQueryLog(20), Stats: NewStats()}
	e.Filter.SetList("ads", set("ads.example"))
	e.Filter.SetList("gaming", set("roblox.example"))
	// Configured (non-legacy) mode, network scope: "ads" is blocked, but
	// "gaming" is loaded and matchable yet never turned on anywhere — the
	// accountability library's own motivating example, a watched category
	// that is never blocked at all (docs/ACCOUNTABILITY.md).
	e.Filter.SetScopes(map[string]ScopeConfig{
		NetworkScope().String(): {Items: map[string]bool{"ads": true}},
	})

	var calls []AccessInfo
	e.OnAccess = func(info AccessInfo) { calls = append(calls, info) }

	e.ServeDNS(udpWriter(), query("x.ads.example.", dns.TypeA))  // blocked, matches "ads" (blocked queries bypass the cache)
	e.ServeDNS(udpWriter(), query("site.example.", dns.TypeA))   // allowed, no list match: no call
	e.ServeDNS(udpWriter(), query("roblox.example.", dns.TypeA)) // allowed, matches "gaming" (never blocked)
	e.ServeDNS(udpWriter(), query("roblox.example.", dns.TypeA)) // cached, matches "gaming"

	if len(calls) != 3 {
		t.Fatalf("OnAccess called %d times, want 3 (blocked + allowed-but-watched + cached), got %+v", len(calls), calls)
	}
	if calls[0].Action != "blocked" || calls[0].Domain != "x.ads.example" || len(calls[0].Items) != 1 || calls[0].Items[0] != "ads" {
		t.Errorf("blocked call = %+v", calls[0])
	}
	if calls[1].Action != "allowed" || calls[1].Domain != "roblox.example" || calls[1].Items[0] != "gaming" {
		t.Errorf("an allowed, never-blocked, watched access must still be reported: %+v", calls[1])
	}
	if calls[2].Action != "cached" || calls[2].Items[0] != "gaming" {
		t.Errorf("cached call = %+v", calls[2])
	}
	for _, c := range calls {
		if c.ClientIP == "" {
			t.Errorf("ClientIP must be set: %+v", c)
		}
	}

	// A nil OnAccess must never be called (no panic).
	e.OnAccess = nil
	e.ServeDNS(udpWriter(), query("x.ads.example.", dns.TypeA))

	// An upstream error must never report an access, even for a watched item.
	errPool, _ := NewPool([]string{"127.0.0.1:1"}) // nothing listening: upstream error
	e2 := &Engine{Filter: e.Filter, Pool: errPool, Cache: NewCache(10), Log: NewQueryLog(20), Stats: NewStats()}
	var errCalls []AccessInfo
	e2.OnAccess = func(info AccessInfo) { errCalls = append(errCalls, info) }
	e2.ServeDNS(udpWriter(), query("roblox.example.", dns.TypeA)) // matches "gaming", but upstream fails
	if len(errCalls) != 0 {
		t.Errorf("an upstream error must never report an access: %+v", errCalls)
	}
}
