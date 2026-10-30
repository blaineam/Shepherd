// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// fakeClients is a ClientScopes backed by a map.
type fakeClients map[string]struct {
	device string
	groups []string
}

func (f fakeClients) ScopesFor(ip string) (string, []string) {
	return f[ip].device, f[ip].groups[:len(f[ip].groups):len(f[ip].groups)]
}

func client(device string, groups ...string) struct {
	device string
	groups []string
} {
	return struct {
		device string
		groups []string
	}{device, groups}
}

// scopedFilter loads three apps, two ad lists and enables, at network scope,
// the ad list and app one.
func scopedFilter(t *testing.T, cfg map[string]ScopeConfig) *Filter {
	t.Helper()
	f := NewFilter()
	f.SetList("ads-main", set("ads.example"))
	f.SetList("app-one", set("one.example"))
	f.SetList("app-two", set("two.example"))
	f.SetList("app-three", set("three.example", "ads.example"))
	f.SetScopes(cfg)
	return f
}

func on(ids ...string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func expect(t *testing.T, f *Filter, cs ClientScopes, ip, name string, blocked bool, reason, scope string) {
	t.Helper()
	d := f.CheckFor(ip, name, cs)
	if d.Blocked != blocked || d.Reason != reason || d.Scope != scope {
		t.Errorf("CheckFor(%s, %s) = %+v, want blocked=%v reason=%q scope=%q", ip, name, d, blocked, reason, scope)
	}
}

func TestScopeStringAndParse(t *testing.T) {
	for _, sc := range []Scope{NetworkScope(), GroupScope("kids"), DeviceScope("tv-1.lan")} {
		got, err := ParseScope(sc.String())
		if err != nil || got != sc {
			t.Errorf("round trip of %v = %v, %v", sc, got, err)
		}
	}
	for _, bad := range []string{"", "group", "group:", "other:x", "device:bad id", "network:x", "group:" + string(make([]byte, 200))} {
		if _, err := ParseScope(bad); err == nil {
			t.Errorf("ParseScope(%q) accepted", bad)
		}
	}
	if (Scope{Kind: "weird"}).level() != 0 {
		t.Error("unknown kinds must rank as least specific")
	}
}

// The scenario matrix. Setup: the network blocks app one and the ad list; the
// "teens" group blocks app two; the device "console" is a member of teens.
func TestScopedScenarioMatrix(t *testing.T) {
	f := scopedFilter(t, map[string]ScopeConfig{
		"network":     {Items: on("ads-main", "app-one")},
		"group:teens": {Items: on("app-two")},
	})
	cs := fakeClients{
		"198.51.100.1": client("console", "teens"),
		"198.51.100.2": client("laptop"),
		"198.51.100.3": client("", "teens"),
	}

	t.Run("network blocks one app", func(t *testing.T) {
		expect(t, f, cs, "198.51.100.2", "x.one.example", true, "app-one", "network")
		expect(t, f, nil, "", "one.example", true, "app-one", "network")
		expect(t, f, cs, "198.51.100.2", "ads.example", true, "ads-main", "network")
		expect(t, f, cs, "198.51.100.2", "three.example", false, "", "")
	})
	t.Run("a group blocks another app", func(t *testing.T) {
		expect(t, f, cs, "198.51.100.1", "two.example", true, "app-two", "group:teens")
		expect(t, f, cs, "198.51.100.3", "two.example", true, "app-two", "group:teens")
		expect(t, f, cs, "198.51.100.2", "two.example", false, "", "")
		// The group still inherits the network's blocks (union).
		expect(t, f, cs, "198.51.100.1", "one.example", true, "app-one", "network")
	})
	t.Run("unknown client falls back to network", func(t *testing.T) {
		expect(t, f, cs, "203.0.113.99", "one.example", true, "app-one", "network")
		expect(t, f, cs, "203.0.113.99", "two.example", false, "", "")
	})
}

func TestAllowOverridesAndPrecedence(t *testing.T) {
	cs := fakeClients{
		"192.0.2.1": client("dev1", "g1"),
		"192.0.2.2": client("dev2", "g1"),
		"192.0.2.3": client("dev3", "g1", "g2"),
		"192.0.2.4": client("dev4", "g2"),
	}
	f := scopedFilter(t, map[string]ScopeConfig{
		"network":     {Items: on("app-one"), Allow: []string{"ok.one.example"}},
		"group:g1":    {Items: on("app-two"), Allow: []string{"one.example"}, Block: []string{"blocked.example"}},
		"group:g2":    {Items: on("app-three")},
		"device:dev1": {Allow: []string{"two.example"}},
		"device:dev2": {Block: []string{"one.example"}, Allow: []string{"mine.example"}},
	})
	// Device allow beats the group's block of app two.
	expect(t, f, cs, "192.0.2.1", "two.example", false, "allowlist", "device:dev1")
	// ...and the group allow of one.example beats the network block for the whole group.
	expect(t, f, cs, "192.0.2.1", "one.example", false, "allowlist", "group:g1")
	expect(t, f, cs, "192.0.2.4", "one.example", true, "app-one", "network")
	// A block at a more specific scope beats an allow at a less specific one.
	expect(t, f, cs, "192.0.2.2", "one.example", true, "custom rule", "device:dev2")
	// An allow at the same scope beats a block at that scope.
	g := scopedFilter(t, map[string]ScopeConfig{"network": {Items: on("app-one"), Allow: []string{"one.example"}}})
	expect(t, g, nil, "", "x.one.example", false, "allowlist", "network")
	// A network allow covers subdomains but a more specific block still holds.
	expect(t, f, cs, "192.0.2.4", "ok.one.example", false, "allowlist", "network")
	expect(t, f, cs, "192.0.2.2", "ok.one.example", true, "custom rule", "device:dev2")
	// Custom block rules at a group.
	expect(t, f, cs, "192.0.2.1", "sub.blocked.example", true, "custom rule", "group:g1")
	expect(t, f, cs, "192.0.2.4", "sub.blocked.example", false, "", "")
	// Two groups: blocks union; an allow in one sibling group does not lift the other's block.
	expect(t, f, cs, "192.0.2.3", "three.example", true, "app-three", "group:g2")
	expect(t, f, cs, "192.0.2.3", "two.example", true, "app-two", "group:g1")
	expect(t, f, cs, "192.0.2.3", "one.example", false, "allowlist", "group:g1")
}

func TestOptOutAtMoreSpecificScope(t *testing.T) {
	cs := fakeClients{
		"192.0.2.1": client("gamer", "teens"),
		"192.0.2.2": client("kid", "teens"),
		"192.0.2.3": client("solo"),
	}
	f := scopedFilter(t, map[string]ScopeConfig{
		"network":      {Items: on("ads-main", "app-one", "app-two")},
		"group:teens":  {Items: map[string]bool{"app-one": false}},
		"device:gamer": {Items: map[string]bool{"ads-main": false, "app-two": false}},
		"device:solo":  {Items: on("app-three")},
	})
	// Group opts out of app one for everyone in it; the network still blocks it for others.
	expect(t, f, cs, "192.0.2.2", "one.example", false, "", "")
	expect(t, f, cs, "192.0.2.3", "one.example", true, "app-one", "network")
	// Device opts out of two items; the group's own opt-out is untouched.
	expect(t, f, cs, "192.0.2.1", "ads.example", false, "", "")
	expect(t, f, cs, "192.0.2.1", "two.example", false, "", "")
	expect(t, f, cs, "192.0.2.2", "two.example", true, "app-two", "network")
	expect(t, f, cs, "192.0.2.2", "ads.example", true, "ads-main", "network")
	// A name in two items stays blocked while one of them is still on: app three also lists ads.example.
	expect(t, f, cs, "192.0.2.3", "ads.example", true, "app-three", "device:solo")
	g := scopedFilter(t, map[string]ScopeConfig{
		"network":      {Items: on("ads-main")},
		"device:solo":  {Items: on("app-three")},
		"device:gamer": {Items: map[string]bool{"ads-main": false}},
	})
	cs2 := fakeClients{"192.0.2.9": client("gamer"), "192.0.2.3": client("solo")}
	expect(t, g, cs2, "192.0.2.9", "ads.example", false, "", "")
	expect(t, g, cs2, "192.0.2.3", "ads.example", true, "app-three", "device:solo")
	// A device-level "on" is not undone by a less specific "off".
	h := scopedFilter(t, map[string]ScopeConfig{
		"network":     {Items: map[string]bool{"app-one": false}},
		"device:solo": {Items: on("app-one")},
	})
	expect(t, h, cs2, "192.0.2.3", "one.example", true, "app-one", "device:solo")
	expect(t, h, nil, "", "one.example", false, "", "")
}

func TestPolicySwitchesAreScopeable(t *testing.T) {
	cs := fakeClients{"192.0.2.1": client("phone", "adults"), "192.0.2.2": client("tablet")}
	f := scopedFilter(t, map[string]ScopeConfig{
		"network":      {Policies: map[string]bool{PolicyPrivateRelay: true}},
		"device:phone": {Policies: map[string]bool{PolicyPrivateRelay: false}},
	})
	d := f.CheckFor("192.0.2.2", "mask.icloud.com", cs)
	if !d.Blocked || !d.NXDOMAIN || d.Reason != PolicyPrivateRelay || d.Scope != "network" {
		t.Errorf("network policy = %+v", d)
	}
	if d := f.CheckFor("192.0.2.1", "mask.icloud.com", cs); d.Blocked {
		t.Errorf("device opt-out ignored: %+v", d)
	}
	// Enabled only for one group.
	g := scopedFilter(t, map[string]ScopeConfig{"group:adults": {Policies: map[string]bool{PolicyPrivateRelay: true}}})
	if d := g.CheckFor("192.0.2.1", "mask-api.icloud.com", cs); !d.Blocked || d.Scope != "group:adults" {
		t.Errorf("group policy = %+v", d)
	}
	if g.CheckFor("192.0.2.2", "mask-api.icloud.com", cs).Blocked {
		t.Error("policy leaked outside its group")
	}
	// An allow rule overrides a policy at the same scope.
	h := scopedFilter(t, map[string]ScopeConfig{"network": {Policies: map[string]bool{PolicyPrivateRelay: true}, Allow: []string{"mask.icloud.com"}}})
	if h.Check("mask.icloud.com").Blocked {
		t.Error("allow must beat a policy at the same scope")
	}
}

func TestScopedItemsLoadedLaterAndRemovedStaleRules(t *testing.T) {
	f := NewFilter()
	f.SetScopes(map[string]ScopeConfig{"network": {Items: on("late")}, "group:old": {Block: []string{"old.example"}}})
	if f.Check("late.example").Blocked {
		t.Fatal("blocked before the list loaded")
	}
	cs := fakeClients{"192.0.2.1": client("", "old")}
	if !f.CheckFor("192.0.2.1", "old.example", cs).Blocked {
		t.Fatal("group rule missing")
	}
	// Loading the list afterwards activates it: cached masks are rebuilt.
	f.SetList("late", set("late.example"))
	if d := f.Check("late.example"); !d.Blocked || d.Reason != "late" {
		t.Errorf("late list not applied: %+v", d)
	}
	// Reconfiguring drops rule sets of scopes that disappeared.
	f.SetScopes(map[string]ScopeConfig{"network": {Items: on("late")}})
	if f.CheckFor("192.0.2.1", "old.example", cs).Blocked {
		t.Error("rules of a removed scope survived")
	}
	// Unloading a list stops it blocking.
	f.SetList("late", nil)
	if f.Check("late.example").Blocked {
		t.Error("unloaded list still blocks")
	}
}

func TestLegacyModeAppliesEverythingNetworkWide(t *testing.T) {
	f := NewFilter()
	f.SetList("l1", set("a.example"))
	f.SetList("l2", set("b.example"))
	if !f.Check("a.example").Blocked || !f.Check("b.example").Blocked {
		t.Error("legacy mode must apply every loaded list")
	}
	cs := fakeClients{"192.0.2.1": client("dev", "grp")}
	if d := f.CheckFor("192.0.2.1", "a.example", cs); !d.Blocked || d.Scope != "network" {
		t.Errorf("legacy decision for a known client = %+v", d)
	}
	// After SetScopes the legacy setters stop editing the network scope.
	f.SetScopes(map[string]ScopeConfig{"network": {}})
	f.SetRules(nil, []string{"legacy.example"})
	f.SetPolicy(PolicyPrivateRelay, []string{"mask.icloud.com"})
	if f.Check("legacy.example").Blocked || f.Check("mask.icloud.com").Blocked || f.Check("a.example").Blocked {
		t.Error("legacy setters must be inert once scoped")
	}
}

func TestSignatureCacheIsBoundedAndInvalidated(t *testing.T) {
	f := scopedFilter(t, map[string]ScopeConfig{"network": {Items: on("app-one")}})
	cs := dynamicClients(func(ip string) (string, []string) { return "dev-" + ip, nil })
	for i := 0; i < maxCachedSignatures+50; i++ {
		f.CheckFor(fmt.Sprint(i), "one.example", cs)
	}
	if n := f.pol.Load().n.Load(); n != maxCachedSignatures {
		t.Errorf("cache size = %d, want the bound %d", n, maxCachedSignatures)
	}
	// Past the bound a query is still decided correctly.
	if !f.CheckFor("99999", "one.example", cs).Blocked {
		t.Error("uncached signature decided wrongly")
	}
	// Reconfiguring swaps the state and with it the cache.
	f.SetScopes(map[string]ScopeConfig{"network": {}})
	if f.pol.Load().n.Load() != 0 {
		t.Error("configuration change did not drop the cache")
	}
}

type dynamicClients func(string) (string, []string)

func (d dynamicClients) ScopesFor(ip string) (string, []string) { return d(ip) }

func TestMultiGroupSignatureKeysDiffer(t *testing.T) {
	f := scopedFilter(t, map[string]ScopeConfig{
		"group:a": {Items: on("app-one")}, "group:b": {Items: on("app-two")}, "group:c": {Items: on("app-three")},
	})
	cs := fakeClients{
		"192.0.2.1": client("", "a", "b"),
		"192.0.2.2": client("", "a", "c"),
		"192.0.2.3": client("", "a"),
	}
	expect(t, f, cs, "192.0.2.1", "two.example", true, "app-two", "group:b")
	expect(t, f, cs, "192.0.2.1", "three.example", false, "", "")
	expect(t, f, cs, "192.0.2.2", "three.example", true, "app-three", "group:c")
	expect(t, f, cs, "192.0.2.2", "two.example", false, "", "")
	expect(t, f, cs, "192.0.2.3", "one.example", true, "app-one", "group:a")
}

func TestCheckForConcurrentWithReconfiguration(t *testing.T) {
	f := scopedFilter(t, map[string]ScopeConfig{"network": {Items: on("app-one")}})
	cs := fakeClients{"192.0.2.1": client("dev", "g")}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					f.CheckFor("192.0.2.1", "one.example", cs)
					f.Check("x.two.example")
				}
			}
		}()
	}
	for i := 0; i < 30; i++ {
		f.SetScopes(map[string]ScopeConfig{"network": {Items: on("app-one", "app-two")}, "group:g": {Block: []string{fmt.Sprintf("n%d.example", i)}}})
		f.SetList("app-one", set("one.example", fmt.Sprintf("m%d.example", i)))
	}
	close(stop)
	wg.Wait()
}

func TestScopedConfigRestoresPoliciesRemovedByLegacySetter(t *testing.T) {
	f := NewFilter()
	f.SetPolicy(PolicyPrivateRelay, nil) // legacy "off" drops the policy's domains
	f.SetScopes(map[string]ScopeConfig{"network": {Policies: map[string]bool{PolicyPrivateRelay: true}}})
	if !f.Check("mask.icloud.com").Blocked {
		t.Error("scoped configuration must restore the built-in policy domains")
	}
}

func startScopedEngine(t *testing.T, clients ClientScopes) (*Engine, string) {
	t.Helper()
	var hits atomic.Int32
	pool, err := NewPool([]string{fakeUpstream(t, "192.0.2.9", &hits)})
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Filter: NewFilter(), Pool: pool, Cache: NewCache(100), Log: NewQueryLog(50), Stats: NewStats(), Clients: clients}
	e.Filter.SetList("app-one", set("one.example"))
	e.Filter.SetScopes(map[string]ScopeConfig{"device:probe": {Items: on("app-one")}})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: e}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return e, pc.LocalAddr().String()
}

func TestEngineUsesClientScopes(t *testing.T) {
	// With no ClientScopes every client is network-only, so nothing blocks.
	_, addr := startScopedEngine(t, nil)
	if r := ask(t, addr, "one.example.", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) {
		t.Errorf("unscoped query was blocked: %v", r.Answer)
	}
	// The test client connects from 127.0.0.1; map it to the device.
	e, addr := startScopedEngine(t, fakeClients{"127.0.0.1": client("probe")})
	if r := ask(t, addr, "one.example.", dns.TypeA); len(r.Answer) != 1 || !r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) {
		t.Errorf("scoped block not applied: %v", r.Answer)
	}
	entries, _ := e.Log.After(0, 10)
	if last := entries[len(entries)-1]; last.Action != "blocked" || last.Reason != "app-one" {
		t.Errorf("log entry = %+v", last)
	}
}

func BenchmarkCheckForScoped(b *testing.B) {
	f := NewFilter()
	big := make(map[string]struct{}, 300000)
	for i := 0; i < 300000; i++ {
		big[fmt.Sprintf("d%d.example", i)] = struct{}{}
	}
	f.SetList("ads-main", big)
	f.SetList("app-one", set("one.example", "d5.example"))
	f.SetScopes(map[string]ScopeConfig{"network": {Items: on("ads-main")}, "group:g": {Items: on("app-one")}})
	cs := fakeClients{"192.0.2.1": client("dev", "g")}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.CheckFor("192.0.2.1", "www.d5.example", cs)
		f.CheckFor("192.0.2.1", "clean.example", cs)
	}
}
