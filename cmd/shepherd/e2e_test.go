// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
)

// Everything here uses loopback and reserved names only.

// answerServer is a fake upstream resolver: every A query gets 192.0.2.99.
func answerServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.99")})
		}
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// listServer serves the block lists the test catalog points at.
func listServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ads.txt":
			fmt.Fprint(w, "ads.example\n")
		case "/chat.txt":
			fmt.Fprint(w, "chat.example\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func testCatalogFor(t *testing.T, base string) *dnsengine.CatalogSet {
	t.Helper()
	cat, err := dnsengine.NewCatalogSet([]dnsengine.CatalogEntry{
		{ID: "ads-main", Kind: dnsengine.KindList, Name: "Main ads", Category: "ads", Recommended: true,
			Sources: []dnsengine.Source{{URL: base + "/ads.txt", Format: "domains"}}},
		{ID: "chatapp", Kind: dnsengine.KindApp, Name: "ChatApp", Category: "social",
			Sources: []dnsengine.Source{{URL: base + "/chat.txt", Format: "domains"}}},
		{ID: "ads", Kind: dnsengine.KindCategory, Name: "Ads", Includes: []string{"ads-main"}},
		{ID: "social", Kind: dnsengine.KindCategory, Name: "Social", Includes: []string{"chatapp"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func useCatalog(t *testing.T, c *dnsengine.CatalogSet) {
	t.Helper()
	catalogOverride = c
	t.Cleanup(func() { catalogOverride = nil })
}

// allowLoopbackDevices lets the test's loopback clients become devices.
func allowLoopbackDevices(t *testing.T) {
	t.Helper()
	registryOptions = func(o *devices.Options) { o.AllowLoopback = true }
	t.Cleanup(func() { registryOptions = func(*devices.Options) {} })
}

func ipv6Loopback(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback on this machine")
	}
	l.Close()
}

type e2eConfig struct {
	dir, path        string
	dnsPort, webPort int
}

// writeE2EConfig writes a config shaped like a running deployment: one [[lists]]
// entry, an upstream, and the DNS server on both loopback families.
func writeE2EConfig(t *testing.T, dir, upstream, listURL string, extra string) e2eConfig {
	t.Helper()
	c := e2eConfig{dir: dir, dnsPort: freeBothPort(t), webPort: freePort(t)}
	c.path = filepath.Join(dir, "shepherd.toml")
	body := fmt.Sprintf(`data_dir = %q
[dns]
listen = ["127.0.0.1:%d", "[::1]:%d"]
upstreams = [%q]
[privacy]
block_private_relay = true
[portal]
listen = "127.0.0.1:%d"
[map]
enabled = false
[devices]
neighbors = false
mdns = false
reverse_dns = false
[arp]
enabled = false
# WAN-exposure checking does real SSDP multicast discovery against whatever
# router is actually on this machine's network, defaults enabled, so it is
# disabled here too, the same way arp/mdns/map above are: nothing in this
# file should ever reach past loopback.
[portscan.wan_exposure]
enabled = false
%s
[[lists]]
name = "pro"
url = %q
`, filepath.Join(dir, "data"), c.dnsPort, c.dnsPort, upstream, c.webPort, extra, listURL)
	if err := os.WriteFile(c.path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// freeBothPort finds a port free on 127.0.0.1 and [::1] for UDP and TCP.
func freeBothPort(t *testing.T) int {
	t.Helper()
	for range 50 {
		port := freePort(t)
		ok := true
		for _, addr := range []string{"127.0.0.1", "[::1]"} {
			pc, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", addr, port))
			if err != nil {
				ok = false
				break
			}
			pc.Close()
		}
		if ok {
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

func (c e2eConfig) startRun(t *testing.T) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, c.path, false, os.Stdout) }()
	r := &running{t: t, dnsAddr: fmt.Sprintf("127.0.0.1:%d", c.dnsPort), portalBase: fmt.Sprintf("http://127.0.0.1:%d", c.webPort)}
	r.stop = func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run returned %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("run did not stop")
		}
	}
	waitUntil(t, "the portal token", func() bool {
		b, err := os.ReadFile(filepath.Join(c.dir, "data", "portal-token"))
		r.token = strings.TrimSpace(string(b))
		return err == nil && len(r.token) >= 32
	})
	waitUntil(t, "DNS to answer", func() bool {
		q := new(dns.Msg)
		q.SetQuestion("mask.icloud.com.", dns.TypeA)
		_, _, err := (&dns.Client{Timeout: 300 * time.Millisecond}).Exchange(q, r.dnsAddr)
		return err == nil
	})
	return r
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// resolve asks the server from a specific loopback family and returns the
// first A address ("" when there is none).
func resolve(t *testing.T, server, name string) string {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	resp, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(q, server)
	if err != nil {
		t.Fatalf("query %s via %s: %v", name, server, err)
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

func (r *running) json(method, path, body string, want int) map[string]any {
	r.t.Helper()
	code, out := r.api(method, path, body)
	if code != want {
		r.t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, out)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(out), &m)
	return m
}

func deviceIDForIP(t *testing.T, r *running, ip string) string {
	t.Helper()
	m := r.json("GET", "/api/devices?limit=500", "", 200)
	for _, d := range m["devices"].([]any) {
		dm := d.(map[string]any)
		for _, a := range dm["ips"].([]any) {
			if a == ip {
				return dm["id"].(string)
			}
		}
	}
	t.Fatalf("no device holds %s: %v", ip, m)
	return ""
}

func TestEndToEndLegacyMigrationGroupsPolicyAndUpstreams(t *testing.T) {
	ipv6Loopback(t)
	allowLoopbackDevices(t)
	lists := listServer(t)
	useCatalog(t, testCatalogFor(t, lists.URL))
	upstream := answerServer(t)

	// A deployment that predates the policy store: a rules.json with allow, block and
	// a policy switch the user turned off, and one configured list that is also in the catalog.
	dir := t.TempDir()
	cfg := writeE2EConfig(t, dir, upstream, lists.URL+"/ads.txt", "")
	os.MkdirAll(filepath.Join(dir, "data"), 0o750)
	os.WriteFile(filepath.Join(dir, "data", "rules.json"),
		[]byte(`{"allow":["fine.chat.example"],"block":["blocked.example"],"policies":{"apple-private-relay":false}}`), 0o640)

	r := cfg.startRun(t)
	stopped := false
	defer func() {
		if !stopped {
			r.stop()
		}
	}()

	// Migration lost nothing and added nothing.
	p := r.json("GET", "/api/policy", "", 200)
	net := p["scopes"].([]any)[0].(map[string]any)
	items := net["items"].(map[string]any)
	if len(items) != 1 || items["ads-main"] != true {
		t.Errorf("migrated network items = %v, want only the configured list", items)
	}
	rules := net["rules"].(map[string]any)
	if rules["allow"].([]any)[0] != "fine.chat.example" || rules["block"].([]any)[0] != "blocked.example" {
		t.Errorf("migrated rules = %v", rules)
	}
	if net["switches"].(map[string]any)["apple-private-relay"] != false {
		t.Errorf("the switched-off policy must stay off: %v", net["switches"])
	}
	v4, v6 := fmt.Sprintf("127.0.0.1:%d", cfg.dnsPort), fmt.Sprintf("[::1]:%d", cfg.dnsPort)
	waitUntil(t, "the migrated list to load", func() bool { return resolve(t, v4, "x.ads.example.") == "0.0.0.0" })
	if got := resolve(t, v4, "blocked.example."); got != "0.0.0.0" {
		t.Errorf("legacy block rule: got %q", got)
	}
	if got := resolve(t, v4, "mask.icloud.com."); got == "" {
		t.Error("relay answered NXDOMAIN though the user had switched it off")
	}

	// Both loopback clients became devices through their DNS queries.
	resolve(t, v6, "warm.example.")
	idA, idB := deviceIDForIP(t, r, "127.0.0.1"), deviceIDForIP(t, r, "::1")
	if idA == idB {
		t.Fatal("two clients, one device")
	}

	// Create a group, assign device A by bulk operation, block an app for that group only.
	g := r.json("POST", "/api/groups", `{"name":"Kids","color":"#ff8800"}`, 200)
	if g["id"] != "kids" {
		t.Fatalf("group = %v", g)
	}
	res := r.json("POST", "/api/devices/bulk", fmt.Sprintf(`{"ids":["%s"],"op":"assign_group","group_id":"kids"}`, idA), 200)
	if res["changed"].(float64) != 1 {
		t.Fatalf("bulk = %v", res)
	}
	r.json("POST", "/api/policy/items", `{"scope":{"kind":"group","id":"kids"},"item":"chatapp","enabled":true}`, 200)
	waitUntil(t, "the chat list to load for the group", func() bool { return resolve(t, v4, "www.chat.example.") == "0.0.0.0" })
	if got := resolve(t, v6, "www.chat.example."); got != "192.0.2.99" {
		t.Errorf("a device outside the group must not be blocked, got %q", got)
	}
	// Network-wide blocks still reach both devices.
	for _, srv := range []string{v4, v6} {
		if got := resolve(t, srv, "x.ads.example."); got != "0.0.0.0" {
			t.Errorf("%s: network list not applied: %q", srv, got)
		}
	}
	// An allow rule at the network is less specific than the group's block, so the
	// group's block wins for its member and the other device is simply not blocked.
	if got := resolve(t, v4, "fine.chat.example."); got != "0.0.0.0" {
		t.Errorf("a group block must beat a network allow, got %q", got)
	}
	if got := resolve(t, v6, "fine.chat.example."); got != "192.0.2.99" {
		t.Errorf("the allow rule must apply to the other device, got %q", got)
	}

	// Device names show up in the live ring.
	q := r.json("GET", "/api/queries?limit=200", "", 200)
	var named bool
	for _, e := range q["entries"].([]any) {
		em := e.(map[string]any)
		if em["client"] == "127.0.0.1" && em["device_id"] == idA && em["device"] != "" {
			named = true
		}
	}
	if !named {
		t.Error("queries must carry the device name and ID")
	}
	st := r.json("GET", "/api/status", "", 200)
	// 2 groups: Kids, plus the reserved Quarantine group every install now has.
	if st["device_count"].(float64) != 2 || st["group_count"].(float64) != 2 {
		t.Errorf("status = %v", st)
	}

	// Upstreams: test, add, list, remove, all through the API; persisted.
	second := answerServer(t)
	if tr := r.json("POST", "/api/upstreams/test", `{"addr":"`+second+`"}`, 200); tr["ok"] != true {
		t.Errorf("upstream test = %v", tr)
	}
	u := r.json("POST", "/api/upstreams", `{"addr":"`+second+`"}`, 200)
	if len(u["upstreams"].([]any)) != 2 {
		t.Fatalf("after add = %v", u)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "upstreams.json")); err != nil {
		t.Errorf("upstreams.json not written: %v", err)
	}
	u = r.json("DELETE", "/api/upstreams?addr="+upstream, "", 200)
	if got := u["upstreams"].([]any); len(got) != 1 || got[0].(map[string]any)["config"] != second {
		t.Errorf("after remove = %v", got)
	}

	// Restart on the same data directory: everything survives, and the saved
	// upstream list wins over the configuration.
	r.stop()
	stopped = true
	for _, f := range []string{"policy.json", "devices.json", "upstreams.json"} {
		info, err := os.Stat(filepath.Join(dir, "data", f))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, info, err)
		}
	}
	r2 := cfg.startRun(t)
	defer r2.stop()
	waitUntil(t, "the group block to return after a restart", func() bool { return resolve(t, v4, "www.chat.example.") == "0.0.0.0" })
	if got := resolve(t, v6, "www.chat.example."); got != "192.0.2.99" {
		t.Errorf("after restart the other device must still be free, got %q", got)
	}
	m := r2.json("GET", "/api/upstreams", "", 200)
	if got := m["upstreams"].([]any); len(got) != 1 || got[0].(map[string]any)["config"] != second {
		t.Errorf("upstreams after restart = %v", got)
	}
	if deviceIDForIP(t, r2, "127.0.0.1") != idA {
		t.Error("the device ID must survive a restart")
	}
	gs := r2.json("GET", "/api/groups", "", 200)["groups"].([]any)
	byID := map[string]map[string]any{}
	for _, g := range gs {
		gm := g.(map[string]any)
		byID[gm["id"].(string)] = gm
	}
	// Kids holds idA (explicitly assigned, which released it from quarantine);
	// idB was discovered but never assigned anywhere, so it is still quarantined.
	if len(gs) != 2 || byID["kids"] == nil || byID["kids"]["count"].(float64) != 1 ||
		byID["quarantine"] == nil || byID["quarantine"]["count"].(float64) != 1 {
		t.Errorf("groups after restart = %v", gs)
	}
}

func TestExcludedDeviceIsNotFiltered(t *testing.T) {
	allowLoopbackDevices(t)
	lists := listServer(t)
	useCatalog(t, testCatalogFor(t, lists.URL))
	cfgPath := writeConfig(t, freePort(t), freePort(t), "")
	body, _ := os.ReadFile(cfgPath)
	up := answerServer(t)
	body = []byte(strings.Replace(string(body), `["192.0.2.53"]`, `["`+up+`"]`, 1))
	// a legacy-style list, so ads.example is blocked at the network
	body = append(body, []byte("\n[[lists]]\nname = \"pro\"\nurl = \""+lists.URL+"/ads.txt\"\n")...)
	os.WriteFile(cfgPath, body, 0o600)
	r := start(t, cfgPath)
	defer r.stop()
	waitUntil(t, "the list to load", func() bool { return resolve(t, r.dnsAddr, "x.ads.example.") == "0.0.0.0" })
	id := deviceIDForIP(t, r, "127.0.0.1")
	r.json("PATCH", "/api/devices/"+id, `{"excluded":true}`, 200)
	if got := resolve(t, r.dnsAddr, "x.ads.example."); got != "192.0.2.99" {
		t.Errorf("an excluded device must not be filtered, got %q", got)
	}
	// dnsengine.Engine.done records the query-log entry before ServeDNS
	// ever writes the client's response (see its own doc comment), so the
	// entry for the resolve above is already there by the time this
	// query-log request fires. Still poll briefly rather than asserting
	// on the very first read: this is a separate HTTP round trip to the
	// portal API, with its own ordinary scheduling latency to allow for.
	var reason string
	waitUntil(t, "the allowed query to be logged", func() bool {
		for _, e := range r.json("GET", "/api/queries?limit=50", "", 200)["entries"].([]any) {
			if em := e.(map[string]any); em["name"] == "x.ads.example" && em["action"] == "allowed" {
				reason, _ = em["reason"].(string)
				if reason == "excluded" {
					return true
				}
			}
		}
		return false
	})
	if reason != "excluded" {
		t.Errorf("entry reason = %q", reason)
	}
	r.json("PATCH", "/api/devices/"+id, `{"excluded":false}`, 200)
	if got := resolve(t, r.dnsAddr, "x.ads.example."); got != "0.0.0.0" {
		t.Errorf("filtering must resume, got %q", got)
	}
}

func TestWanderingDeviceIsWatchedButNotFiltered(t *testing.T) {
	allowLoopbackDevices(t)
	lists := listServer(t)
	useCatalog(t, testCatalogFor(t, lists.URL))
	cfgPath := writeConfig(t, freePort(t), freePort(t), "")
	body, _ := os.ReadFile(cfgPath)
	up := answerServer(t)
	body = []byte(strings.Replace(string(body), `["192.0.2.53"]`, `["`+up+`"]`, 1))
	body = append(body, []byte("\n[[lists]]\nname = \"pro\"\nurl = \""+lists.URL+"/ads.txt\"\n")...)
	os.WriteFile(cfgPath, body, 0o600)
	r := start(t, cfgPath)
	defer r.stop()
	waitUntil(t, "the list to load", func() bool { return resolve(t, r.dnsAddr, "x.ads.example.") == "0.0.0.0" })
	id := deviceIDForIP(t, r, "127.0.0.1")

	r.json("PATCH", "/api/devices/"+id, `{"wandering":true,"wandering_minutes":60}`, 200)
	if got := resolve(t, r.dnsAddr, "x.ads.example."); got != "192.0.2.99" {
		t.Errorf("a wandering device must not be filtered, got %q", got)
	}
	// See the matching comment in TestExcludedDeviceIsNotFiltered: the log
	// entry for the resolve above can still be landing when this fires.
	var found map[string]any
	waitUntil(t, "the allowed query to be logged", func() bool {
		for _, e := range r.json("GET", "/api/queries?limit=50", "", 200)["entries"].([]any) {
			if em := e.(map[string]any); em["name"] == "x.ads.example" && em["action"] == "allowed" {
				found = em
			}
		}
		return found != nil
	})
	if found == nil || found["reason"] != "wandering" || found["wandering"] != true || found["shadow"] == nil {
		t.Errorf("the request must be logged as wandering with a shadow result: %v", found)
	}

	r.json("PATCH", "/api/devices/"+id, `{"wandering":false}`, 200)
	if got := resolve(t, r.dnsAddr, "x.ads.example."); got != "0.0.0.0" {
		t.Errorf("filtering must resume, got %q", got)
	}
}

func TestDevicesAreClassifiedAutomaticallyFromRealDNSTraffic(t *testing.T) {
	allowLoopbackDevices(t)
	classifyEvery = 30 * time.Millisecond
	t.Cleanup(func() { classifyEvery = 0 })

	c := writeE2EConfig(t, t.TempDir(), answerServer(t), listServer(t).URL+"/ads.txt", "")
	r := c.startRun(t)
	defer r.stop()

	// Real, verified rule data (internal/classify/rules/domains.json): three
	// distinct Netflix-family domains, each scored toward "tv". A few lookups
	// each is enough evidence to cross the classifier's threshold.
	for i := 0; i < 4; i++ {
		for _, name := range []string{"netflix.com.", "nflxso.net.", "nflxext.com."} {
			resolve(t, r.dnsAddr, name)
		}
	}

	id := deviceIDForIP(t, r, "127.0.0.1")
	var dev map[string]any
	waitUntil(t, "the classifier to guess a type", func() bool {
		dev = r.json("GET", "/api/devices/"+id, "", 200)
		typ, _ := dev["type"].(string)
		return typ == "tv" || typ == "streaming box"
	})
	if dev["type_auto"] != true {
		t.Errorf("a guessed type must be marked type_auto: %v", dev)
	}
	if conf, _ := dev["type_confidence"].(float64); conf <= 0 {
		t.Errorf("type_confidence = %v, want > 0", dev["type_confidence"])
	}
	if reason, _ := dev["type_reason"].(string); reason == "" {
		t.Error("a guessed type must come with a plain-language reason")
	}

	// A type the user sets themselves always wins and is never overwritten by
	// later evidence, even through the real API and the real classifier loop.
	r.json("PATCH", "/api/devices/"+id, `{"type":"laptop"}`, 200)
	for i := 0; i < 4; i++ {
		for _, name := range []string{"netflix.com.", "nflxso.net.", "nflxext.com."} {
			resolve(t, r.dnsAddr, name)
		}
	}
	time.Sleep(150 * time.Millisecond) // give a few more Apply ticks a chance to (wrongly) overwrite it
	dev = r.json("GET", "/api/devices/"+id, "", 200)
	if dev["type"] != "laptop" || dev["type_auto"] == true {
		t.Errorf("a user-set type must survive the classifier: %v", dev)
	}
}

func TestNewDevicesAreQuarantinedUntilMovedToARealGroup(t *testing.T) {
	allowLoopbackDevices(t)
	c := writeE2EConfig(t, t.TempDir(), answerServer(t), listServer(t).URL+"/ads.txt", "")
	r := c.startRun(t)
	defer r.stop()

	resolve(t, r.dnsAddr, "warmup.example.com.") // creates the one test device
	id := deviceIDForIP(t, r, "127.0.0.1")

	dev := r.json("GET", "/api/devices/"+id, "", 200)
	groups, _ := dev["groups"].([]any)
	if len(groups) != 1 || groups[0] != "quarantine" {
		t.Fatalf("a newly discovered device must start in quarantine, got groups=%v", groups)
	}
	gl := r.json("GET", "/api/groups", "", 200)
	var quarantine map[string]any
	for _, g := range gl["groups"].([]any) {
		if gm := g.(map[string]any); gm["id"] == "quarantine" {
			quarantine = gm
		}
	}
	if quarantine == nil || quarantine["name"] != "Quarantine" {
		t.Fatalf("the reserved group must exist and be named Quarantine: %v", gl)
	}
	if code, _ := r.api("DELETE", "/api/groups/quarantine", ""); code != 403 {
		t.Errorf("deleting quarantine through the real API = %d, want 403", code)
	}

	kids := r.json("POST", "/api/groups", `{"name":"Kids"}`, 200)
	r.json("POST", "/api/devices/bulk", `{"ids":["`+id+`"],"op":"assign_group","group_id":"`+kids["id"].(string)+`"}`, 200)

	dev = r.json("GET", "/api/devices/"+id, "", 200)
	groups, _ = dev["groups"].([]any)
	if len(groups) != 1 || groups[0] != "kids" {
		t.Errorf("moving to a real group must release quarantine: groups=%v", groups)
	}
}

func TestQuarantineOnNewDevicesCanBeOptedOut(t *testing.T) {
	allowLoopbackDevices(t)
	c := writeE2EConfig(t, t.TempDir(), answerServer(t), listServer(t).URL+"/ads.txt", "")
	body, err := os.ReadFile(c.path)
	if err != nil {
		t.Fatal(err)
	}
	// splice into the existing [devices] table: a second [devices] header is
	// invalid TOML (a duplicate table), not something to introduce in a test.
	patched := strings.Replace(string(body), "reverse_dns = false\n", "reverse_dns = false\nquarantine_new_devices = false\n", 1)
	if patched == string(body) {
		t.Fatal("did not find the [devices] block to patch")
	}
	if err := os.WriteFile(c.path, []byte(patched), 0o600); err != nil {
		t.Fatal(err)
	}
	r := c.startRun(t)
	defer r.stop()

	resolve(t, r.dnsAddr, "warmup.example.com.")
	id := deviceIDForIP(t, r, "127.0.0.1")
	dev := r.json("GET", "/api/devices/"+id, "", 200)
	if groups, _ := dev["groups"].([]any); len(groups) != 0 {
		t.Errorf("quarantine_new_devices = false must leave new devices ungrouped: groups=%v", groups)
	}
	// The reserved group still exists (so policy can be configured for it ahead of time);
	// it is only the automatic assignment that is turned off.
	gl := r.json("GET", "/api/groups", "", 200)
	found := false
	for _, g := range gl["groups"].([]any) {
		if gm := g.(map[string]any); gm["id"] == "quarantine" {
			found = true
		}
	}
	if !found {
		t.Error("the quarantine group should still exist even with auto-assignment off")
	}
}
