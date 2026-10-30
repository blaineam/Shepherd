// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func scopeByKind(t *testing.T, policy map[string]any, kind, id string) map[string]any {
	t.Helper()
	for _, s := range policy["scopes"].([]any) {
		m := s.(map[string]any)
		sc := m["scope"].(map[string]any)
		if sc["kind"] == kind && sc["id"] == id {
			return m
		}
	}
	return nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestCatalogEndpoint(t *testing.T) {
	h := newHarness(t)
	m := h.ok("GET", "/api/catalog", "", 200)
	cats := strs(m["categories"])
	if len(cats) != 3 || cats[0] != "Ads and Trackers" {
		t.Errorf("categories = %v", cats)
	}
	byID := map[string]map[string]any{}
	for _, e := range m["entries"].([]any) {
		byID[e.(map[string]any)["id"].(string)] = e.(map[string]any)
	}
	chat := byID["chatapp"]
	if chat["kind"] != "app" || chat["name"] != "ChatApp" || chat["category"] != "Social" || chat["recommended"] != false {
		t.Errorf("chatapp = %v", chat)
	}
	if _, has := chat["includes"]; has {
		t.Error("includes only appears on entries that have it")
	}
	if ads := byID["ads-main"]; ads["recommended"] != true || ads["license"] != "Test license" || ads["approx_entries"].(float64) != 3 || ads["homepage"] == "" {
		t.Errorf("ads-main = %v", ads)
	}
	if soc := byID["social"]; soc["kind"] != "category" || soc["category"] != "Social" || strs(soc["includes"])[0] != "chatapp" {
		t.Errorf("social = %v", soc)
	}
}

func TestPolicyGroupScopeBlocksOnlyThatGroup(t *testing.T) {
	h := newHarness(t)
	kid := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "")
	adult := h.addDevice("02:00:5e:00:00:02", "192.0.2.11", "")
	h.ok("POST", "/api/groups", `{"name":"Kids"}`, 200)
	h.ok("POST", "/api/devices/bulk", fmt.Sprintf(`{"ids":["%s"],"op":"assign_group","group_id":"kids"}`, kid), 200)
	_ = adult

	p := h.ok("GET", "/api/policy", "", 200)
	net := scopeByKind(t, p, "network", "")
	if net == nil || net["items"].(map[string]any)["ads-main"] != true || net["switches"].(map[string]any)["apple-private-relay"] != true {
		t.Fatalf("network scope on a fresh install = %v", net)
	}
	if rules := net["rules"].(map[string]any); len(rules["allow"].([]any)) != 0 || len(rules["block"].([]any)) != 0 {
		t.Errorf("rules = %v", rules)
	}
	if len(p["switches"].([]any)) != 1 || p["switches"].([]any)[0].(map[string]any)["title"] == "" {
		t.Errorf("switches = %v", p["switches"])
	}

	p = h.ok("POST", "/api/policy/items", `{"scope":{"kind":"group","id":"kids"},"item":"social","enabled":true}`, 200)
	if g := scopeByKind(t, p, "group", "kids"); g == nil || g["items"].(map[string]any)["social"] != true {
		t.Fatalf("group scope = %v", g)
	}
	h.ok("POST", "/api/policy/refresh", "", 202)
	waitFor(t, "the chat list to load", func() bool { return h.filter.CheckFor("192.0.2.10", "chat.example", h.reg).Blocked })
	if h.filter.CheckFor("192.0.2.11", "chat.example", h.reg).Blocked {
		t.Error("a device outside the group must not be blocked")
	}
	if !h.filter.CheckFor("192.0.2.10", "ads.example", h.reg).Blocked && h.filter.Check("ads.example").Blocked {
		t.Error("network blocks must still apply to the group")
	}

	// enabled null removes the group's setting again
	p = h.ok("POST", "/api/policy/items", `{"scope":{"kind":"group","id":"kids"},"item":"social","enabled":null}`, 200)
	if g := scopeByKind(t, p, "group", "kids"); g != nil {
		t.Errorf("an emptied scope should not be listed: %v", g)
	}
	if h.filter.CheckFor("192.0.2.10", "chat.example", h.reg).Blocked {
		t.Error("clearing the setting must unblock")
	}

	// enabled=false at a device opts it out of a network-wide block
	h.ok("POST", "/api/policy/items", `{"scope":{"kind":"network"},"item":"chatapp","enabled":true}`, 200)
	h.ok("POST", "/api/policy/items", `{"scope":{"kind":"device","id":"`+adult+`"},"item":"chatapp","enabled":false}`, 200)
	p = h.ok("GET", "/api/policy", "", 200)
	if d := scopeByKind(t, p, "device", adult); d == nil || d["items"].(map[string]any)["chatapp"] != false {
		t.Errorf("explicit off must be reported as false: %v", d)
	}
	h.ok("POST", "/api/policy/refresh", `{"item":"chatapp"}`, 202)
	waitFor(t, "chatapp to load", func() bool { return h.filter.CheckFor("192.0.2.10", "chat.example", h.reg).Blocked })
	if h.filter.CheckFor("192.0.2.11", "chat.example", h.reg).Blocked {
		t.Error("the device-level opt-out must win")
	}
}

func TestPolicyItemAndSwitchValidation(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "")
	h.ok("POST", "/api/groups", `{"name":"Kids"}`, 200)
	items := map[string]int{
		`{"scope":{"kind":"network"},"item":"chatapp","enabled":true}`:                  200,
		`{"scope":{"kind":"device","id":"` + id + `"},"item":"chatapp","enabled":null}`: 200,
		`{"scope":{"kind":"network"},"item":"chatapp"}`:                                 400,
		`{"scope":{"kind":"network"},"item":"chatapp","enabled":"yes"}`:                 400,
		`{"scope":{"kind":"network","id":"x"},"item":"chatapp","enabled":true}`:         400,
		`{"scope":{"kind":"planet"},"item":"chatapp","enabled":true}`:                   400,
		`{"item":"chatapp","enabled":true}`:                                             400,
		`{"scope":{"kind":"group","id":"ghost"},"item":"chatapp","enabled":true}`:       404,
		`{"scope":{"kind":"device","id":"ghost"},"item":"chatapp","enabled":true}`:      404,
		`{"scope":{"kind":"network"},"item":"unknown","enabled":true}`:                  404,
		`{"scope":{"kind":"network"},"item":"chatapp","enabled":true,"extra":1}`:        400,
		`{"scope":{"kind":"network","id":"","x":1},"item":"chatapp","enabled":true}`:    400,
	}
	for body, want := range items {
		h.expect("POST", "/api/policy/items", body, want)
	}
	sw := map[string]int{
		`{"scope":{"kind":"network"},"name":"apple-private-relay","enabled":false}`:           200,
		`{"scope":{"kind":"group","id":"kids"},"name":"apple-private-relay","enabled":true}`:  200,
		`{"scope":{"kind":"group","id":"kids"},"name":"apple-private-relay","enabled":null}`:  200,
		`{"scope":{"kind":"network"},"name":"apple-private-relay"}`:                           400,
		`{"scope":{"kind":"network"},"name":"nope","enabled":true}`:                           404,
		`{"scope":{"kind":"group","id":"ghost"},"name":"apple-private-relay","enabled":true}`: 404,
		`{"scope":{"kind":"network"},"name":"apple-private-relay","enabled":true,"zzz":1}`:    400,
	}
	for body, want := range sw {
		h.expect("POST", "/api/policy/switches", body, want)
	}
	if d := h.filter.Check("mask.icloud.com"); d.Blocked {
		t.Error("the last network switch call turned the relay block on")
	}
	h.ok("POST", "/api/policy/switches", `{"scope":{"kind":"network"},"name":"apple-private-relay","enabled":true}`, 200)
	if d := h.filter.Check("mask.icloud.com"); !d.Blocked || !d.NXDOMAIN {
		t.Errorf("switch not applied: %+v", d)
	}
}

func TestPolicyRulesPerScope(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "")
	h.ok("POST", "/api/groups", `{"name":"Kids"}`, 200)
	h.ok("POST", "/api/devices/bulk", fmt.Sprintf(`{"ids":["%s"],"op":"assign_group","group_id":"kids"}`, id), 200)

	h.ok("POST", "/api/policy/rules", `{"scope":{"kind":"group","id":"kids"},"kind":"block","domain":"Video.Example."}`, 200)
	p := h.ok("POST", "/api/policy/rules", `{"scope":{"kind":"device","id":"`+id+`"},"kind":"allow","domain":"ok.video.example"}`, 200)
	g := scopeByKind(t, p, "group", "kids")
	if got := strs(g["rules"].(map[string]any)["block"]); len(got) != 1 || got[0] != "video.example" {
		t.Errorf("group rules = %v", g["rules"])
	}
	if !h.filter.CheckFor("192.0.2.10", "tube.video.example", h.reg).Blocked {
		t.Error("group block rule not applied")
	}
	if h.filter.CheckFor("192.0.2.10", "ok.video.example", h.reg).Blocked {
		t.Error("device allow must beat the group block")
	}
	h.ok("DELETE", "/api/policy/rules?scope_kind=group&scope_id=kids&kind=block&domain=video.example", "", 200)
	if h.filter.CheckFor("192.0.2.10", "tube.video.example", h.reg).Blocked {
		t.Error("rule survived deletion")
	}
	bads := []struct{ m, p, b string }{
		{"POST", "/api/policy/rules", `{"scope":{"kind":"network"},"kind":"maybe","domain":"a.example"}`},
		{"POST", "/api/policy/rules", `{"scope":{"kind":"network"},"kind":"block","domain":"not a domain"}`},
		{"POST", "/api/policy/rules", `{"scope":{"kind":"network"},"kind":"block"}`},
		{"POST", "/api/policy/rules", `{"kind":"block","domain":"a.example"}`},
		{"DELETE", "/api/policy/rules?scope_kind=network&kind=maybe&domain=a.example", ""},
		{"DELETE", "/api/policy/rules?kind=block&domain=a.example", ""},
		{"DELETE", "/api/policy/rules?scope_kind=network&scope_id=x&kind=block&domain=a.example", ""},
	}
	for _, c := range bads {
		h.expect(c.m, c.p, c.b, 400)
	}
	h.expect("POST", "/api/policy/rules", `{"scope":{"kind":"device","id":"ghost"},"kind":"block","domain":"a.example"}`, 404)
	h.expect("DELETE", "/api/policy/rules?scope_kind=group&scope_id=ghost&kind=block&domain=a.example", "", 404)
}

func TestCustomLists(t *testing.T) {
	h := newHarness(t)
	c := h.ok("POST", "/api/policy/custom-lists", `{"name":"My blocks","category":"mine","inline":"# mine\nbad1.example\nbad2.example\n"}`, 200)
	if c["id"] != "custom-my-blocks" || c["inline"] != true || c["count"].(float64) != 2 || c["category"] != "mine" {
		t.Fatalf("inline list = %v", c)
	}
	if _, has := c["url"]; has {
		t.Error("an inline list has no url")
	}
	u := h.ok("POST", "/api/policy/custom-lists", `{"name":"From web","url":"`+h.listSrv.URL+`/gameapp.txt"}`, 200)
	if u["url"] != h.listSrv.URL+"/gameapp.txt" || u["category"] != "custom" || u["count"].(float64) != 0 {
		t.Errorf("url list = %v", u)
	}
	// it is enabled at the network and the list manager picks it up
	h.ok("POST", "/api/policy/refresh", "", 202)
	waitFor(t, "custom list to load", func() bool { return h.filter.Check("game.example").Blocked })
	waitFor(t, "inline list to load", func() bool { return h.filter.Check("bad1.example").Blocked })
	p := h.ok("GET", "/api/policy", "", 200)
	if n := len(p["custom_lists"].([]any)); n != 2 {
		t.Errorf("custom lists = %d", n)
	}
	var sawCount bool
	for _, l := range p["lists"].([]any) {
		m := l.(map[string]any)
		if m["id"] == "custom-from-web" && m["count"].(float64) == 1 && m["updated"] != nil {
			sawCount = true
		}
	}
	if !sawCount {
		t.Errorf("lists = %v", p["lists"])
	}

	for _, b := range []string{
		`{}`, `{"name":"x"}`, `{"name":"x","url":"https://x.example/a","inline":"a.example"}`,
		`{"url":"https://x.example/a"}`, `{"name":"x","url":"ftp://x.example/a"}`, `{"name":"x","inline":"google.com\nok.example"}`,
		`{"name":"x","inline":""}`, `{"name":"x","extra":1,"url":"https://x.example/a"}`, `{"name":"` + strings.Repeat("n", 81) + `","url":"https://x.example/a"}`,
	} {
		h.expect("POST", "/api/policy/custom-lists", b, 400)
	}
	h.expect("POST", "/api/policy/custom-lists", `{"name":"big","inline":"`+strings.Repeat("a", 3<<20)+`"}`, 413)
	h.expect("POST", "/api/policy/custom-lists", `{"name":"big","inline":"`+strings.Repeat("a.example\\n", 120000)+`"}`, 400)

	h.ok("DELETE", "/api/policy/custom-lists/custom-my-blocks", "", 200)
	h.expect("DELETE", "/api/policy/custom-lists/custom-my-blocks", "", 404)
	h.expect("POST", "/api/policy/refresh", `{"item":"ghost"}`, 404)
	h.expect("POST", "/api/policy/refresh", `{"item":"x","y":1}`, 400)
}

func TestPolicySaveFailureIs500(t *testing.T) {
	h := newHarness(t)
	if err := os.RemoveAll(h.dir); err != nil {
		t.Fatal(err)
	}
	// a regular file where the directory should be: every save fails
	if err := os.WriteFile(h.dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(h.dir) })
	h.expect("POST", "/api/policy/items", `{"scope":{"kind":"network"},"item":"chatapp","enabled":true}`, 500)
	h.expect("POST", "/api/policy/rules", `{"scope":{"kind":"network"},"kind":"block","domain":"a.example"}`, 500)
	h.expect("POST", "/api/rules", `{"kind":"block","domain":"a.example"}`, 500)
	h.expect("POST", "/api/upstreams", `{"addr":"192.0.2.99"}`, 500)
	if len(h.pool.List()) != 1 {
		t.Error("a failed save must leave the pool as it was")
	}
}

func TestLegacyEndpointsActOnTheNetworkScope(t *testing.T) {
	h := newHarness(t)
	h.ok("POST", "/api/rules", `{"kind":"block","domain":"evil.example"}`, 200)
	h.ok("POST", "/api/rules", `{"kind":"allow","domain":"fine.example"}`, 200)
	r := h.ok("GET", "/api/rules", "", 200)
	if strs(r["block"])[0] != "evil.example" || strs(r["allow"])[0] != "fine.example" || r["policies"].(map[string]any)["apple-private-relay"] != true {
		t.Errorf("rules = %v", r)
	}
	p := h.ok("GET", "/api/policy", "", 200)
	if n := scopeByKind(t, p, "network", ""); strs(n["rules"].(map[string]any)["block"])[0] != "evil.example" {
		t.Errorf("network scope = %v", n)
	}
	r = h.ok("POST", "/api/policies", `{"name":"apple-private-relay","enabled":false}`, 200)
	if r["policies"].(map[string]any)["apple-private-relay"] != false {
		t.Errorf("policies = %v", r)
	}
	h.ok("DELETE", "/api/rules?kind=block&domain=evil.example", "", 200)
	if r := h.ok("GET", "/api/rules", "", 200); len(r["block"].([]any)) != 0 {
		t.Errorf("rules = %v", r)
	}
	h.expect("POST", "/api/lists/refresh", "", 202)
}

func TestStatusGainsDeviceAndCatalogCounts(t *testing.T) {
	h := newHarness(t)
	h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "")
	h.addDevice("02:00:5e:00:00:02", "192.0.2.11", "")
	h.ok("POST", "/api/groups", `{"name":"Kids"}`, 200)
	h.ok("POST", "/api/policy/custom-lists", `{"name":"mine","inline":"x.example"}`, 200)
	s := h.ok("GET", "/api/status", "", 200)
	want := map[string]float64{"device_count": 2, "group_count": 1, "catalog_count": 6, "custom_list_count": 1, "network_item_count": 2}
	for k, v := range want {
		if s[k] != v {
			t.Errorf("status[%s] = %v, want %v", k, s[k], v)
		}
	}
	if s["policies"].(map[string]any)["apple-private-relay"] != true {
		t.Errorf("status policies = %v", s["policies"])
	}
}
