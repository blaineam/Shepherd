// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestManagementAPIRequiresTokenAndCSRFHeader(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "")
	gets := []string{"/api/devices", "/api/devices/" + id, "/api/groups", "/api/catalog", "/api/policy", "/api/upstreams"}
	for _, p := range gets {
		if got := do(t, "GET", h.ts.URL+p, "", "", nil).StatusCode; got != 401 {
			t.Errorf("GET %s without token = %d", p, got)
		}
	}
	writes := []struct{ m, p, b string }{
		{"PATCH", "/api/devices/" + id, `{"alias":"x"}`},
		{"DELETE", "/api/devices/" + id, ""},
		{"POST", "/api/devices/bulk", `{"ids":["a"],"op":"delete"}`},
		{"POST", "/api/devices/merge", `{"target":"a","sources":["b"]}`},
		{"POST", "/api/groups", `{"name":"x"}`},
		{"PATCH", "/api/groups/x", `{"name":"y"}`},
		{"DELETE", "/api/groups/x", ""},
		{"POST", "/api/policy/items", `{}`},
		{"POST", "/api/policy/rules", `{}`},
		{"DELETE", "/api/policy/rules?scope_kind=network", ""},
		{"POST", "/api/policy/switches", `{}`},
		{"POST", "/api/policy/custom-lists", `{}`},
		{"DELETE", "/api/policy/custom-lists/x", ""},
		{"POST", "/api/policy/refresh", ""},
		{"POST", "/api/upstreams/test", `{}`},
		{"POST", "/api/upstreams", `{}`},
		{"DELETE", "/api/upstreams?addr=192.0.2.53", ""},
		{"PUT", "/api/upstreams", `{}`},
		{"PUT", "/api/upstreams/bootstrap", `{}`},
	}
	tok := strings.Repeat("t", 64)
	for _, w := range writes {
		if got := do(t, w.m, h.ts.URL+w.p, tok, w.b, nil).StatusCode; got != 403 {
			t.Errorf("%s %s without X-Shepherd = %d, want 403", w.m, w.p, got)
		}
		if got := do(t, w.m, h.ts.URL+w.p, "", w.b, hdr).StatusCode; got != 401 {
			t.Errorf("%s %s without token = %d, want 401", w.m, w.p, got)
		}
	}
	if _, ok := h.reg.Get(id); !ok || len(h.pool.List()) != 1 {
		t.Error("rejected requests changed state")
	}
}

func TestDeviceListShapeSearchAndPaging(t *testing.T) {
	h := newHarness(t)
	a := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "kitchen-tablet.local")
	h.addDevice("02:00:5e:00:00:02", "192.0.2.11", "")
	h.addDevice("02:00:5e:00:00:03", "2001:db8::3", "office-printer.local")

	m := h.ok("GET", "/api/devices", "", 200)
	if m["total"].(float64) != 3 || m["offset"].(float64) != 0 || m["limit"].(float64) != 100 || len(m["devices"].([]any)) != 3 {
		t.Fatalf("list = %v", m)
	}
	var got map[string]any
	for _, d := range m["devices"].([]any) {
		if d.(map[string]any)["id"] == a {
			got = d.(map[string]any)
		}
	}
	for _, k := range []string{"id", "name", "alias", "names", "vendor", "type", "type_reason", "macs", "ips", "first_seen", "last_seen", "groups", "tags", "excluded", "notes"} {
		if _, ok := got[k]; !ok {
			t.Errorf("device JSON lacks %q: %v", k, got)
		}
	}
	if got["name"] != "kitchen-tablet" || got["names"].(map[string]any)["mdns"] != "kitchen-tablet" {
		t.Errorf("names = %v", got)
	}
	if len(got["groups"].([]any)) != 0 || len(got["tags"].([]any)) != 0 {
		t.Error("empty lists must be [] and not null")
	}

	for q, want := range map[string]float64{"?q=printer": 1, "?q=ip:192.0.2.": 2, "?q=-ip:192.0.2.": 1, "?q=unnamed:true": 1, "?q=nomatch": 0} {
		if n := h.ok("GET", "/api/devices"+q, "", 200)["total"].(float64); n != want {
			t.Errorf("%s total = %v, want %v", q, n, want)
		}
	}
	page := h.ok("GET", "/api/devices?sort=name&limit=2&offset=1", "", 200)
	if page["limit"].(float64) != 2 || page["offset"].(float64) != 1 || len(page["devices"].([]any)) != 2 || page["total"].(float64) != 3 {
		t.Errorf("page = %v", page)
	}
	for _, bad := range []string{"?sort=oldest", "?offset=-1", "?limit=x", "?offset=1.5"} {
		h.expect("GET", "/api/devices"+bad, "", 400)
	}
	if n := h.ok("GET", "/api/devices?limit=0", "", 200)["limit"].(float64); n != 100 {
		t.Errorf("limit=0 should mean the default, got %v", n)
	}
	h.expect("GET", "/api/devices/nope", "", 404)
	h.ok("GET", "/api/devices/"+a, "", 200)
}

func TestPatchDevice(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "")
	d := h.ok("PATCH", "/api/devices/"+id, `{"alias":"Kitchen tablet","notes":"on the fridge","type":"tablet","excluded":true,"tags":["Kids","guest"]}`, 200)
	if d["alias"] != "Kitchen tablet" || d["name"] != "Kitchen tablet" || d["notes"] != "on the fridge" || d["type"] != "tablet" || d["excluded"] != true {
		t.Errorf("device = %v", d)
	}
	if got := strs(d["tags"]); len(got) != 2 || got[0] != "guest" || got[1] != "kids" {
		t.Errorf("tags = %v", got)
	}
	d = h.ok("PATCH", "/api/devices/"+id, `{"type":"auto","alias":"","excluded":false,"tags":[]}`, 200)
	if d["alias"] != "" || d["excluded"] != false || len(d["tags"].([]any)) != 0 {
		t.Errorf("cleared = %v", d)
	}
	h.expect("PATCH", "/api/devices/"+id, `{}`, 200)
	bads := []string{
		`{"alias":"` + strings.Repeat("a", 129) + `"}`,
		"{\"alias\":\"bad\\u0007\"}",
		`{"notes":"` + strings.Repeat("n", 2001) + `"}`,
		`{"type":"toaster"}`,
		`{"tags":["` + strings.Repeat("t", 33) + `"]}`,
		`{"tags":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u"]}`,
		`{"nope":1}`, `{"alias":1}`, `[]`, `{"alias":"x"} {"alias":"y"}`, `not json`,
	}
	for _, b := range bads {
		h.expect("PATCH", "/api/devices/"+id, b, 400)
	}
	h.expect("PATCH", "/api/devices/ghost", `{"alias":"x"}`, 404)
	if a := h.ok("GET", "/api/devices/"+id, "", 200)["alias"]; a != "" {
		t.Errorf("a rejected PATCH changed the device: %v", a)
	}
	h.expect("PATCH", "/api/devices/"+id, `{"alias":"`+strings.Repeat("a", 70000)+`"}`, http.StatusRequestEntityTooLarge)
}

func TestGroupsLifecycleAndValidation(t *testing.T) {
	h := newHarness(t)
	g := h.ok("POST", "/api/groups", `{"name":"Kids","color":"#ff8800"}`, 200)
	if g["id"] != "kids" || g["name"] != "Kids" || g["color"] != "#ff8800" || g["count"].(float64) != 0 {
		t.Fatalf("group = %v", g)
	}
	h.expect("POST", "/api/groups", `{"name":"kids"}`, 409)
	for _, b := range []string{`{}`, `{"name":""}`, `{"name":"` + strings.Repeat("n", 65) + `"}`, `{"name":"x","color":"red; background:url(x)"}`, `{"name":"x","extra":1}`, "{\"name\":\"a\\u0001\"}"} {
		h.expect("POST", "/api/groups", b, 400)
	}
	h.ok("POST", "/api/groups", `{"name":"Guests","color":"orange"}`, 200)
	h.ok("POST", "/api/groups", `{"name":"Plain"}`, 200)
	m := h.ok("GET", "/api/groups", "", 200)
	if len(m["groups"].([]any)) != 3 {
		t.Errorf("groups = %v", m)
	}
	r := h.ok("PATCH", "/api/groups/kids", `{"name":"Children","color":"#123"}`, 200)
	if r["name"] != "Children" || r["color"] != "#123" || r["id"] != "kids" {
		t.Errorf("patched = %v", r)
	}
	h.ok("PATCH", "/api/groups/kids", `{}`, 200)
	h.expect("PATCH", "/api/groups/kids", `{"name":"guests"}`, 409)
	h.expect("PATCH", "/api/groups/kids", `{"name":""}`, 400)
	h.expect("PATCH", "/api/groups/kids", `{"color":"url(x)"}`, 400)
	h.expect("PATCH", "/api/groups/kids", `{"bogus":1}`, 400)
	h.expect("PATCH", "/api/groups/ghost", `{"name":"x"}`, 404)
	h.expect("DELETE", "/api/groups/ghost", "", 404)
	h.ok("DELETE", "/api/groups/guests", "", 200)
	if n := len(h.ok("GET", "/api/groups", "", 200)["groups"].([]any)); n != 2 {
		t.Errorf("groups after delete = %d", n)
	}
}

func TestBulkOperationsAndMerge(t *testing.T) {
	h := newHarness(t)
	a := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "")
	b := h.addDevice("02:00:5e:00:00:02", "192.0.2.11", "")
	c := h.addDevice("02:00:5e:00:00:03", "192.0.2.12", "")
	h.ok("POST", "/api/groups", `{"name":"Kids"}`, 200)

	ids := fmt.Sprintf(`["%s","%s","ghost"]`, a, b)
	r := h.ok("POST", "/api/devices/bulk", `{"ids":`+ids+`,"op":"assign_group","group_id":"kids"}`, 200)
	if r["changed"].(float64) != 2 || len(r["missing"].([]any)) != 1 || r["missing"].([]any)[0] != "ghost" {
		t.Errorf("assign = %v", r)
	}
	if n := h.ok("GET", "/api/groups", "", 200)["groups"].([]any)[0].(map[string]any)["count"].(float64); n != 2 {
		t.Errorf("group count = %v", n)
	}
	if n := h.ok("GET", "/api/devices?q=group:kids", "", 200)["total"].(float64); n != 2 {
		t.Errorf("group search = %v", n)
	}
	r = h.ok("POST", "/api/devices/bulk", fmt.Sprintf(`{"ids":["%s"],"op":"assign_group","group_id":"kids"}`, a), 200)
	if r["changed"].(float64) != 0 || len(r["missing"].([]any)) != 0 {
		t.Errorf("idempotent assign = %v (missing must be [])", r)
	}
	h.ok("POST", "/api/devices/bulk", fmt.Sprintf(`{"ids":["%s"],"op":"remove_group","group_id":"kids"}`, b), 200)
	h.ok("POST", "/api/devices/bulk", fmt.Sprintf(`{"ids":["%s","%s"],"op":"set_excluded","excluded":true}`, a, c), 200)
	if n := h.ok("GET", "/api/devices?q=excluded:true", "", 200)["total"].(float64); n != 2 {
		t.Errorf("excluded = %v", n)
	}
	h.ok("POST", "/api/devices/bulk", fmt.Sprintf(`{"ids":["%s","%s"],"op":"set_tags","add_tags":["Guest","iot"],"remove_tags":["x"]}`, a, b), 200)
	if n := h.ok("GET", "/api/devices?q=tag:guest", "", 200)["total"].(float64); n != 2 {
		t.Errorf("tagged = %v", n)
	}

	bads := []string{
		`{"ids":[],"op":"delete"}`, `{"op":"delete"}`, `{"ids":["a"],"op":"explode"}`, `{"ids":["a"]}`,
		`{"ids":["a"],"op":"assign_group"}`, `{"ids":["a"],"op":"remove_group"}`,
		`{"ids":["a"],"op":"set_excluded"}`, `{"ids":["a"],"op":"set_tags"}`,
		`{"ids":["a"],"op":"set_tags","add_tags":["` + strings.Repeat("t", 40) + `"]}`,
		`{"ids":["a"],"op":"set_tags","remove_tags":["` + strings.Repeat("t", 40) + `"]}`,
		`{"ids":["a"],"op":"delete","bogus":1}`,
		`{"ids":[` + strings.Repeat(`"x",`, 2000) + `"x"],"op":"delete"}`,
	}
	for _, body := range bads {
		h.expect("POST", "/api/devices/bulk", body, 400)
	}
	h.expect("POST", "/api/devices/bulk", `{"ids":["a"],"op":"assign_group","group_id":"ghost"}`, 404)
	h.expect("POST", "/api/devices/bulk", `{"ids":["a"],"op":"remove_group","group_id":"ghost"}`, 404)

	// merge
	d := h.ok("POST", "/api/devices/merge", fmt.Sprintf(`{"target":"%s","sources":["%s"]}`, a, c), 200)
	if d["id"] != a || len(d["macs"].([]any)) != 2 {
		t.Errorf("merged = %v", d)
	}
	h.expect("GET", "/api/devices/"+c, "", 404)
	for body, want := range map[string]int{
		`{"target":"` + a + `","sources":["ghost"]}`:     404,
		`{"target":"ghost","sources":["` + b + `"]}`:     404,
		`{"target":"` + a + `","sources":["` + a + `"]}`: 400,
		`{"target":"","sources":["x"]}`:                  400,
		`{"target":"x","sources":[]}`:                    400,
		`{"target":"x","sources":["y"],"z":1}`:           400,
	} {
		h.expect("POST", "/api/devices/merge", body, want)
	}

	// bulk delete
	r = h.ok("POST", "/api/devices/bulk", fmt.Sprintf(`{"ids":["%s","%s"],"op":"delete"}`, a, b), 200)
	if r["changed"].(float64) != 2 {
		t.Errorf("delete = %v", r)
	}
	if h.reg.Len() != 0 {
		t.Error("devices remain")
	}
}

func TestDeletingThingsForgetsTheirPolicy(t *testing.T) {
	h := newHarness(t)
	a := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "")
	b := h.addDevice("02:00:5e:00:00:02", "192.0.2.11", "")
	c := h.addDevice("02:00:5e:00:00:03", "192.0.2.12", "")
	d := h.addDevice("02:00:5e:00:00:04", "192.0.2.13", "")
	h.ok("POST", "/api/groups", `{"name":"Kids"}`, 200)
	for _, sc := range []string{`{"kind":"device","id":"` + a + `"}`, `{"kind":"device","id":"` + b + `"}`, `{"kind":"device","id":"` + c + `"}`, `{"kind":"device","id":"` + d + `"}`, `{"kind":"group","id":"kids"}`} {
		h.ok("POST", "/api/policy/items", `{"scope":`+sc+`,"item":"chatapp","enabled":true}`, 200)
	}
	scopes := func() int { return len(h.ok("GET", "/api/policy", "", 200)["scopes"].([]any)) }
	if scopes() != 6 {
		t.Fatalf("scopes = %d", scopes())
	}
	h.ok("DELETE", "/api/devices/"+a, "", 200)
	h.expect("DELETE", "/api/devices/"+a, "", 404)
	h.ok("POST", "/api/devices/bulk", `{"ids":["`+b+`"],"op":"delete"}`, 200)
	h.ok("POST", "/api/devices/merge", fmt.Sprintf(`{"target":"%s","sources":["%s"]}`, c, d), 200)
	h.ok("DELETE", "/api/groups/kids", "", 200)
	if scopes() != 2 { // network and the merge target
		t.Errorf("scopes after deletes = %d, want 2", scopes())
	}
}

func TestQuarantineGroupCannotBeDeletedThroughThePortal(t *testing.T) {
	h := newHarness(t)
	h.reg.EnsureQuarantineGroup()
	before := len(h.ok("GET", "/api/groups", "", 200)["groups"].([]any))
	h.expect("DELETE", "/api/groups/quarantine", "", 403)
	after := h.ok("GET", "/api/groups", "", 200)
	if len(after["groups"].([]any)) != before {
		t.Errorf("a refused delete must not remove the group: before %d, after %v", before, after)
	}
	// Renaming and recoloring the reserved group through the portal still works.
	r := h.ok("PATCH", "/api/groups/quarantine", `{"name":"Holding Pen","color":"#123456"}`, 200)
	if r["name"] != "Holding Pen" || r["color"] != "#123456" || r["id"] != "quarantine" {
		t.Errorf("patched quarantine = %v", r)
	}
}
