// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"fmt"
	"strings"
	"testing"

	"shepherd/internal/alarms"
)

// raiseTestAlarm raises one alarm directly on the harness's engine and
// returns its ID.
func (h *harness) raiseTestAlarm(typ, deviceID string) string {
	h.t.Helper()
	a, err := h.alarms.RaiseSync(alarms.Event{Type: typ, DeviceID: deviceID, Title: "t: " + typ})
	if err != nil {
		h.t.Fatal(err)
	}
	return a.ID
}

func TestAlarmsAPIRequiresTokenAndCSRFHeader(t *testing.T) {
	h := newHarness(t)
	id := h.raiseTestAlarm(alarms.TypeNewDevice, "dev1")
	gets := []string{"/api/alarms", "/api/alarms/" + id, "/api/alarms/summary", "/api/alarms/types", "/api/alarms/rules"}
	for _, p := range gets {
		if got := do(t, "GET", h.ts.URL+p, "", "", nil).StatusCode; got != 401 {
			t.Errorf("GET %s without token = %d", p, got)
		}
	}
	writes := []struct{ m, p, b string }{
		{"PATCH", "/api/alarms/" + id, `{"state":"acknowledged"}`},
		{"DELETE", "/api/alarms/" + id, ""},
		{"POST", "/api/alarms/" + id + "/mute", `{"preset":"1h"}`},
		{"POST", "/api/alarms/bulk", `{"all":true,"op":"acknowledge"}`},
		{"POST", "/api/alarms/undo", `{"handle":"x"}`},
		{"POST", "/api/alarms/rules", `{"name":"x"}`},
		{"DELETE", "/api/alarms/rules/x", ""},
	}
	for _, w := range writes {
		if got := do(t, w.m, h.ts.URL+w.p, "", w.b, nil).StatusCode; got != 401 {
			t.Errorf("%s %s without token = %d", w.m, w.p, got)
		}
		if got := do(t, w.m, h.ts.URL+w.p, strings.Repeat("t", 64), w.b, nil).StatusCode; got != 403 {
			t.Errorf("%s %s without the CSRF header = %d", w.m, w.p, got)
		}
	}
}

func TestListAlarmsFiltersAndPages(t *testing.T) {
	h := newHarness(t)
	h.raiseTestAlarm(alarms.TypeNewDevice, "dev1")
	h.raiseTestAlarm(alarms.TypeUpstreamDown, "")

	out := h.ok("GET", "/api/alarms", "", 200)
	if int(out["total"].(float64)) != 2 {
		t.Fatalf("list = %+v", out)
	}
	out = h.ok("GET", "/api/alarms?types=new-device", "", 200)
	if int(out["total"].(float64)) != 1 {
		t.Fatalf("filtered list = %+v", out)
	}
	out = h.ok("GET", "/api/alarms?severities=critical", "", 200)
	if int(out["total"].(float64)) != 0 {
		t.Fatalf("severity filter = %+v", out)
	}
	out = h.ok("GET", "/api/alarms?min_severity=info&sort=first_seen&asc=1&states=new&since=2000-01-01T00%3A00%3A00Z&until=2100-01-01T00%3A00%3A00Z", "", 200)
	if int(out["total"].(float64)) != 2 {
		t.Fatalf("min_severity/sort/asc/states/since/until = %+v", out)
	}
	h.expect("GET", "/api/alarms?offset=-1", "", 400)
	h.expect("GET", "/api/alarms?sort=bogus", "", 400)
	h.expect("GET", "/api/alarms?severities=bogus", "", 400)
	h.expect("GET", "/api/alarms?states=bogus", "", 400)
	h.expect("GET", "/api/alarms?min_severity=bogus", "", 400)
	h.expect("GET", "/api/alarms?since=not-a-time", "", 400)
	h.expect("GET", "/api/alarms?until=not-a-time", "", 400)
}

func TestGetAlarmAndChildrenOfABundle(t *testing.T) {
	h := newHarness(t)
	id := h.raiseTestAlarm(alarms.TypeNewDevice, "dev1")
	out := h.ok("GET", "/api/alarms/"+id, "", 200)
	a := out["alarm"].(map[string]any)
	if a["id"] != id {
		t.Fatalf("get = %+v", out)
	}
	h.expect("GET", "/api/alarms/nope", "", 404)
}

func TestGetAlarmBundleIncludesChildren(t *testing.T) {
	h := newHarness(t)
	// More than the storm threshold (5) of distinct new-device alarms for the
	// same device within the storm window collapse into one bundle alarm.
	for i := 0; i < 6; i++ {
		if _, err := h.alarms.RaiseSync(alarms.Event{Type: alarms.TypeNewDevice, DeviceID: "dev1", Domain: fmt.Sprintf("d%d.example", i)}); err != nil {
			t.Fatal(err)
		}
	}
	page := h.alarms.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeNewDevice}, IncludeChildren: true}, Limit: 50})
	var bundleID string
	for _, a := range page.Alarms {
		if a.Bundle {
			bundleID = a.ID
		}
	}
	if bundleID == "" {
		t.Fatalf("expected a storm bundle among %+v", page.Alarms)
	}
	out := h.ok("GET", "/api/alarms/"+bundleID, "", 200)
	children, ok := out["children"].([]any)
	if !ok || len(children) == 0 {
		t.Fatalf("a bundle's response must include its children: %+v", out)
	}
}

func TestPatchAlarmAcknowledgeAndResolve(t *testing.T) {
	h := newHarness(t)
	id := h.raiseTestAlarm(alarms.TypeNewDevice, "dev1")

	out := h.ok("PATCH", "/api/alarms/"+id, `{"state":"acknowledged"}`, 200)
	if out["alarm"].(map[string]any)["state"] != "acknowledged" {
		t.Fatalf("patch ack = %+v", out)
	}
	out = h.ok("PATCH", "/api/alarms/"+id, `{"state":"resolved"}`, 200)
	if out["alarm"].(map[string]any)["state"] != "resolved" {
		t.Fatalf("patch resolve = %+v", out)
	}
	h.expect("PATCH", "/api/alarms/"+id, `{"state":"bogus"}`, 400)
	h.expect("PATCH", "/api/alarms/nope", `{"state":"acknowledged"}`, 404)
}

func TestDeleteAlarm(t *testing.T) {
	h := newHarness(t)
	id := h.raiseTestAlarm(alarms.TypeNewDevice, "dev1")
	h.ok("DELETE", "/api/alarms/"+id, "", 200)
	h.expect("GET", "/api/alarms/"+id, "", 404)
	h.expect("DELETE", "/api/alarms/"+id, "", 404)
}

func TestMuteSingleAlarmSnoozesIt(t *testing.T) {
	h := newHarness(t)
	id := h.raiseTestAlarm(alarms.TypeNewDevice, "dev1")
	out := h.ok("POST", "/api/alarms/"+id+"/mute", `{"preset":"1h"}`, 200)
	if out["alarm"].(map[string]any)["state"] != "muted" {
		t.Fatalf("mute = %+v", out)
	}
	h.expect("POST", "/api/alarms/"+id+"/mute", `{"preset":"bogus"}`, 400)
	h.expect("POST", "/api/alarms/nope/mute", `{"preset":"1h"}`, 404)
}

func TestAlarmsBulkAcknowledgeResolveDeleteAndMute(t *testing.T) {
	h := newHarness(t)
	a1 := h.raiseTestAlarm(alarms.TypeNewDevice, "dev1")
	a2 := h.raiseTestAlarm(alarms.TypeUpstreamDown, "")

	out := h.ok("POST", "/api/alarms/bulk", `{"ids":["`+a1+`","`+a2+`"],"op":"acknowledge"}`, 200)
	if int(out["changed"].(float64)) != 2 {
		t.Fatalf("bulk ack = %+v", out)
	}
	out = h.ok("POST", "/api/alarms/bulk", `{"all":true,"op":"resolve"}`, 200)
	if int(out["changed"].(float64)) != 2 {
		t.Fatalf("bulk resolve = %+v", out)
	}

	a3 := h.raiseTestAlarm(alarms.TypeNewDevice, "dev2")
	out = h.ok("POST", "/api/alarms/bulk", `{"ids":["`+a3+`"],"op":"mute","mute":{"by":"alarm","duration":{"preset":"1h"}}}`, 200)
	if int(out["changed"].(float64)) != 1 {
		t.Fatalf("bulk mute = %+v", out)
	}

	out = h.ok("POST", "/api/alarms/bulk", `{"ids":["`+a3+`"],"op":"delete"}`, 200)
	if int(out["changed"].(float64)) != 1 {
		t.Fatalf("bulk delete = %+v", out)
	}

	h.expect("POST", "/api/alarms/bulk", `{"all":true,"op":"bogus"}`, 400)
	h.expect("POST", "/api/alarms/bulk", `{"op":"acknowledge"}`, 400) // empty selector
	h.expect("POST", "/api/alarms/bulk", `{"all":true,"op":"mute"}`, 400)
}

func TestUndoAlarmsBatch(t *testing.T) {
	h := newHarness(t)
	id := h.raiseTestAlarm(alarms.TypeNewDevice, "dev1")
	out := h.ok("POST", "/api/alarms/bulk", `{"ids":["`+id+`"],"op":"acknowledge"}`, 200)
	handle, _ := out["handle"].(string)
	if handle == "" {
		t.Fatalf("bulk ack did not return a handle: %+v", out)
	}
	out = h.ok("POST", "/api/alarms/undo", `{"handle":"`+handle+`"}`, 200)
	if int(out["changed"].(float64)) != 1 {
		t.Fatalf("undo = %+v", out)
	}
	h.expect("POST", "/api/alarms/undo", `{"handle":"`+handle+`"}`, 404) // used up
	h.expect("POST", "/api/alarms/undo", `{"handle":"nope"}`, 404)
}

func TestAlarmsSummaryAndTypes(t *testing.T) {
	h := newHarness(t)
	h.raiseTestAlarm(alarms.TypeNewDevice, "dev1")
	out := h.ok("GET", "/api/alarms/summary", "", 200)
	if int(out["total"].(float64)) != 1 {
		t.Fatalf("summary = %+v", out)
	}
	out = h.ok("GET", "/api/alarms/types", "", 200)
	types, ok := out["types"].([]any)
	if !ok || len(types) == 0 {
		t.Fatalf("types = %+v", out)
	}
}

func TestAlarmRulesCRUD(t *testing.T) {
	h := newHarness(t)
	h.raiseTestAlarm(alarms.TypeNewDevice, "dev1")

	out := h.ok("POST", "/api/alarms/rules", `{"name":"quiet dev1","match":{"device_ids":["dev1"]},"duration":{"preset":"forever"}}`, 200)
	rule := out["rule"].(map[string]any)
	ruleID, _ := rule["id"].(string)
	if ruleID == "" {
		t.Fatalf("create rule = %+v", out)
	}
	result := out["result"].(map[string]any)
	if int(result["changed"].(float64)) != 1 {
		t.Fatalf("create rule should have muted the matching alarm: %+v", out)
	}

	listed := h.ok("GET", "/api/alarms/rules", "", 200)
	rules := listed["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("list rules = %+v", listed)
	}

	h.ok("DELETE", "/api/alarms/rules/"+ruleID, "", 200)
	h.expect("DELETE", "/api/alarms/rules/"+ruleID, "", 404)

	listed = h.ok("GET", "/api/alarms/rules", "", 200)
	if rules := listed["rules"].([]any); len(rules) != 0 {
		t.Fatalf("rule must be gone from the active list: %+v", listed)
	}
	listed = h.ok("GET", "/api/alarms/rules?all=1", "", 200)
	if rules := listed["rules"].([]any); len(rules) != 1 {
		t.Fatalf("removed rule must still show with all=1: %+v", listed)
	}

	h.expect("POST", "/api/alarms/rules", `{"name":"bad"}`, 400) // no match criteria
}

func TestUpstreamAlarmTypesAreBuiltIn(t *testing.T) {
	h := newHarness(t)
	out := h.ok("GET", "/api/alarms/types", "", 200)
	var sawDown, sawUp bool
	for _, raw := range out["types"].([]any) {
		m := raw.(map[string]any)
		switch m["id"] {
		case alarms.TypeUpstreamDown:
			sawDown = true
		case alarms.TypeUpstreamRecovered:
			sawUp = true
		}
	}
	if !sawDown || !sawUp {
		t.Fatalf("types = %+v", out["types"])
	}
}
