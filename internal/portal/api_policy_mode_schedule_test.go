// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import "testing"

func TestPolicyModeEndpoint(t *testing.T) {
	h := newHarness(t)
	h.ok("POST", "/api/groups", `{"name":"Kids"}`, 200)

	p := h.ok("POST", "/api/policy/mode", `{"scope":{"kind":"network"},"mode":"allow"}`, 200)
	net := scopeByKind(t, p, "network", "")
	if net["mode"] != "allow" {
		t.Fatalf("network mode = %v", net["mode"])
	}
	if d := h.filter.Check("unmatched.example"); !d.Blocked {
		t.Error("allow mode not applied to the filter")
	}

	p = h.ok("POST", "/api/policy/mode", `{"scope":{"kind":"group","id":"kids"},"mode":"block"}`, 200)
	grp := scopeByKind(t, p, "group", "kids")
	if grp == nil || grp["mode"] != "block" {
		t.Fatalf("group mode = %v", grp)
	}

	// mode:null clears it.
	p = h.ok("POST", "/api/policy/mode", `{"scope":{"kind":"network"},"mode":null}`, 200)
	net = scopeByKind(t, p, "network", "")
	if net != nil && net["mode"] != "" && net["mode"] != nil {
		t.Errorf("mode not cleared: %v", net)
	}
	if d := h.filter.Check("unmatched.example"); d.Blocked {
		t.Error("clearing mode must restore the block-mode default")
	}

	bads := []string{
		`{"scope":{"kind":"network"},"mode":"sideways"}`,
		`{"scope":{"kind":"planet"},"mode":"allow"}`,
		`{"scope":{"kind":"network"},"mode":"allow","extra":1}`,
	}
	for _, b := range bads {
		h.expect("POST", "/api/policy/mode", b, 400)
	}
	h.expect("POST", "/api/policy/mode", `{"scope":{"kind":"group","id":"ghost"},"mode":"allow"}`, 404)
}

func TestPolicyRuleScheduleRoundTrips(t *testing.T) {
	h := newHarness(t)
	body := `{"scope":{"kind":"network"},"kind":"block","domain":"evening.example",` +
		`"schedule":{"days":[1,2,3,4,5],"start_min":1080,"end_min":1260}}`
	p := h.ok("POST", "/api/policy/rules", body, 200)
	net := scopeByKind(t, p, "network", "")
	sched := net["rule_schedules"].(map[string]any)["block"].(map[string]any)["evening.example"].(map[string]any)
	if days := sched["days"].([]any); len(days) != 5 || days[0].(float64) != 1 {
		t.Errorf("schedule days = %v", sched["days"])
	}
	if sched["start_min"].(float64) != 1080 || sched["end_min"].(float64) != 1260 {
		t.Errorf("schedule times = %v", sched)
	}

	bads := []string{
		`{"scope":{"kind":"network"},"kind":"block","domain":"x.example","schedule":{"days":[],"start_min":0,"end_min":60}}`,
		`{"scope":{"kind":"network"},"kind":"block","domain":"x.example","schedule":{"days":[1],"start_min":60,"end_min":0}}`,
		`{"scope":{"kind":"network"},"kind":"block","domain":"not a domain","schedule":{"days":[1],"start_min":0,"end_min":60}}`,
		`{not valid json`,
	}
	for _, b := range bads {
		h.expect("POST", "/api/policy/rules", b, 400)
	}

	// Re-adding the same rule with no schedule clears it.
	p = h.ok("POST", "/api/policy/rules", `{"scope":{"kind":"network"},"kind":"block","domain":"evening.example"}`, 200)
	net = scopeByKind(t, p, "network", "")
	if _, has := net["rule_schedules"].(map[string]any)["block"].(map[string]any)["evening.example"]; has {
		t.Error("re-adding plainly must clear the schedule")
	}
}
