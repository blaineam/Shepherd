// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"encoding/json"
	"testing"
)

func TestAlarmPreferencesReadAndWrite(t *testing.T) {
	h := newHarness(t)
	out := h.ok("GET", "/api/alarms/preferences", "", 200)
	p := out["preferences"].(map[string]any)
	if p["immediate_min"] != "high" || p["digest"].(map[string]any)["every"] != "6h0m0s" {
		t.Fatalf("defaults = %v", p)
	}
	// Change the digest to a set time and lower the immediate threshold.
	p["immediate_min"] = "medium"
	p["digest"] = map[string]any{"enabled": true, "at": "08:30"}
	p["timezone"] = "UTC"
	body, _ := json.Marshal(p)
	out = h.ok("PUT", "/api/alarms/preferences", string(body), 200)
	p = out["preferences"].(map[string]any)
	if p["immediate_min"] != "medium" || p["digest"].(map[string]any)["at"] != "08:30" || p["timezone"] != "UTC" {
		t.Fatalf("after put = %v", p)
	}
	if got := h.alarms.Preferences(); got.Digest.At != "08:30" {
		t.Fatalf("engine kept %+v", got.Digest)
	}
	// Bad values are refused with the reason, and nothing changes.
	p["digest"] = map[string]any{"enabled": true, "at": "25:99"}
	body, _ = json.Marshal(p)
	h.expect("PUT", "/api/alarms/preferences", string(body), 400)
	p["digest"] = map[string]any{"enabled": true, "every": "10s"}
	body, _ = json.Marshal(p)
	h.expect("PUT", "/api/alarms/preferences", string(body), 400)
	h.expect("PUT", "/api/alarms/preferences", "{nope", 400)
	if got := h.alarms.Preferences(); got.Digest.At != "08:30" {
		t.Fatalf("a refused write changed the preferences: %+v", got.Digest)
	}
}
