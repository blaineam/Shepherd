// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"testing"
	"time"
)

func TestWanderingModeThroughTheAPI(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "")

	d := h.ok("PATCH", "/api/devices/"+id, `{"wandering":true,"wandering_minutes":60}`, 200)
	if d["wandering"] != true {
		t.Fatalf("device = %v", d)
	}
	until, err := time.Parse(time.RFC3339, d["wandering_until"].(string))
	if err != nil || until.Before(time.Now().Add(58*time.Minute)) || until.After(time.Now().Add(62*time.Minute)) {
		t.Errorf("a 60 minute timer must end about an hour from now, got %v (%v)", d["wandering_until"], err)
	}

	d = h.ok("PATCH", "/api/devices/"+id, `{"wandering":true}`, 200) // no minutes: until turned off
	if d["wandering"] != true || d["wandering_until"] != nil {
		t.Errorf("open-ended wandering must have no end time: %v", d)
	}
	if got := h.ok("GET", "/api/devices?q=wandering:true", "", 200)["total"]; got != float64(1) {
		t.Errorf("the search filter found %v devices", got)
	}

	other := h.addDevice("02:00:5e:00:00:02", "192.0.2.11", "")
	res := h.ok("POST", "/api/devices/bulk", `{"ids":["`+id+`","`+other+`"],"op":"set_wandering","wandering":true,"wandering_minutes":15}`, 200)
	if res["changed"] != float64(2) {
		t.Errorf("bulk = %v", res)
	}
	if got := h.ok("GET", "/api/devices/"+other, "", 200); got["wandering"] != true || got["wandering_until"] == nil {
		t.Errorf("bulk device = %v", got)
	}

	d = h.ok("PATCH", "/api/devices/"+id, `{"wandering":false}`, 200)
	if d["wandering"] != false || d["wandering_until"] != nil {
		t.Errorf("turning it off must clear the timer: %v", d)
	}

	// A timer that has run out reads as protected even before the sweep clears it.
	h.reg.SetWandering(other, true, time.Now().Add(-time.Minute))
	if got := h.ok("GET", "/api/devices/"+other, "", 200); got["wandering"] != false {
		t.Errorf("an expired timer must read as not wandering: %v", got)
	}
}

func TestWanderingRequestValidation(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "")
	h.expect("PATCH", "/api/devices/"+id, `{"wandering":true,"wandering_minutes":-1}`, 400)
	h.expect("PATCH", "/api/devices/"+id, `{"wandering":true,"wandering_minutes":99999}`, 400)
	h.expect("PATCH", "/api/devices/nope", `{"wandering":true}`, 404)
	h.expect("POST", "/api/devices/bulk", `{"ids":["`+id+`"],"op":"set_wandering"}`, 400)
	h.expect("POST", "/api/devices/bulk", `{"ids":["`+id+`"],"op":"set_wandering","wandering":true,"wandering_minutes":-5}`, 400)
	if got := h.ok("GET", "/api/devices/"+id, "", 200); got["wandering"] != false {
		t.Errorf("rejected requests must change nothing: %v", got)
	}
}
