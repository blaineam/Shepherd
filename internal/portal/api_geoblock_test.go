// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"fmt"
	"testing"
)

func TestGeoBlockEndpointsSetListAndClear(t *testing.T) {
	h := newHarness(t)

	m := h.ok("GET", "/api/geoblock", "", 200)
	if len(strs(m["network"])) != 0 {
		t.Errorf("fresh network list = %v", m["network"])
	}
	if m["groups"].(map[string]any) == nil || m["devices"].(map[string]any) == nil {
		t.Errorf("groups/devices must be present empty maps: %+v", m)
	}

	m = h.ok("POST", "/api/geoblock", `{"scope":{"kind":"network","id":""},"countries":["cn","RU"]}`, 200)
	if got := strs(m["network"]); len(got) != 2 || got[0] != "CN" || got[1] != "RU" {
		t.Errorf("network after set = %v", got)
	}

	kid := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "")
	h.ok("POST", "/api/groups", `{"name":"Kids"}`, 200)

	m = h.ok("POST", "/api/geoblock", `{"scope":{"kind":"group","id":"kids"},"countries":["KP"]}`, 200)
	groups := m["groups"].(map[string]any)
	if got := strs(groups["kids"]); len(got) != 1 || got[0] != "KP" {
		t.Errorf("groups.kids = %v", got)
	}

	m = h.ok("POST", "/api/geoblock", fmt.Sprintf(`{"scope":{"kind":"device","id":"%s"},"countries":["IR"]}`, kid), 200)
	devices := m["devices"].(map[string]any)
	if got := strs(devices[kid]); len(got) != 1 || got[0] != "IR" {
		t.Errorf("devices[%s] = %v", kid, got)
	}

	// Clearing (an empty list) drops the scope entirely rather than leaving an
	// empty entry behind.
	m = h.ok("POST", "/api/geoblock", `{"scope":{"kind":"group","id":"kids"},"countries":[]}`, 200)
	if _, has := m["groups"].(map[string]any)["kids"]; has {
		t.Errorf("cleared group must be absent: %+v", m["groups"])
	}

	// Round trip through a fresh fetch.
	m = h.ok("GET", "/api/geoblock", "", 200)
	if got := strs(m["network"]); len(got) != 2 {
		t.Errorf("GET after edits = %v", got)
	}
}

func TestGeoBlockEndpointValidation(t *testing.T) {
	h := newHarness(t)
	h.expect("POST", "/api/geoblock", `{"scope":{"kind":"network","id":""},"countries":["usa"]}`, 400)
	h.expect("POST", "/api/geoblock", `{"scope":{"kind":"group","id":"nope"},"countries":["US"]}`, 404)
	h.expect("POST", "/api/geoblock", `{"scope":{"kind":"device","id":"nope"},"countries":["US"]}`, 404)
	h.expect("POST", "/api/geoblock", `{"scope":{"kind":"bogus","id":""},"countries":["US"]}`, 400)
}

func TestGeoBlockDeletedWithItsGroupOrDevice(t *testing.T) {
	h := newHarness(t)
	kid := h.addDevice("02:00:5e:00:00:03", "192.0.2.20", "")
	h.ok("POST", "/api/groups", `{"name":"Kids"}`, 200)
	h.ok("POST", "/api/geoblock", `{"scope":{"kind":"group","id":"kids"},"countries":["KP"]}`, 200)
	h.ok("POST", "/api/geoblock", fmt.Sprintf(`{"scope":{"kind":"device","id":"%s"},"countries":["IR"]}`, kid), 200)

	h.ok("DELETE", "/api/groups/kids", "", 200)
	h.ok("DELETE", "/api/devices/"+kid, "", 200)

	m := h.ok("GET", "/api/geoblock", "", 200)
	if _, has := m["groups"].(map[string]any)["kids"]; has {
		t.Errorf("deleting the group must drop its geo-block scope: %+v", m)
	}
	if _, has := m["devices"].(map[string]any)[kid]; has {
		t.Errorf("deleting the device must drop its geo-block scope: %+v", m)
	}
}
