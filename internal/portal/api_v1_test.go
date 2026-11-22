// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"shepherd/internal/backends"
	"shepherd/internal/backends/hub"
)

var v1Caps = []backends.Capability{
	backends.CapDevices, backends.CapFlows, backends.CapAlarms, backends.CapRules, backends.CapRuleWrite,
	backends.CapRuleCreate, backends.CapDeviceRename, backends.CapDeviceBlock, backends.CapAlarmDismiss,
	backends.CapGroups, backends.CapGroupWrite,
}

func v1Harness(t *testing.T, caps ...backends.Capability) (*harness, *fakeHub) {
	t.Helper()
	h := newHarness(t)
	when := time.Unix(1795300000, 0).UTC()
	fh := &fakeHub{running: true, snap: hub.Snapshot{
		Name: "firewalla", Capabilities: caps, Status: hub.Status{Name: "firewalla", LastPoll: &when},
		Devices: []backends.Device{
			{MAC: "02005e000002", Name: "tablet", IP: "192.0.2.6", Online: true, Native: "02:00:5E:00:00:02", NameFrom: backends.NameLearned},
			{MAC: "02005e000001", Name: "Den TV", IP: "192.0.2.5", Vendor: "ExampleCo", Online: true, Group: "Smart Home", Network: "LAN", Box: "box-1", Native: "02:00:5E:00:00:01", NameFrom: backends.NameTyped},
			{MAC: "02005e000003", Name: "old phone", Online: true, Blocked: true, Native: "02:00:5E:00:00:03"},
		},
		Groups: []backends.Group{{ID: "18", Name: "Smart Home"}, {ID: "17", Name: "Den"}},
		Rules:  []backends.Rule{{ID: "26", Action: "block", TargetType: "category", Target: "games", DNSOnly: true, Created: when}, {ID: "27", Action: "allow", TargetType: "domain", Target: "example.org", ScopeType: "device", Scope: "02005e000001", Paused: true}},
		Alarms: []backends.Alarm{{ID: "81", Box: "box-1", Type: "New Device", Message: "Found a device", Time: when, DeviceMAC: "02005e000001", Device: "Den TV"}, {ID: "82", Type: "Large Upload", Message: "Uploaded a lot", Domain: "example.org"}},
	}}
	h.srv.Backend = fh
	return h, fh
}

func list(t *testing.T, out map[string]any, key string) []map[string]any {
	t.Helper()
	raw, ok := out[key].([]any)
	if !ok {
		t.Fatalf("%s = %#v", key, out[key])
	}
	res := make([]map[string]any, len(raw))
	for i, v := range raw {
		res[i] = v.(map[string]any)
	}
	return res
}

func TestTheRouterAPIDescribesWhatIsConnected(t *testing.T) {
	h := newHarness(t)
	out := h.ok("GET", "/api/v1/router", "", 200)
	if out["connected"] != false || len(out["capabilities"].([]any)) != 0 {
		t.Fatalf("nothing wired = %v", out)
	}
	code, body := h.call("GET", "/api/v1/devices", "")
	if code != 404 || !strings.Contains(body, `"code":"not_connected"`) {
		t.Fatalf("devices with nothing wired = %d %s", code, body)
	}
	h.srv.Backend = &fakeHub{}
	if out := h.ok("GET", "/api/v1/router", "", 200); out["connected"] != false {
		t.Fatalf("nothing running = %v", out)
	}
	if code, body := h.call("GET", "/api/v1/devices", ""); code != 404 || !strings.Contains(body, "not_connected") {
		t.Fatalf("devices with nothing running = %d %s", code, body)
	}

	h, fh := v1Harness(t, v1Caps...)
	fh.snap.Status.Errors = map[string]string{"flows": "HTTP 500"}
	out = h.ok("GET", "/api/v1/router", "", 200)
	if out["connected"] != true || out["product"] != "firewalla" || out["read_only"] != false || len(out["capabilities"].([]any)) != len(v1Caps) {
		t.Fatalf("router = %v", out)
	}
	if errs, _ := out["errors"].(map[string]any); errs["flows"] != "HTTP 500" || out["last_read"] == nil {
		t.Fatalf("router = %v", out)
	}
}

func TestDevicesAreListedFoundAndChanged(t *testing.T) {
	h, fh := v1Harness(t, v1Caps...)
	devs := list(t, h.ok("GET", "/api/v1/devices", "", 200), "devices")
	if len(devs) != 3 || devs[0]["name"] != "Den TV" || devs[1]["name"] != "old phone" {
		t.Fatalf("devices = %v", devs)
	}
	tv := devs[0]
	if tv["mac"] != "02005e000001" || tv["group"] != "Smart Home" || tv["name_from"] != "typed" || tv["online"] != true || tv["blocked"] != false || tv["network"] != "LAN" {
		t.Fatalf("tv = %v", tv)
	}
	// A device Shepherd cut off is not online, whatever the product says.
	if devs[1]["blocked"] != true || devs[1]["online"] != false {
		t.Fatalf("blocked device = %v", devs[1])
	}
	// Any way of writing the MAC finds it.
	if one := h.ok("GET", "/api/v1/devices/02:00:5E:00:00:01", "", 200); one["name"] != "Den TV" {
		t.Fatalf("one = %v", one)
	}
	for path, want := range map[string]string{"/api/v1/devices/not-a-mac": `"code":"invalid"`, "/api/v1/devices/02005e0000ff": `"code":"not_found"`} {
		if code, body := h.call("GET", path, ""); !strings.Contains(body, want) || code < 400 {
			t.Errorf("%s = %d %s", path, code, body)
		}
	}

	out := h.ok("PATCH", "/api/v1/devices/02005e000001", `{"name":"Living room TV","group":"Den","blocked":true}`, 200)
	if out["mac"] != "02005e000001" {
		t.Fatalf("patch = %v", out)
	}
	want := []string{"rename box-1/02:00:5E:00:00:01 Living room TV", "group box-1/02:00:5E:00:00:01 Den", "block box-1/02:00:5E:00:00:01"}
	if got := fh.wrote(); !reflect.DeepEqual(got, want) {
		t.Fatalf("writes = %v", got)
	}
	// An empty group takes it out; false unblocks.
	h.ok("PATCH", "/api/v1/devices/02005e000001", `{"group":"","blocked":false}`, 200)
	if got := fh.wrote(); got[3] != "group box-1/02:00:5E:00:00:01 " || got[4] != "unblock box-1/02:00:5E:00:00:01" {
		t.Fatalf("writes = %v", got)
	}

	n := len(fh.wrote())
	for body, want := range map[string]string{`{}`: "at least one of", `nope`: "", `{"name":5}`: ""} {
		code, out := h.call("PATCH", "/api/v1/devices/02005e000001", body)
		if code != 400 || !strings.Contains(out, want) {
			t.Errorf("PATCH %s = %d %s", body, code, out)
		}
	}
	h.expect("PATCH", "/api/v1/devices/02005e0000ff", `{"name":"x"}`, 404)
	if len(fh.wrote()) != n {
		t.Fatal("an unusable change was sent")
	}

	// The router's refusals come back in the API's own shape, and the
	// first failure stops the rest.
	for err, want := range map[error][2]string{
		backends.ErrReadOnly:      {"403", "read_only"},
		backends.ErrNotFound:      {"404", "not_found"},
		backends.ErrRateLimited:   {"429", "rate_limited"},
		backends.ErrAuth:          {"502", "credential_refused"},
		errors.New("box offline"): {"502", "router_error"},
		fmt.Errorf("%w: a device name is 1 to 32 characters", backends.ErrInvalid): {"400", "1 to 32 characters"},
	} {
		fh.err = err
		before := len(fh.wrote())
		code, body := h.call("PATCH", "/api/v1/devices/02005e000001", `{"name":"x","group":"Den"}`)
		if fmt.Sprint(code) != want[0] || !strings.Contains(body, want[1]) {
			t.Errorf("%v = %d %s", err, code, body)
		}
		if len(fh.wrote()) != before+1 {
			t.Errorf("%v: carried on after the failure", err)
		}
	}
	fh.err = errors.New("box offline")
	for _, body := range []string{`{"group":"Den"}`, `{"blocked":true}`} {
		if code, _ := h.call("PATCH", "/api/v1/devices/02005e000001", body); code != 502 {
			t.Errorf("PATCH %s with the router failing = %d", body, code)
		}
	}
}

func TestACallTheProductCannotServeSaysWhy(t *testing.T) {
	// A product with no groups and no rename, with changes allowed.
	h, fh := v1Harness(t, backends.CapDevices, backends.CapRules, backends.CapRuleWrite)
	for call, body := range map[string]string{
		"GET /api/v1/groups": "", "GET /api/v1/alarms": "", "GET /api/v1/flows": "",
		"POST /api/v1/rules":       `{"action":"block","target_type":"domain","target":"x.example"}`,
		"DELETE /api/v1/alarms/81": "",
	} {
		m, p, _ := strings.Cut(call, " ")
		code, out := h.call(m, p, body)
		if code != 501 || !strings.Contains(out, `"code":"unsupported"`) || !strings.Contains(out, "firewalla cannot do this") {
			t.Errorf("%s = %d %s", call, code, out)
		}
	}
	for _, body := range []string{`{"name":"x"}`, `{"group":"Den"}`, `{"blocked":true}`} {
		if code, out := h.call("PATCH", "/api/v1/devices/02005e000001", body); code != 501 || !strings.Contains(out, "unsupported") {
			t.Errorf("PATCH %s = %d %s", body, code, out)
		}
	}
	if len(fh.wrote()) != 0 {
		t.Fatalf("something was sent: %v", fh.wrote())
	}

	// With changes switched off, a write says so rather than "unsupported".
	h, fh = v1Harness(t, backends.CapDevices, backends.CapRules, backends.CapGroups)
	fh.snap.ReadOnly = true
	for call, body := range map[string]string{
		"PATCH /api/v1/devices/02005e000001": `{"name":"x"}`, "DELETE /api/v1/rules/26": "", "PATCH /api/v1/rules/26": `{"paused":true}`,
	} {
		m, p, _ := strings.Cut(call, " ")
		if code, out := h.call(m, p, body); code != 403 || !strings.Contains(out, `"code":"read_only"`) {
			t.Errorf("%s while read-only = %d %s", call, code, out)
		}
	}
	// Reading still works.
	h.ok("GET", "/api/v1/devices", "", 200)
	h.ok("GET", "/api/v1/groups", "", 200)
}

func TestGroupsRulesAndAlarms(t *testing.T) {
	h, fh := v1Harness(t, v1Caps...)
	groups := list(t, h.ok("GET", "/api/v1/groups", "", 200), "groups")
	if len(groups) != 2 || groups[0]["name"] != "Smart Home" || groups[0]["devices"] != float64(1) || groups[1]["devices"] != float64(0) {
		t.Fatalf("groups = %v", groups)
	}

	rules := list(t, h.ok("GET", "/api/v1/rules", "", 200), "rules")
	if len(rules) != 2 || rules[0]["id"] != "26" || rules[0]["dns_only"] != true || rules[0]["created"] == nil ||
		rules[1]["scope_type"] != "device" || rules[1]["paused"] != true || rules[1]["created"] != nil {
		t.Fatalf("rules = %v", rules)
	}
	made := h.ok("POST", "/api/v1/rules", `{"action":"block","target_type":"domain","target":"ads.example","scope_type":"device","scope":"02005e000001"}`, 201)
	if made["id"] != "new" || made["target"] != "ads.example" {
		t.Fatalf("created = %v", made)
	}
	h.ok("PATCH", "/api/v1/rules/26", `{"paused":true}`, 200)
	h.ok("PATCH", "/api/v1/rules/26", `{"paused":false}`, 200)
	h.ok("DELETE", "/api/v1/rules/26", "", 200)
	want := []string{"create ads.example device:02005e000001", "pause 26", "resume 26", "delete 26"}
	if got := fh.wrote(); !reflect.DeepEqual(got, want) {
		t.Fatalf("writes = %v", got)
	}
	h.expect("PATCH", "/api/v1/rules/26", `{}`, 400)
	h.expect("PATCH", "/api/v1/rules/26", `nope`, 400)
	h.expect("POST", "/api/v1/rules", `nope`, 400)

	alarms := list(t, h.ok("GET", "/api/v1/alarms", "", 200), "alarms")
	if len(alarms) != 2 || alarms[0]["id"] != "81" || alarms[0]["mac"] != "02005e000001" || alarms[0]["time"] == nil || alarms[1]["time"] != nil || alarms[1]["domain"] != "example.org" {
		t.Fatalf("alarms = %v", alarms)
	}
	// The box is taken from the alarm when it is not given.
	h.ok("DELETE", "/api/v1/alarms/81", "", 200)
	h.ok("DELETE", "/api/v1/alarms/82?box=box-9", "", 200)
	h.ok("DELETE", "/api/v1/alarms/99", "", 200)
	if got := fh.wrote(); got[4] != "dismiss box-1/81" || got[5] != "dismiss box-9/82" || got[6] != "dismiss /99" {
		t.Fatalf("dismissals = %v", got[4:])
	}

	fh.err = backends.ErrNotFound
	for call, body := range map[string]string{
		"POST /api/v1/rules": `{"action":"block","target_type":"domain","target":"x.example"}`, "PATCH /api/v1/rules/26": `{"paused":true}`,
		"DELETE /api/v1/rules/26": "", "DELETE /api/v1/alarms/81": "",
	} {
		m, p, _ := strings.Cut(call, " ")
		if code, out := h.call(m, p, body); code != 404 || !strings.Contains(out, "not_found") {
			t.Errorf("%s = %d %s", call, code, out)
		}
	}
}

func TestFlowsArePagedAndBounded(t *testing.T) {
	h, fh := v1Harness(t, v1Caps...)
	out := h.ok("GET", "/api/v1/flows?device=02005e000001&limit=50&cursor=c1", "", 200)
	flows := list(t, out, "flows")
	if len(flows) != 1 || flows[0]["domain"] != "x.example" || flows[0]["mac"] != "02005e000001" || out["next"] != "c2" {
		t.Fatalf("flows = %v", out)
	}
	if q := fh.queries[0]; q.DeviceMAC != "02005e000001" || q.Limit != 50 || q.Cursor != "c1" {
		t.Fatalf("query = %+v", q)
	}
	h.ok("GET", "/api/v1/flows", "", 200)
	if q := fh.queries[1]; q.Limit != 100 || q.DeviceMAC != "" {
		t.Fatalf("default query = %+v", q)
	}
	for _, bad := range []string{"0", "501", "many"} {
		if code, body := h.call("GET", "/api/v1/flows?limit="+bad, ""); code != 400 || !strings.Contains(body, "1 to 500") {
			t.Errorf("limit=%s = %d %s", bad, code, body)
		}
	}
	fh.err = backends.ErrRateLimited
	if code, body := h.call("GET", "/api/v1/flows", ""); code != 429 || !strings.Contains(body, "rate_limited") {
		t.Fatalf("limited = %d %s", code, body)
	}
}

// The document is built from the routes, so this is mostly a check that
// the shapes it describes are the shapes served.
func TestTheOpenAPIDocumentMatchesWhatIsServed(t *testing.T) {
	h, _ := v1Harness(t, v1Caps...)
	h.srv.Version = "1.2.3"
	_, raw := h.call("GET", "/api/v1/openapi.json", "")
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["openapi"] != "3.1.0" || doc["info"].(map[string]any)["version"] != "1.2.3" {
		t.Fatalf("header = %v %v", doc["openapi"], doc["info"])
	}
	if v1OpenAPI("")["info"].(schema)["version"] != "dev" {
		t.Error("an unversioned build has no version in the document")
	}
	paths := doc["paths"].(map[string]any)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)

	ids := map[string]bool{}
	for _, rt := range v1Routes() {
		item, ok := paths[rt.path].(map[string]any)
		if !ok {
			t.Fatalf("%s is not in the document", rt.path)
		}
		op, ok := item[strings.ToLower(rt.method)].(map[string]any)
		if !ok {
			t.Fatalf("%s %s is not in the document", rt.method, rt.path)
		}
		id := op["operationId"].(string)
		if ids[id] {
			t.Errorf("operationId %q is used twice", id)
		}
		ids[id] = true
		for _, p := range rt.params {
			if p.in == "path" && !strings.Contains(rt.path, "{"+p.name+"}") {
				t.Errorf("%s: path parameter %q is not in the path", rt.path, p.name)
			}
		}
	}
	if !ids["getRouter"] || !ids["patchDevicesMac"] || !ids["deleteAlarmsId"] {
		t.Errorf("operation ids = %v", ids)
	}

	// Every $ref points at a schema that exists.
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if r, ok := x["$ref"].(string); ok {
				if _, ok := schemas[strings.TrimPrefix(r, "#/components/schemas/")]; !ok {
					t.Errorf("dangling reference %s", r)
				}
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(doc)

	// Every field a call returns is described.
	described := func(name string) map[string]any {
		return schemas[name].(map[string]any)["properties"].(map[string]any)
	}
	check := func(name string, got map[string]any) {
		t.Helper()
		for field := range got {
			if _, ok := described(name)[field]; !ok {
				t.Errorf("%s returns %q, which the document does not describe", name, field)
			}
		}
		for _, req := range schemas[name].(map[string]any)["required"].([]any) {
			if _, ok := got[req.(string)]; !ok {
				t.Errorf("%s says %q is always present, and it was not", name, req)
			}
		}
	}
	check("Router", h.ok("GET", "/api/v1/router", "", 200))
	check("Device", list(t, h.ok("GET", "/api/v1/devices", "", 200), "devices")[0])
	check("Group", list(t, h.ok("GET", "/api/v1/groups", "", 200), "groups")[0])
	for _, r := range list(t, h.ok("GET", "/api/v1/rules", "", 200), "rules") {
		check("Rule", r)
	}
	for _, a := range list(t, h.ok("GET", "/api/v1/alarms", "", 200), "alarms") {
		check("Alarm", a)
	}
	full, _ := json.Marshal(v1Flow{Time: time.Now(), MAC: "m", Device: "d", DeviceIP: "i", Domain: "x", RemoteIP: "r", Protocol: "tcp",
		Country: "US", Category: "c", FlowCount: 2})
	var flow map[string]any
	_ = json.Unmarshal(full, &flow)
	check("Flow", flow)
	check("Ok", h.ok("DELETE", "/api/v1/rules/26", "", 200))
	_, errBody := h.call("GET", "/api/v1/devices/nope", "")
	var e map[string]any
	_ = json.Unmarshal([]byte(errBody), &e)
	check("Error", e)
}
