// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"net/url"
	"testing"
	"time"

	"shepherd/internal/traffic"
	"shepherd/internal/watch"
)

func rfc(t time.Time) string { return url.QueryEscape(t.UTC().Format(time.RFC3339)) }

func TestTrafficStatusWithoutWatchMode(t *testing.T) {
	h := newHarness(t)
	out := h.ok("GET", "/api/traffic", "", 200)
	if out["enabled"] != false || out["measuring"] != false || out["devices_tracked"] != 0.0 {
		t.Fatalf("status = %v", out)
	}
	if ret := out["retention"].(map[string]any); ret["minute_hours"] != 48.0 || ret["hour_days"] != 90.0 {
		t.Fatalf("retention = %v", ret)
	}
	if len(out["devices"].([]any)) != 0 {
		t.Fatalf("devices = %v", out["devices"])
	}
}

func TestTrafficStatusReportsLiveRatesBusiestFirst(t *testing.T) {
	h := newHarness(t)
	phone := h.addDevice("02:00:5e:00:00:10", "192.0.2.10", "phone")
	tv := h.addDevice("02:00:5e:00:00:11", "192.0.2.11", "tv")
	g, err := h.reg.CreateGroup("Kids", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.reg.BulkAssignGroup([]string{tv}, g.ID); err != nil {
		t.Fatal(err)
	}
	fw := runningWatch()
	fw.snap.Stats = watch.RelayStats{BytesPerSecond: 100, RxBytesPerSecond: 5000, BytesRelayed: 1 << 20, BytesReceivedEst: 9 << 20}
	fw.snap.Devices = []watch.DeviceStatus{
		{DeviceID: phone, Name: "phone", State: watch.StateSteered, BytesPerSecond: 10, RxBytesPerSecond: 20, BytesRelayed: 1, BytesReceivedEst: 2},
		{DeviceID: tv, Name: "tv", State: watch.StateSteered, BytesPerSecond: 90, RxBytesPerSecond: 4980, BytesRelayed: 3, BytesReceivedEst: 4},
		{DeviceID: "x", Name: "idle", State: watch.StatePending},
	}
	h.srv.Watch = fw
	out := h.ok("GET", "/api/traffic", "", 200)
	if out["enabled"] != true || out["measuring"] != true {
		t.Fatalf("status = %v", out)
	}
	live := out["live"].(map[string]any)
	if live["down_bytes_per_second"] != 5000.0 || live["bytes_received_est"] != float64(9<<20) {
		t.Fatalf("live = %v", live)
	}
	devs := out["devices"].([]any)
	if len(devs) != 2 {
		t.Fatalf("devices = %v", devs)
	}
	first := devs[0].(map[string]any)
	if first["device_id"] != tv || first["down_bytes_per_second"] != 4980.0 || first["groups"].([]any)[0] != g.ID {
		t.Fatalf("busiest = %v", first)
	}
	if devs[1].(map[string]any)["groups"].([]any) == nil {
		t.Fatal("groups must be an empty list, not null")
	}
	// Killed: enabled but not measuring; the tie-break by total holds.
	fw.snap.Armed = false
	fw.snap.Devices[0].BytesPerSecond, fw.snap.Devices[0].RxBytesPerSecond = 90, 4980
	fw.snap.Devices[0].BytesReceivedEst = 100
	out = h.ok("GET", "/api/traffic", "", 200)
	if out["measuring"] != false || out["devices"].([]any)[0].(map[string]any)["device_id"] != phone {
		t.Fatalf("killed status = %v", out)
	}
}

func TestTrafficSeriesByScope(t *testing.T) {
	h := newHarness(t)
	phone := h.addDevice("02:00:5e:00:00:10", "192.0.2.10", "phone")
	tv := h.addDevice("02:00:5e:00:00:11", "192.0.2.11", "tv")
	g, _ := h.reg.CreateGroup("Kids", "")
	if _, err := h.reg.BulkAssignGroup([]string{tv}, g.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	h.srv.Traffic.Record(now.Add(-2*time.Minute), map[string]traffic.Delta{phone: {Up: 10, Down: 100}, tv: {Up: 20, Down: 200}})
	h.srv.Traffic.Record(now.Add(-time.Minute), map[string]traffic.Delta{phone: {Up: 1, Down: 1}})
	from, to := now.Add(-time.Hour), now

	q := "?from=" + rfc(from) + "&to=" + rfc(to)
	net := h.ok("GET", "/api/traffic/series"+q, "", 200)
	if net["scope"] != "network" || net["bucket"] != "minute" {
		t.Fatalf("network series = %v", net)
	}
	pts := net["points"].([]any)
	if len(pts) != 2 || pts[0].(map[string]any)["up"] != 30.0 || pts[0].(map[string]any)["down"] != 300.0 || pts[1].(map[string]any)["up"] != 1.0 {
		t.Fatalf("network points = %v", pts)
	}
	dev := h.ok("GET", "/api/traffic/series"+q+"&scope=device:"+tv, "", 200)
	pts = dev["points"].([]any)
	if len(pts) != 1 || pts[0].(map[string]any)["down"] != 200.0 {
		t.Fatalf("device points = %v", pts)
	}
	grp := h.ok("GET", "/api/traffic/series"+q+"&scope=group:"+g.ID+"&bucket=hour", "", 200)
	if grp["bucket"] != "hour" {
		t.Fatalf("explicit bucket = %v", grp["bucket"])
	}
	pts = grp["points"].([]any)
	if len(pts) != 1 || pts[0].(map[string]any)["up"] != 20.0 {
		t.Fatalf("group points = %v", pts)
	}
	// An empty group is an empty series, not an error; unknown scopes are.
	empty, _ := h.reg.CreateGroup("Nobody", "")
	if got := h.ok("GET", "/api/traffic/series"+q+"&scope=group:"+empty.ID, "", 200)["points"].([]any); len(got) != 0 {
		t.Fatalf("empty group points = %v", got)
	}
	h.expect("GET", "/api/traffic/series"+q+"&scope=device:nope", "", 404)
	h.expect("GET", "/api/traffic/series"+q+"&scope=group:nope", "", 404)
	h.expect("GET", "/api/traffic/series"+q+"&scope=planet", "", 404)
	h.expect("GET", "/api/traffic/series?from=yesterday", "", 400)
	// Default buckets follow the span.
	week := h.ok("GET", "/api/traffic/series?from="+rfc(now.Add(-7*24*time.Hour))+"&to="+rfc(now), "", 200)
	if week["bucket"] != "hour" {
		t.Fatalf("week bucket = %v", week["bucket"])
	}
	year := h.ok("GET", "/api/traffic/series?from="+rfc(now.Add(-365*24*time.Hour))+"&to="+rfc(now), "", 200)
	if year["bucket"] != "day" {
		t.Fatalf("year bucket = %v", year["bucket"])
	}
}

func TestTrafficTopRanksDevicesAndGroups(t *testing.T) {
	h := newHarness(t)
	phone := h.addDevice("02:00:5e:00:00:10", "192.0.2.10", "phone")
	tv := h.addDevice("02:00:5e:00:00:11", "192.0.2.11", "tv")
	kids, _ := h.reg.CreateGroup("Kids", "")
	if _, err := h.reg.BulkAssignGroup([]string{tv, phone}, kids.ID); err != nil {
		t.Fatal(err)
	}
	work, _ := h.reg.CreateGroup("Work", "")
	if _, err := h.reg.BulkAssignGroup([]string{phone}, work.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	h.srv.Traffic.Record(now.Add(-time.Minute), map[string]traffic.Delta{
		phone: {Up: 10, Down: 100}, tv: {Up: 20, Down: 2000}, "gone": {Up: 5, Down: 5},
	})
	q := "?from=" + rfc(now.Add(-time.Hour)) + "&to=" + rfc(now)
	out := h.ok("GET", "/api/traffic/top"+q, "", 200)
	if net := out["network"].(map[string]any); net["up"] != 35.0 || net["down"] != 2105.0 {
		t.Fatalf("network = %v", net)
	}
	devs := out["devices"].([]any)
	if len(devs) != 3 {
		t.Fatalf("devices = %v", devs)
	}
	if d := devs[0].(map[string]any); d["device_id"] != tv || d["name"] != "tv" || d["down"] != 2000.0 {
		t.Fatalf("top device = %v", d)
	}
	if d := devs[2].(map[string]any); d["device_id"] != "gone" || d["name"] != "" || len(d["groups"].([]any)) != 0 {
		t.Fatalf("forgotten device = %v", d)
	}
	groups := out["groups"].([]any)
	if len(groups) != 2 || groups[0].(map[string]any)["name"] != "Kids" || groups[0].(map[string]any)["down"] != 2100.0 || groups[1].(map[string]any)["up"] != 10.0 {
		t.Fatalf("groups = %v", groups)
	}
	if got := h.ok("GET", "/api/traffic/top"+q+"&limit=1", "", 200)["devices"].([]any); len(got) != 1 {
		t.Fatalf("limit=1 gave %d devices", len(got))
	}
	h.expect("GET", "/api/traffic/top"+q+"&limit=-1", "", 400)
	h.expect("GET", "/api/traffic/top"+q+"&limit=x", "", 400)
	h.expect("GET", "/api/traffic/top?to=never", "", 400)
	// Nothing in range: empty lists, zero total.
	old := h.ok("GET", "/api/traffic/top?from="+rfc(now.Add(-48*time.Hour))+"&to="+rfc(now.Add(-24*time.Hour)), "", 200)
	if len(old["devices"].([]any)) != 0 || len(old["groups"].([]any)) != 0 {
		t.Fatalf("out of range = %v", old)
	}
}
