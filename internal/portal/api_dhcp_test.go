// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shepherd/internal/devices"
	"shepherd/internal/dhcp"
)

// A real *dhcp.Server with the mode off and no socket: that is the shape the
// portal actually sees on nearly every install, and it is the shape in which
// the whole arrangement has to be reviewable before it is switched on.
func dhcpHarness(t *testing.T, mode dhcp.Mode, route bool) (*harness, *dhcp.Server) {
	t.Helper()
	dir := t.TempDir()
	state, err := dhcp.OpenState(filepath.Join(dir, "dhcp.json"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	set := dhcp.Settings{
		Subnet:   netip.MustParsePrefix("192.0.2.0/24"),
		ServerIP: netip.MustParseAddr("192.0.2.20"),
		Gateway:  netip.MustParseAddr("192.0.2.1"),
		Pool:     dhcp.Pool{Start: netip.MustParseAddr("192.0.2.100"), End: netip.MustParseAddr("192.0.2.110")},
		DNS:      []netip.Addr{netip.MustParseAddr("192.0.2.20")},
	}
	srv := &dhcp.Server{
		Mode: func() dhcp.Mode { return mode }, Settings: func() dhcp.Settings { return set },
		Route: func() bool { return route }, RouteConsoles: func() bool { return false },
		Own: func() dhcp.Own {
			return dhcp.Own{IPs: []netip.Addr{set.ServerIP}, Gateway: set.Gateway}
		},
		Store: dhcp.NewLeases(), State: state, Peers: dhcp.NewPeers(),
		LeasePath: filepath.Join(dir, "dhcp-leases.json"),
		Log:       log.New(&strings.Builder{}, "", 0),
	}
	if err := srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	h := newHarnessWith(t, func(d *Deps) { d.DHCP = srv })
	return h, srv
}

func TestDHCPScreenAnswersWithEverythingItNeedsWhenTheModeIsOff(t *testing.T) {
	h, _ := dhcpHarness(t, dhcp.ModeOff, false)
	m := h.ok("GET", "/api/dhcp", "", 200)

	if m["available"] != true {
		t.Fatalf("available = %v", m["available"])
	}
	status := m["status"].(map[string]any)
	if status["mode"] != "off" || status["serving"] != false || status["routing"] != false {
		t.Errorf("status = %+v", status)
	}
	// The screen must have the addressing even with the mode off, so the
	// reservation form can refuse an address inside the pool.
	set := m["settings"].(map[string]any)
	if set["subnet"] != "192.0.2.0/24" || set["pool_start"] != "192.0.2.100" {
		t.Errorf("settings = %+v", set)
	}
	if m["confirm_phrase"] == "" {
		t.Error("the screen needs the phrase to ask for")
	}
	if _, ok := m["leases"].([]any); !ok {
		t.Errorf("leases must be a list even when empty: %T", m["leases"])
	}
	if _, ok := m["reservations"].([]any); !ok {
		t.Errorf("reservations must be a list even when empty: %T", m["reservations"])
	}
}

func TestDHCPScreenSaysSoWhenTheModeIsNotWiredIn(t *testing.T) {
	h := newHarness(t)
	m := h.ok("GET", "/api/dhcp", "", 200)
	if m["available"] != false {
		t.Fatalf("available = %v, want false", m["available"])
	}
	if !strings.Contains(m["reason"].(string), "shepherd.toml") {
		t.Errorf("reason = %q, should say where to turn it on", m["reason"])
	}
	// The shape must still be complete so the screen renders rather than
	// failing on a missing field.
	if _, ok := m["status"].(map[string]any); !ok {
		t.Error("a status is still expected")
	}
	for _, path := range []string{"/api/dhcp/confirm", "/api/dhcp/kill", "/api/dhcp/rearm", "/api/dhcp/peers/forget"} {
		h.expect("POST", path, `{}`, 404)
	}
	h.expect("PUT", "/api/dhcp/reservations", `{"mac":"02:00:5e:01:02:03"}`, 404)
	h.expect("DELETE", "/api/dhcp/reservations/02:00:5e:01:02:03", "", 404)
}

// The confirmation is a typed phrase because the mistake it guards against is
// one somebody makes at midnight and discovers at breakfast.
func TestConfirmingNeedsThePhraseAndWithdrawingDoesNot(t *testing.T) {
	h, srv := dhcpHarness(t, dhcp.ModeServe, false)

	h.expect("POST", "/api/dhcp/confirm", `{"confirm":true}`, 400)
	h.expect("POST", "/api/dhcp/confirm", `{"confirm":true,"phrase":"yes please"}`, 400)
	if srv.Status().Confirmed {
		t.Fatal("nothing should have been confirmed")
	}

	m := h.ok("POST", "/api/dhcp/confirm", `{"confirm":true,"phrase":"Serve DHCP"}`, 200)
	if m["status"].(map[string]any)["confirmed"] != true {
		t.Fatalf("status = %+v", m["status"])
	}

	m = h.ok("POST", "/api/dhcp/confirm", `{"confirm":false}`, 200)
	if m["status"].(map[string]any)["confirmed"] != false {
		t.Error("withdrawing needs no phrase: stopping is always allowed to be easy")
	}
}

func TestTheKillSwitchStopsRoutingAndCanBeReArmed(t *testing.T) {
	h, srv := dhcpHarness(t, dhcp.ModeServe, true)
	if err := srv.Confirm(context.Background(), true); err != nil {
		t.Fatal(err)
	}

	m := h.ok("POST", "/api/dhcp/kill", `{"reason":"the TV stopped working"}`, 200)
	status := m["status"].(map[string]any)
	if status["disarmed"] != true || status["disarmed_reason"] != "the TV stopped working" {
		t.Fatalf("status = %+v", status)
	}
	// Leasing carries on: that is the difference between the kill switch
	// and an outage.
	if status["routing"] == true {
		t.Error("routing must have stopped")
	}

	m = h.ok("POST", "/api/dhcp/rearm", `{}`, 200)
	if m["status"].(map[string]any)["disarmed"] != false {
		t.Error("re-arming should clear it")
	}

	// A kill with no body at all is allowed: the button sends none.
	h.expect("POST", "/api/dhcp/kill", "", 200)
	h.expect("POST", "/api/dhcp/kill", `{"reason":"`+strings.Repeat("x", 201)+`"}`, 400)
	h.expect("POST", "/api/dhcp/kill", "{\"reason\":\"a\\u0007b\"}", 400)
}

func TestForgettingPeersIsWhatHappensAfterTheRouterIsTurnedOff(t *testing.T) {
	h, srv := dhcpHarness(t, dhcp.ModeServe, false)
	srv.Peers.Saw(netip.MustParseAddr("192.0.2.2"), time.Now())
	if err := srv.Confirm(context.Background(), true); err != nil {
		t.Fatal(err)
	}

	m := h.ok("GET", "/api/dhcp", "", 200)
	peers := m["status"].(map[string]any)["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("peers = %+v", peers)
	}
	m = h.ok("POST", "/api/dhcp/peers/forget", `{}`, 200)
	if got := m["status"].(map[string]any)["peers"].([]any); len(got) != 0 {
		t.Errorf("peers = %+v, want cleared", got)
	}
}

func TestReservationsCanBeAddedEditedAndRemoved(t *testing.T) {
	h, _ := dhcpHarness(t, dhcp.ModeOff, false)

	m := h.ok("PUT", "/api/dhcp/reservations", `{"mac":"02-00-5E-01-02-03","ip":"192.0.2.50","hostname":"printer","note":"by the door"}`, 200)
	res := m["reservations"].([]any)
	if len(res) != 1 {
		t.Fatalf("reservations = %+v", res)
	}
	one := res[0].(map[string]any)
	if one["mac"] != "02:00:5e:01:02:03" || one["ip"] != "192.0.2.50" || one["hostname"] != "printer" {
		t.Errorf("reservation = %+v", one)
	}

	// Editing is the same call.
	m = h.ok("PUT", "/api/dhcp/reservations", `{"mac":"02:00:5e:01:02:03","ip":"192.0.2.51","hostname":"printer"}`, 200)
	if m["reservations"].([]any)[0].(map[string]any)["ip"] != "192.0.2.51" {
		t.Errorf("the edit did not take: %+v", m["reservations"])
	}

	// A name-only reservation is allowed.
	h.ok("PUT", "/api/dhcp/reservations", `{"mac":"02:00:5e:01:02:04","hostname":"doorbell"}`, 200)

	m = h.ok("DELETE", "/api/dhcp/reservations/02:00:5e:01:02:03", "", 200)
	if len(m["reservations"].([]any)) != 1 {
		t.Errorf("reservations after the delete = %+v", m["reservations"])
	}
	h.expect("DELETE", "/api/dhcp/reservations/02:00:5e:01:02:03", "", 404)
	h.expect("DELETE", "/api/dhcp/reservations/nonsense", "", 400)
}

// The rule that matters: an address inside the pool could be handed out
// twice. The server is the authority on it, and it says which rule was
// broken rather than "bad request".
func TestReservationValidationExplainsEachRefusal(t *testing.T) {
	h, _ := dhcpHarness(t, dhcp.ModeOff, false)
	cases := map[string]string{
		`{"mac":""}`:         "MAC",
		`{"mac":"nonsense"}`: "MAC",
		`{"mac":"02:00:5e:01:02:03","ip":"198.51.100.5"}`:                       "LAN",
		`{"mac":"02:00:5e:01:02:03","ip":"not an address"}`:                     "IPv4",
		`{"mac":"02:00:5e:01:02:03","hostname":"not a name!"}`:                  "hostname",
		`{"mac":"02:00:5e:01:02:03","hostname":"a\u0007b"}`:                     "plain text",
		`{"mac":"02:00:5e:01:02:03","note":"` + strings.Repeat("x", 201) + `"}`: "note",
	}
	for body, want := range cases {
		code, out := h.call("PUT", "/api/dhcp/reservations", body)
		if code != 400 {
			t.Errorf("PUT %s = %d, want 400", body, code)
			continue
		}
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("PUT %s said %q, should mention %q", body, strings.TrimSpace(out), want)
		}
	}

	// An address inside the dynamic pool is the ordinary case -- pinning a
	// device to the address it already holds -- and the allocator takes a
	// reserved address out of the pool for everyone else.
	m := h.ok("PUT", "/api/dhcp/reservations", `{"mac":"02:00:5e:01:02:09","ip":"192.0.2.105"}`, 200)
	if len(m["reservations"].([]any)) != 1 {
		t.Errorf("reservations = %+v", m["reservations"])
	}

	// Two reservations cannot hold one address.
	h.ok("PUT", "/api/dhcp/reservations", `{"mac":"02:00:5e:01:02:03","ip":"192.0.2.50"}`, 200)
	code, out := h.call("PUT", "/api/dhcp/reservations", `{"mac":"02:00:5e:01:02:04","ip":"192.0.2.50"}`)
	if code != 400 || !strings.Contains(out, "already reserved") {
		t.Errorf("PUT a clashing address = %d %q", code, strings.TrimSpace(out))
	}
}

// The lease list is what makes watching before serving worth doing, so it has
// to carry where each lease came from and why a device is not routed.
func TestTheLeaseListSaysWhereEachLeaseCameFromAndWhyItIsNotRouted(t *testing.T) {
	h, srv := dhcpHarness(t, dhcp.ModeObserve, false)
	id := h.addDevice("02:00:5e:01:02:03", "192.0.2.100", "printer")
	if err := h.reg.SetType(id, string(devices.TypeGameConsole)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	srv.Store.Put(dhcp.Lease{MAC: "02:00:5e:01:02:03", IP: netip.MustParseAddr("192.0.2.100"),
		Hostname: "printer", Router: netip.MustParseAddr("192.0.2.1"), Origin: dhcp.OriginObserved,
		Allocated: now, Expires: now.Add(time.Hour), DeviceID: id})
	srv.Store.Put(dhcp.Lease{MAC: "02:00:5e:01:02:04", IP: netip.MustParseAddr("192.0.2.101"),
		Router: netip.MustParseAddr("192.0.2.20"), Origin: dhcp.OriginShepherd,
		Allocated: now, Expires: now.Add(-time.Minute)})

	m := h.ok("GET", "/api/dhcp", "", 200)
	leases := m["leases"].([]any)
	if len(leases) != 2 {
		t.Fatalf("leases = %+v", leases)
	}
	byMAC := map[string]map[string]any{}
	for _, l := range leases {
		one := l.(map[string]any)
		byMAC[one["mac"].(string)] = one
	}
	observed := byMAC["02:00:5e:01:02:03"]
	if observed["origin"] != "observed" {
		t.Errorf("origin = %v, want the router's own lease marked", observed["origin"])
	}
	if observed["routed"] != false || observed["reason"] == "" {
		t.Errorf("a lease that is not routed should say why: %+v", observed)
	}
	if observed["device_id"] != id {
		t.Errorf("device_id = %v, want the registry's device so the two lists are one list", observed["device_id"])
	}
	routed := byMAC["02:00:5e:01:02:04"]
	if routed["routed"] != true || routed["expired"] != true {
		t.Errorf("an expired routed lease = %+v; expired leases are shown, not hidden", routed)
	}
}

func TestADevicesRoutingSwitchIsReachableFromTheDevicesAPI(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:5e:01:02:03", "192.0.2.100", "")

	m := h.ok("GET", "/api/devices/"+id, "", 200)
	if m["route"] != "auto" {
		t.Errorf("route = %v, want auto by default", m["route"])
	}

	m = h.ok("PATCH", "/api/devices/"+id, `{"route":"off"}`, 200)
	if m["route"] != "off" {
		t.Errorf("route = %v after the patch", m["route"])
	}
	h.expect("PATCH", "/api/devices/"+id, `{"route":"sometimes"}`, 400)

	m = h.ok("POST", "/api/devices/bulk", `{"op":"set_route","ids":["`+id+`"],"route":"on"}`, 200)
	if m == nil {
		t.Fatal("the bulk call should answer")
	}
	one := h.ok("GET", "/api/devices/"+id, "", 200)
	if one["route"] != "on" {
		t.Errorf("route = %v after the bulk call", one["route"])
	}
	h.expect("POST", "/api/devices/bulk", `{"op":"set_route","ids":["`+id+`"],"route":"maybe"}`, 400)
	h.expect("POST", "/api/devices/bulk", `{"op":"set_route","ids":["`+id+`"]}`, 400)
}

// failingDHCP is a DHCPService whose every write fails, which is how the
// portal's "it stopped either way, but recording it did not" answers get
// exercised. Those messages matter: the operator has to know which half of a
// kill switch worked.
type failingDHCP struct {
	status    dhcp.Status
	leases    []dhcp.LeaseView
	res       []dhcp.Reservation
	conflicts []dhcp.Conflict
	err       error
}

func (f *failingDHCP) Status() dhcp.Status                   { return f.status }
func (f *failingDHCP) SettingsView() dhcp.SettingsView       { return dhcp.SettingsView{} }
func (f *failingDHCP) Leases() []dhcp.LeaseView              { return f.leases }
func (f *failingDHCP) Reservations() []dhcp.Reservation      { return f.res }
func (f *failingDHCP) SetReservation(dhcp.Reservation) error { return f.err }
func (f *failingDHCP) DeleteReservation(string) (bool, error) {
	return false, f.err
}
func (f *failingDHCP) Confirm(context.Context, bool) error   { return f.err }
func (f *failingDHCP) Unroute(context.Context, string) error { return f.err }
func (f *failingDHCP) Rearm(context.Context) error           { return f.err }
func (f *failingDHCP) ForgetPeers(context.Context)           {}
func (f *failingDHCP) RangeView() dhcp.RangeView             { return dhcp.RangeView{} }
func (f *failingDHCP) Conflicts() []dhcp.Conflict            { return f.conflicts }
func (f *failingDHCP) SetRange(context.Context, dhcp.Range) error {
	return f.err
}
func (f *failingDHCP) Reservation(mac string) (dhcp.Reservation, bool) {
	for _, r := range f.res {
		if r.MAC == mac {
			return r, true
		}
	}
	return dhcp.Reservation{}, false
}

func TestAFailedWriteIsReportedRatherThanLookingLikeSuccess(t *testing.T) {
	svc := &failingDHCP{err: errors.New("disk full")}
	h := newHarnessWith(t, func(d *Deps) { d.DHCP = svc })

	h.expect("POST", "/api/dhcp/confirm", `{"confirm":true,"phrase":"serve dhcp"}`, 500)
	h.expect("POST", "/api/dhcp/kill", `{}`, 500)
	h.expect("POST", "/api/dhcp/rearm", `{}`, 500)
	h.expect("PUT", "/api/dhcp/reservations", `{"mac":"02:00:5e:01:02:03"}`, 500)

	// A delete that reports no error and nothing removed is a 404, not a 500.
	svc.err = nil
	h.expect("DELETE", "/api/dhcp/reservations/02:00:5e:01:02:03", "", 404)
	svc.err = errors.New("disk full")
	h.expect("DELETE", "/api/dhcp/reservations/02:00:5e:01:02:03", "", 500)
}

func TestTheScreenShapeIsCompleteWhenEverythingIsPopulated(t *testing.T) {
	now := time.Now()
	svc := &failingDHCP{
		status: dhcp.Status{Mode: "serve", Serving: true, Routing: true, RoutedCount: 1,
			Peers: []dhcp.Peer{{Server: netip.MustParseAddr("192.0.2.2"), First: now, Last: now, Count: 3}}},
		leases: []dhcp.LeaseView{{Lease: dhcp.Lease{MAC: "02:00:5e:01:02:03"}, Routed: true}},
		res:    []dhcp.Reservation{{MAC: "02:00:5e:01:02:03"}},
	}
	h := newHarnessWith(t, func(d *Deps) { d.DHCP = svc })
	m := h.ok("GET", "/api/dhcp", "", 200)
	if len(m["leases"].([]any)) != 1 || len(m["reservations"].([]any)) != 1 {
		t.Fatalf("leases/reservations = %+v / %+v", m["leases"], m["reservations"])
	}
	if len(m["status"].(map[string]any)["peers"].([]any)) != 1 {
		t.Errorf("peers = %+v", m["status"])
	}
}

// Malformed JSON must be a bad request rather than a panic, on every one of
// these: they are reachable from a browser with a stale script.
func TestMalformedBodiesAreRefused(t *testing.T) {
	h, _ := dhcpHarness(t, dhcp.ModeOff, false)
	for _, path := range []string{"/api/dhcp/confirm", "/api/dhcp/kill"} {
		h.expect("POST", path, `{nope`, 400)
	}
	h.expect("PUT", "/api/dhcp/reservations", `{nope`, 400)
	h.expect("PUT", "/api/dhcp/reservations", `{"mac":"02:00:5e:01:02:03","unknown":1}`, 400)
}

// A range that does not fit yet is stored anyway and the conflicts come back
// with it: the whole point is being told what to change on the router.
func TestTheRangeEndpointStoresAChoiceAndReportsWhatBlocksIt(t *testing.T) {
	h, srv := dhcpHarness(t, dhcp.ModeServe, false)
	srv.Observe = func() dhcp.Observed {
		return dhcp.Observed{
			HostAddrs: []netip.Addr{netip.MustParseAddr("192.0.2.20")},
			Gateway:   netip.MustParseAddr("192.0.2.1"),
			Holders:   []dhcp.Holder{{IP: netip.MustParseAddr("192.0.2.31"), Name: "Garage Camera"}},
		}
	}
	body := `{"subnet":"192.168.1.0/24","server_ip":"192.168.1.20","gateway":"192.168.1.1","pool_start":"192.168.1.100","pool_end":"192.168.1.200"}`
	m := h.ok("PUT", "/api/dhcp/range", body, 200)

	rng := m["range"].(map[string]any)
	if rng["chosen"] != true || rng["subnet"] != "192.168.1.0/24" {
		t.Fatalf("range = %+v", rng)
	}
	if rng["current"].(map[string]any)["subnet"] != "192.0.2.0/24" {
		t.Errorf("the screen should show what it would fall back to: %+v", rng["current"])
	}
	conflicts := m["conflicts"].([]any)
	if len(conflicts) == 0 {
		t.Fatal("a range nothing on this network uses must report conflicts")
	}
	var blocking int
	for _, c := range conflicts {
		if c.(map[string]any)["severity"] == "blocking" {
			blocking++
		}
	}
	if blocking == 0 {
		t.Errorf("at least one must be blocking: %+v", conflicts)
	}
	// And it stops serving while that stands.
	if m["status"].(map[string]any)["serving"] == true {
		t.Error("serving must stop while the chosen range does not fit")
	}
	// The addressing shown is the chosen one, so the form and the
	// reservation rules follow it.
	if m["settings"].(map[string]any)["subnet"] != "192.168.1.0/24" {
		t.Errorf("settings = %+v", m["settings"])
	}

	// Clearing it puts the interface back in charge.
	m = h.ok("PUT", "/api/dhcp/range", `{"subnet":""}`, 200)
	if m["range"].(map[string]any)["chosen"] != false {
		t.Errorf("range = %+v", m["range"])
	}
	if len(m["conflicts"].([]any)) != 0 {
		t.Errorf("with no chosen range there is nothing to compare: %+v", m["conflicts"])
	}
}

func TestTheRangeEndpointExplainsEachRefusal(t *testing.T) {
	h, _ := dhcpHarness(t, dhcp.ModeOff, false)
	full := func(over map[string]string) string {
		b := map[string]string{"subnet": "192.168.1.0/24", "server_ip": "192.168.1.20",
			"gateway": "192.168.1.1", "pool_start": "192.168.1.100", "pool_end": "192.168.1.200"}
		for k, v := range over {
			b[k] = v
		}
		out, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	cases := map[string]string{
		full(map[string]string{"subnet": "192.168.1.0"}):      "CIDR",
		full(map[string]string{"server_ip": ""}):              "required",
		full(map[string]string{"gateway": "nope"}):            "IPv4",
		full(map[string]string{"server_ip": "10.0.0.2"}):      "not inside",
		full(map[string]string{"subnet": "203.0.113.0/24"}):   "private",
		full(map[string]string{"server_ip": "192.168.1.150"}): "inside the pool",
	}
	for body, want := range cases {
		code, out := h.call("PUT", "/api/dhcp/range", body)
		if code != 400 {
			t.Errorf("PUT %s = %d, want 400", body, code)
			continue
		}
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("PUT %s said %q, should mention %q", body, strings.TrimSpace(out), want)
		}
	}
	h.expect("PUT", "/api/dhcp/range", `{nope`, 400)
}

// Toggling any device's address as reserved, from the Devices screen, is
// what the per-device field is for.
func TestEveryDeviceCarriesItsReservationState(t *testing.T) {
	h, srv := dhcpHarness(t, dhcp.ModeServe, false)
	id := h.addDevice("02:00:5e:01:02:03", "192.0.2.105", "tablet")

	one := h.ok("GET", "/api/devices/"+id, "", 200)
	res, ok := one["reserved"].(map[string]any)
	if !ok {
		t.Fatalf("a device should carry its reservation state: %+v", one)
	}
	if res["on"] != false {
		t.Errorf("it has no reservation yet: %+v", res)
	}
	if res["candidate"] != "192.0.2.105" {
		t.Errorf("candidate = %v, want the address it holds now", res["candidate"])
	}
	if res["in_pool"] != true {
		t.Errorf("in_pool = %v; a dynamic address is a pool address, and the screen should say so", res["in_pool"])
	}
	if res["mac"] != "02:00:5e:01:02:03" {
		t.Errorf("mac = %v, want the key the reservation is stored under", res["mac"])
	}

	// Pinning it is the ordinary PUT, with the address it already holds.
	h.ok("PUT", "/api/dhcp/reservations", `{"mac":"02:00:5e:01:02:03","ip":"192.0.2.105"}`, 200)
	one = h.ok("GET", "/api/devices/"+id, "", 200)
	res = one["reserved"].(map[string]any)
	if res["on"] != true || res["ip"] != "192.0.2.105" {
		t.Fatalf("reserved = %+v", res)
	}

	// And the list carries it too, so the screen does not need a call per
	// device.
	list := h.ok("GET", "/api/devices", "", 200)
	devs := list["devices"].([]any)
	var found bool
	for _, d := range devs {
		dm := d.(map[string]any)
		if dm["id"] == id {
			found = dm["reserved"].(map[string]any)["on"] == true
		}
	}
	if !found {
		t.Error("the device list should carry each device's reservation")
	}

	// Unpinning is the DELETE.
	h.ok("DELETE", "/api/dhcp/reservations/02:00:5e:01:02:03", "", 200)
	one = h.ok("GET", "/api/devices/"+id, "", 200)
	if one["reserved"].(map[string]any)["on"] != false {
		t.Error("it should be unpinned")
	}
	_ = srv
}

func TestADeviceWithNoHardwareAddressIsOfferedNoReservedSwitch(t *testing.T) {
	h, _ := dhcpHarness(t, dhcp.ModeObserve, false)
	// A device known only by address -- a container, or one seen only
	// through DNS -- cannot be reserved: the reservation is keyed on
	// hardware, and offering a switch that cannot work is worse than none.
	id := h.reg.Observe(devices.Observation{Source: devices.SourceDNS, IP: "192.0.2.77", Time: time.Now()})
	if id == "" {
		t.Fatal("the observation should have created a device")
	}
	one := h.ok("GET", "/api/devices/"+id, "", 200)
	if _, ok := one["reserved"]; ok {
		t.Errorf("reserved = %+v, want the field left off", one["reserved"])
	}
}

func TestWithoutDHCPModeTheDevicesScreenShowsNoReservedSwitch(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:5e:01:02:03", "192.0.2.105", "")
	one := h.ok("GET", "/api/devices/"+id, "", 200)
	if _, ok := one["reserved"]; ok {
		t.Error("with no DHCP mode there is nothing true to say about a reservation")
	}
}

// DHCP mode is alpha, so it is something somebody goes looking for. With the
// mode off, the Devices screen offers no reserved switch even though the
// service is wired in and the reservation would store perfectly well: a
// switch for an alpha feature does not belong on a screen somebody was
// already on. The DHCP screen itself stays fully usable, because getting
// there is the going and looking.
func TestWithTheModeOffTheDevicesScreenStillOffersNothing(t *testing.T) {
	h, srv := dhcpHarness(t, dhcp.ModeOff, false)
	id := h.addDevice("02:00:5e:01:02:03", "192.0.2.105", "")
	one := h.ok("GET", "/api/devices/"+id, "", 200)
	if _, ok := one["reserved"]; ok {
		t.Errorf("reserved = %+v, want the field left off while the mode is off", one["reserved"])
	}
	list := h.ok("GET", "/api/devices", "", 200)
	for _, d := range list["devices"].([]any) {
		if _, ok := d.(map[string]any)["reserved"]; ok {
			t.Error("and the list should not carry it either")
		}
	}
	// But the DHCP screen can still store one, which is the whole point of
	// being able to prepare the arrangement before switching it on.
	if err := srv.SetReservation(dhcp.Reservation{MAC: "02:00:5e:01:02:03", IP: netip.MustParseAddr("192.0.2.50")}); err != nil {
		t.Errorf("SetReservation with the mode off: %v", err)
	}
	m := h.ok("GET", "/api/dhcp", "", 200)
	if len(m["reservations"].([]any)) != 1 {
		t.Errorf("reservations = %+v", m["reservations"])
	}
}
