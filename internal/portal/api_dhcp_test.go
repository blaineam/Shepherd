// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
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
		`{"mac":"02:00:5e:01:02:03","ip":"192.0.2.105"}`:                        "pool",
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
	status dhcp.Status
	leases []dhcp.LeaseView
	res    []dhcp.Reservation
	err    error
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
