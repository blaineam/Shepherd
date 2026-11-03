// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestModeParsesEverySpellingAndRefusesTheRest(t *testing.T) {
	cases := map[string]Mode{
		"": ModeOff, "off": ModeOff, "false": ModeOff, "no": ModeOff,
		"observe": ModeObserve, "watch": ModeObserve, "listen": ModeObserve,
		"serve": ModeServe, "server": ModeServe, "on": ModeServe, "true": ModeServe, "yes": ModeServe,
		" SERVE ": ModeServe,
	}
	for in, want := range cases {
		got, ok := ParseMode(in)
		if !ok || got != want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q, true", in, got, ok, want)
		}
	}
	if _, ok := ParseMode("maybe"); ok {
		t.Error("an unknown mode must be refused rather than guessed: this one decides whether a house has DHCP")
	}
	if ModeOff.Listens() || !ModeObserve.Listens() || !ModeServe.Listens() {
		t.Error("Listens: off opens no socket, the other two do")
	}
	if Mode("").String() != "off" || ModeServe.String() != "serve" {
		t.Error("String should spell the mode the way the configuration file does")
	}
}

func TestReservationValidateNormalizesAndRefusesTheWaysToBreakAddressing(t *testing.T) {
	pool := Pool{Start: poolStart, End: poolEnd}

	r := Reservation{MAC: "02-00-5E-01-02-03", Hostname: " printer ", IP: netip.MustParseAddr("192.0.2.50")}
	if err := r.Validate(lanPrefix, pool); err != nil {
		t.Fatalf("a static address outside the pool is fine: %v", err)
	}
	if r.MAC != macA || r.Hostname != "printer" {
		t.Errorf("Validate should normalize in place, got %+v", r)
	}

	// A reservation with no address is still worth having: it holds a name.
	nameOnly := Reservation{MAC: macA, Hostname: "printer"}
	if err := nameOnly.Validate(lanPrefix, pool); err != nil {
		t.Errorf("a name-only reservation is valid: %v", err)
	}

	bad := []struct {
		name string
		r    Reservation
		want string
	}{
		{"no MAC", Reservation{}, "MAC address is required"},
		{"nonsense MAC", Reservation{MAC: "zz"}, "MAC address is required"},
		{"inside the pool", Reservation{MAC: macA, IP: netip.MustParseAddr("192.0.2.105")}, "inside the dynamic pool"},
		{"outside the LAN", Reservation{MAC: macA, IP: netip.MustParseAddr("198.51.100.5")}, "not inside the LAN"},
		{"IPv6", Reservation{MAC: macA, IP: netip.MustParseAddr("2001:db8::1")}, "must be IPv4"},
		{"long hostname", Reservation{MAC: macA, Hostname: strings.Repeat("a", 64)}, "limited to 63"},
		{"odd hostname", Reservation{MAC: macA, Hostname: "not a name!"}, "letters, digits and hyphens"},
		{"long note", Reservation{MAC: macA, Note: strings.Repeat("x", 201)}, "limited to 200"},
	}
	for _, c := range bad {
		err := c.r.Validate(lanPrefix, pool)
		if err == nil {
			t.Errorf("%s: want an error", c.name)
			continue
		}
		if !errors.Is(err, ErrReservation) {
			t.Errorf("%s: error does not wrap ErrReservation: %v", c.name, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q should mention %q", c.name, err, c.want)
		}
	}
}

func TestValidHostnameRejectsALeadingOrTrailingHyphen(t *testing.T) {
	for _, ok := range []string{"a", "a-b", "nas1", "A-B2"} {
		if !validHostname(ok) {
			t.Errorf("%q should be a valid hostname", ok)
		}
	}
	for _, bad := range []string{"-a", "a-", "a.b", "a_b", "a b"} {
		if validHostname(bad) {
			t.Errorf("%q should not be a valid hostname", bad)
		}
	}
}

func openState(t *testing.T) (*State, *clock, string) {
	t.Helper()
	c := newClock()
	path := filepath.Join(t.TempDir(), "dhcp.json")
	s, err := OpenState(path, c.now)
	if err != nil {
		t.Fatalf("OpenState: %v", err)
	}
	return s, c, path
}

func TestStateStoresReservationsAcrossAReopen(t *testing.T) {
	s, _, path := openState(t)
	pool := Pool{Start: poolStart, End: poolEnd}
	if err := s.SetReservation(Reservation{MAC: "02-00-5E-01-02-03", IP: netip.MustParseAddr("192.0.2.50"), Hostname: "printer"}, lanPrefix, pool); err != nil {
		t.Fatalf("SetReservation: %v", err)
	}
	back, err := OpenState(path, nil)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	got, ok := back.Reservation("02:00:5E:01:02:03")
	if !ok {
		t.Fatal("the reservation did not survive a reopen")
	}
	if got.IP.String() != "192.0.2.50" || got.Hostname != "printer" {
		t.Errorf("reopened reservation = %+v", got)
	}
	if got.Created.IsZero() || got.Updated.IsZero() {
		t.Error("a reservation records when it was made")
	}
}

func TestSetReservationReplacesInPlaceAndKeepsTheCreationTime(t *testing.T) {
	s, c, _ := openState(t)
	pool := Pool{Start: poolStart, End: poolEnd}
	if err := s.SetReservation(Reservation{MAC: macA, Hostname: "first"}, lanPrefix, pool); err != nil {
		t.Fatal(err)
	}
	created, _ := s.Reservation(macA)
	c.advance(time.Hour)
	if err := s.SetReservation(Reservation{MAC: macA, Hostname: "second"}, lanPrefix, pool); err != nil {
		t.Fatal(err)
	}
	if len(s.Reservations()) != 1 {
		t.Fatalf("a second reservation for the same MAC must replace the first, got %d", len(s.Reservations()))
	}
	got, _ := s.Reservation(macA)
	if got.Hostname != "second" {
		t.Errorf("Hostname = %q, want the new one", got.Hostname)
	}
	if !got.Created.Equal(created.Created) {
		t.Error("replacing a reservation keeps the time it was first made")
	}
}

func TestSetReservationRefusesAnAddressAnotherReservationHolds(t *testing.T) {
	s, _, _ := openState(t)
	pool := Pool{Start: poolStart, End: poolEnd}
	ip := netip.MustParseAddr("192.0.2.50")
	if err := s.SetReservation(Reservation{MAC: macA, IP: ip}, lanPrefix, pool); err != nil {
		t.Fatal(err)
	}
	err := s.SetReservation(Reservation{MAC: macB, IP: ip}, lanPrefix, pool)
	if err == nil || !strings.Contains(err.Error(), "already reserved") {
		t.Fatalf("error = %v, want one saying the address is already reserved", err)
	}
	// Re-saving the same MAC with the same address is not a clash.
	if err := s.SetReservation(Reservation{MAC: macA, IP: ip, Note: "same device"}, lanPrefix, pool); err != nil {
		t.Errorf("a reservation may be edited in place: %v", err)
	}
}

func TestDeleteReservationReportsWhetherThereWasOne(t *testing.T) {
	s, _, _ := openState(t)
	pool := Pool{Start: poolStart, End: poolEnd}
	if err := s.SetReservation(Reservation{MAC: macA}, lanPrefix, pool); err != nil {
		t.Fatal(err)
	}
	ok, err := s.DeleteReservation("02-00-5E-01-02-03")
	if err != nil || !ok {
		t.Fatalf("DeleteReservation = %v, %v; want true, nil", ok, err)
	}
	ok, err = s.DeleteReservation(macA)
	if err != nil || ok {
		t.Fatalf("a second delete = %v, %v; want false, nil", ok, err)
	}
}

func TestConfirmationAndKillSwitchSurviveARestart(t *testing.T) {
	s, _, path := openState(t)
	if s.Confirmed() {
		t.Fatal("a fresh state has not been confirmed: that is the point")
	}
	if err := s.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisarmed(true, "testing the kill switch"); err != nil {
		t.Fatal(err)
	}
	back, err := OpenState(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Confirmed() {
		t.Error("the confirmation must survive a restart")
	}
	off, reason, at := back.Disarmed()
	if !off || reason != "testing the kill switch" || at.IsZero() {
		t.Errorf("Disarmed = %v, %q, %v; the kill switch stays pulled across restarts", off, reason, at)
	}
	if err := back.SetDisarmed(false, "ignored"); err != nil {
		t.Fatal(err)
	}
	if off, reason, at = back.Disarmed(); off || reason != "" || !at.IsZero() {
		t.Errorf("re-arming should clear everything, got %v, %q, %v", off, reason, at)
	}
	if err := back.SetConfirmed(false); err != nil {
		t.Fatal(err)
	}
	if back.Confirmed() {
		t.Error("withdrawing the confirmation must stick")
	}
}

// Reservations are the one piece of DHCP state nothing re-sends, so an
// unreadable file is refused rather than silently started over.
func TestOpenStateRefusesAnUnreadableOrUnknownFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(bad, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(bad, nil); err == nil {
		t.Error("an unparseable reservations file must be an error, not an empty store")
	}

	future := filepath.Join(dir, "future.json")
	if err := os.WriteFile(future, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(future, nil); err == nil {
		t.Error("a version this build does not know must be refused")
	}

	asDir := filepath.Join(dir, "statedir")
	if err := os.Mkdir(asDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(asDir, nil); err == nil {
		t.Error("an unreadable path must be an error")
	}
}

func TestOpenStateDropsRecordsWithNoUsableMAC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dhcp.json")
	body := `{"version":1,"reservations":[null,{"mac":""},{"mac":"02-00-5E-01-02-03","hostname":"printer"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenState(path, nil)
	if err != nil {
		t.Fatalf("OpenState: %v", err)
	}
	res := s.Reservations()
	if len(res) != 1 || res[0].MAC != macA {
		t.Fatalf("Reservations = %+v, want just the one with a usable MAC, normalized", res)
	}
}

func TestStateWriteFailureLeavesTheStoreUnchanged(t *testing.T) {
	// A path whose directory disappears: every mutator must roll back
	// rather than report success for something that is not on disk.
	dir := t.TempDir()
	sub := filepath.Join(dir, "gone")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "dhcp.json")
	s, err := OpenState(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}
	pool := Pool{Start: poolStart, End: poolEnd}
	if err := s.SetReservation(Reservation{MAC: macA}, lanPrefix, pool); err == nil {
		t.Fatal("SetReservation must fail when it cannot be written")
	}
	if len(s.Reservations()) != 0 {
		t.Error("a failed write must not leave the reservation in memory")
	}
	if err := s.SetConfirmed(true); err == nil || s.Confirmed() {
		t.Error("a failed confirmation write must roll back")
	}
	if err := s.SetDisarmed(true, "x"); err == nil {
		t.Error("a failed kill-switch write must be reported")
	}
	if off, _, _ := s.Disarmed(); off {
		t.Error("a failed kill-switch write must roll back")
	}
	// Deleting something that is not there needs no write and so still
	// answers cleanly.
	if ok, err := s.DeleteReservation(macA); ok || err != nil {
		t.Errorf("DeleteReservation = %v, %v; want false, nil", ok, err)
	}
}

func TestReservationLookupsOnANilBackedAllocatorAreSafe(t *testing.T) {
	var s *State
	a := &Allocator{}
	if _, ok := a.reservation(macA); ok {
		t.Error("an allocator with no state has no reservations")
	}
	if a.reservations() != nil {
		t.Error("and no list of them")
	}
	_ = s
}

// Editing and deleting write the whole file, so each has its own rollback.
func TestEditingAndDeletingRollBackWhenTheFileCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "state")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "dhcp.json")
	s, err := OpenState(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	pool := Pool{Start: poolStart, End: poolEnd}
	if err := s.SetReservation(Reservation{MAC: macA, Hostname: "first"}, lanPrefix, pool); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}

	// The replace path.
	if err := s.SetReservation(Reservation{MAC: macA, Hostname: "second"}, lanPrefix, pool); err == nil {
		t.Fatal("an edit that cannot be written must fail")
	}
	if got, _ := s.Reservation(macA); got.Hostname != "first" {
		t.Errorf("Hostname = %q, want the edit rolled back", got.Hostname)
	}

	// The delete path.
	if ok, err := s.DeleteReservation(macA); ok || err == nil {
		t.Fatalf("DeleteReservation = %v, %v; want false and an error", ok, err)
	}
	if _, ok := s.Reservation(macA); !ok {
		t.Error("a delete that could not be written must leave the reservation in place")
	}
}
