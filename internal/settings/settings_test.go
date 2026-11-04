// SPDX-License-Identifier: AGPL-3.0-or-later

package settings

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHomeRoundTripAndPrivacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Home() != nil {
		t.Error("a new store has no home")
	}
	if err := s.SetHome(Home{Lat: 48.5, Lon: -120.25, Label: "  Test Town  "}); err != nil {
		t.Fatal(err)
	}
	got := s.Home()
	if got == nil || got.Lat != 48.5 || got.Lon != -120.25 || got.Label != "Test Town" {
		t.Errorf("home = %+v", got)
	}
	got.Lat = 0 // the copy must not alias the store
	if s.Home().Lat != 48.5 {
		t.Error("Home() must return a copy")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("settings file mode %v, want 0600", info.Mode().Perm())
	}
	s2, err := Open(path)
	if err != nil || s2.Home() == nil || s2.Home().Lat != 48.5 {
		t.Errorf("reload: %v %+v", err, s2.Home())
	}
}

func TestHomeValidation(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "s.json"))
	for name, h := range map[string]Home{
		"lat high":  {Lat: 91},
		"lat low":   {Lat: -91},
		"lon high":  {Lon: 181},
		"lon low":   {Lon: -181},
		"nan":       {Lat: math.NaN()},
		"long text": {Label: strings.Repeat("x", 81)},
	} {
		if err := s.SetHome(h); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if s.Home() != nil {
		t.Error("an invalid home must not be stored")
	}
	if err := s.SetHome(Home{Lat: -90, Lon: 180}); err != nil {
		t.Errorf("the extremes are valid: %v", err)
	}
}

func TestOpenErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{nope"), 0o600)
	if _, err := Open(bad); err == nil {
		t.Error("corrupt settings must be an error")
	}
	if _, err := Open(dir); err == nil { // a directory where the file belongs
		t.Error("an unreadable path must be an error")
	}
	s, _ := Open(filepath.Join(dir, "gone", "s.json"))
	if err := s.SetHome(Home{Lat: 1, Lon: 1}); err == nil {
		t.Error("an unwritable path must be an error")
	}
	s2, _ := Open(filepath.Join(dir, "ok.json"))
	os.MkdirAll(filepath.Join(dir, "ok.json.tmp", "x"), 0o700) // blocks the temp file
	if err := s2.SetHome(Home{Lat: 1, Lon: 1}); err == nil {
		t.Error("a failed write must be an error and leave nothing half-saved")
	}
	if s2.Home() != nil {
		t.Error("a failed save must not change the in-memory home")
	}
}

func TestUserOverrideBeatsDetectedHomeAndCanBeCleared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	s, _ := Open(path)
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	if err := s.SetAuto(Home{Lat: 40.76, Lon: -111.89, Label: "Testville, ZZ", At: at}); err != nil {
		t.Fatal(err)
	}
	if h := s.Home(); h == nil || h.Source != SourceAuto || h.Label != "Testville, ZZ" || !h.At.Equal(at) {
		t.Errorf("a detected home is used when there is no override: %+v", h)
	}
	if s.UserHome() != nil {
		t.Error("detection must not create a user override")
	}
	s.SetHome(Home{Lat: 1, Lon: 2, Label: "Mine"})
	if h := s.Home(); h.Source != SourceUser || h.Lat != 1 {
		t.Errorf("the user's choice must win: %+v", h)
	}
	s.SetAuto(Home{Lat: 5, Lon: 5, Label: "Newer detection"}) // a later detection must not clobber the choice
	if h := s.Home(); h.Source != SourceUser || h.Label != "Mine" {
		t.Errorf("detection overrode the user: %+v", h)
	}
	s2, _ := Open(path) // both survive a restart
	if h := s2.UserHome(); h == nil || h.Lat != 1 {
		t.Errorf("override lost on reload: %+v", h)
	}
	if err := s.ClearHome(); err != nil {
		t.Fatal(err)
	}
	if h := s.Home(); h == nil || h.Source != SourceAuto || h.Label != "Newer detection" {
		t.Errorf("clearing must fall back to the detected home: %+v", h)
	}
	if err := s.SetAuto(Home{Lat: 200}); err == nil {
		t.Error("an invalid detected location must be rejected")
	}
}

func TestStoresNoIPAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	s, _ := Open(path)
	s.SetAuto(Home{Lat: 1, Lon: 1, Label: "Somewhere, ZZ"})
	b, _ := os.ReadFile(path)
	for _, key := range []string{"ip", "addr", "wan"} {
		if strings.Contains(strings.ToLower(string(b)), "\""+key) {
			t.Errorf("the settings file must hold a place, not an address: %s", b)
		}
	}
}

func TestAAAAModeRoundTripAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.AAAAMode(); got != "" {
		t.Errorf("a new store has no mode, got %q", got)
	}
	for _, mode := range []string{AAAAAuto, AAAAOn, AAAAOff} {
		if err := s.SetAAAAMode(mode); err != nil {
			t.Fatalf("SetAAAAMode(%q): %v", mode, err)
		}
		if got := s.AAAAMode(); got != mode {
			t.Errorf("AAAAMode = %q, want %q", got, mode)
		}
	}
	// It has to survive a restart, or the portal's choice would be lost and
	// dns.filter_aaaa would silently take over again.
	s2, err := Open(path)
	if err != nil || s2.AAAAMode() != AAAAOff {
		t.Errorf("reload: %v %q", err, s2.AAAAMode())
	}
	for _, bad := range []string{"maybe", "ON", "", "true"} {
		if err := s.SetAAAAMode(bad); err == nil {
			t.Errorf("SetAAAAMode(%q) was accepted", bad)
		}
	}
	if s.AAAAMode() != AAAAOff {
		t.Error("a refused mode must leave the saved one alone")
	}
	if err := s.ClearAAAAMode(); err != nil {
		t.Fatal(err)
	}
	if s.AAAAMode() != "" {
		t.Error("ClearAAAAMode must hand the decision back to the configuration file")
	}
	// Clearing must not have disturbed the home that shares the file.
	if err := s.SetHome(Home{Lat: 1, Lon: 2}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAAAAMode(AAAAOn); err != nil {
		t.Fatal(err)
	}
	if h := s.Home(); h == nil || h.Lat != 1 {
		t.Errorf("home was lost: %+v", s.Home())
	}
	if !ValidAAAAMode(AAAAAuto) || ValidAAAAMode("x") {
		t.Error("ValidAAAAMode")
	}
}
