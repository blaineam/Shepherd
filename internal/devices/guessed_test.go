// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestNewTypesParseAndListed(t *testing.T) {
	for in, want := range map[string]DeviceType{
		"streaming box": TypeStreamingBox, "streaming_box": TypeStreamingBox, "firestick": TypeStreamingBox,
		"smart plug/sensor": TypeSmartPlug, "plug": TypeSmartPlug, "sensor": TypeSmartPlug,
		"doorbell": TypeDoorbell, "video doorbell": TypeDoorbell, "thermostat": TypeThermostat, "thermo": TypeThermostat,
		"e-reader": TypeEReader, "ebook": TypeEReader, "wearable": TypeWearable, "smartwatch": TypeWearable,
		"NAS/server": TypeNAS, "nas": TypeNAS, "server": TypeNAS,
	} {
		if got, ok := ParseType(in); !ok || got != want {
			t.Errorf("ParseType(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	seen := map[DeviceType]bool{}
	for _, ty := range AllTypes() {
		if seen[ty] {
			t.Errorf("%q listed twice", ty)
		}
		seen[ty] = true
		if back, ok := ParseType(string(ty)); !ok || back != ty {
			t.Errorf("type %q does not round-trip through ParseType (%q)", ty, back)
		}
	}
	for _, ty := range []DeviceType{TypeStreamingBox, TypeSmartPlug, TypeDoorbell, TypeThermostat, TypeEReader, TypeWearable, TypeNAS} {
		if !seen[ty] {
			t.Errorf("%q missing from AllTypes", ty)
		}
	}
}

func TestServiceTypeRulesIsACopy(t *testing.T) {
	m := ServiceTypeRules()
	if m["_ipp"] != TypePrinter || m["_hap"] != TypeSmartHome || len(m) < 10 {
		t.Fatalf("unexpected table: %v", m)
	}
	m["_ipp"] = TypeCamera
	if ServiceTypeRules()["_ipp"] != TypePrinter {
		t.Fatal("callers must not be able to edit the table")
	}
}

func TestSetGuessedTypeAndTheUsersChoiceAlwaysWins(t *testing.T) {
	r, _ := newReg(t)
	id := r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:09", IP: "192.0.2.9"})

	changed, err := r.SetGuessedType(id, TypeDoorbell, "Most lookups go to a doorbell cloud", 0.8749)
	if err != nil || !changed {
		t.Fatalf("first guess: %v %v", changed, err)
	}
	d := mustDevice(t, r, id)
	eq(t, d.Type, TypeDoorbell)
	eq(t, d.TypeAuto, true)
	eq(t, d.TypeUser, false)
	eq(t, d.TypeConfidence, 0.87)
	eq(t, d.TypeReason, "Most lookups go to a doorbell cloud")

	// The same answer again changes nothing (and writes nothing).
	stamp := d.Updated
	if changed, _ := r.SetGuessedType(id, TypeDoorbell, "Most lookups go to a doorbell cloud", 0.8749); changed {
		t.Error("an identical guess must be a no-op")
	}
	if changed, _ := r.SetGuessedType(id, TypeDoorbell, "Most lookups go to a doorbell cloud", 0.89); changed {
		t.Error("a confidence wobble below the step must be a no-op")
	}
	eq(t, mustDevice(t, r, id).Updated, stamp)
	if changed, _ := r.SetGuessedType(id, TypeDoorbell, "Most lookups go to a doorbell cloud", 0.95); !changed {
		t.Error("a real confidence change must be recorded")
	}

	// Registry re-guessing (new vendor/services/names) leaves the classifier's guess alone.
	if err := r.Rename(id, "Porch thing"); err != nil {
		t.Fatal(err)
	}
	eq(t, mustDevice(t, r, id).Type, TypeDoorbell)

	// The user's choice beats the guess, and survives every later guess.
	if err := r.SetType(id, "tv"); err != nil {
		t.Fatal(err)
	}
	d = mustDevice(t, r, id)
	eq(t, d.Type, TypeTV)
	eq(t, d.TypeUser, true)
	eq(t, d.TypeAuto, false)
	eq(t, d.TypeConfidence, 0.0)
	if changed, err := r.SetGuessedType(id, TypeCamera, "x", 0.99); changed || err != nil {
		t.Errorf("a guess must not replace the user's type: %v %v", changed, err)
	}
	if changed, _ := r.ClearGuessedType(id); changed {
		t.Error("clearing a guess must not touch the user's type")
	}
	eq(t, mustDevice(t, r, id).Type, TypeTV)

	// Back to automatic: the registry's own guess returns, then the classifier may guess again.
	if err := r.SetType(id, "auto"); err != nil {
		t.Fatal(err)
	}
	eq(t, mustDevice(t, r, id).TypeUser, false)
	if changed, _ := r.SetGuessedType(id, TypeCamera, "cloud", 0.7); !changed {
		t.Error("guessing is possible again after the user returns to auto")
	}
}

func TestSetGuessedTypeValidationAndClear(t *testing.T) {
	r, _ := newReg(t)
	id := r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0a", IP: "192.0.2.10"})
	if _, err := r.SetGuessedType(id, TypeUnknown, "x", 0.9); !errors.Is(err, ErrInvalid) {
		t.Error("unknown is not a guess")
	}
	if _, err := r.SetGuessedType(id, DeviceType("toaster"), "x", 0.9); !errors.Is(err, ErrInvalid) {
		t.Error("an invented type must be rejected")
	}
	if _, err := r.SetGuessedType("nope", TypeTV, "x", 0.9); !errors.Is(err, ErrNotFound) {
		t.Error("missing device")
	}
	if _, err := r.ClearGuessedType("nope"); !errors.Is(err, ErrNotFound) {
		t.Error("missing device")
	}
	// Confidence is clamped and long reasons are trimmed.
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'a'
	}
	r.SetGuessedType(id, TypeTV, string(long), 7)
	d := mustDevice(t, r, id)
	eq(t, d.TypeConfidence, 1.0)
	eq(t, len(d.TypeReason), 256)
	r.SetGuessedType(id, TypeTV, "ok", -3)
	eq(t, mustDevice(t, r, id).TypeConfidence, 0.0)

	if changed, _ := r.ClearGuessedType(id); !changed {
		t.Fatal("clearing a guess changes the device")
	}
	d = mustDevice(t, r, id)
	eq(t, d.TypeAuto, false)
	eq(t, d.TypeConfidence, 0.0)
	eq(t, d.Type, TypeUnknown) // back to the registry's own (empty) guess
	if changed, _ := r.ClearGuessedType(id); changed {
		t.Error("clearing twice is a no-op")
	}
}

func TestGuessedTypeSurvivesSaveAndLoad(t *testing.T) {
	r, _ := newReg(t)
	id := r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0b", IP: "192.0.2.11"})
	r.SetGuessedType(id, TypeThermostat, "Lookups go to a thermostat cloud", 0.72)
	path := filepath.Join(t.TempDir(), "devices.json")
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	r2, _ := newReg(t)
	if err := r2.Load(path); err != nil {
		t.Fatal(err)
	}
	d := mustDevice(t, r2, id)
	eq(t, d.Type, TypeThermostat)
	eq(t, d.TypeAuto, true)
	eq(t, d.TypeConfidence, 0.72)
}

func TestKnownVendorsListsTheTable(t *testing.T) {
	v := KnownVendors()
	if len(v) < 1000 {
		t.Fatalf("expected the full manufacturer list, got %d", len(v))
	}
	for i := 1; i < len(v); i++ {
		if v[i-1] > v[i] {
			t.Fatal("not sorted")
		}
	}
	found := false
	for _, n := range v {
		found = found || n == "Apple"
	}
	if !found {
		t.Error("Apple missing")
	}
}
