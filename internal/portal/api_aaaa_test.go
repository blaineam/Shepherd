// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"os"
	"path/filepath"
	"testing"

	"shepherd/internal/devices"
	"shepherd/internal/settings"
)

func aaaaHarness(t *testing.T, configMode string, filtering, usable bool) *harness {
	t.Helper()
	dir := t.TempDir()
	prefs, err := settings.Open(filepath.Join(dir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	return newHarnessWith(t, func(d *Deps) {
		d.Settings = prefs
		d.AAAAConfigMode = configMode
		d.AAAANetwork = func() bool { return filtering }
		d.AAAAIPv6Usable = func() bool { return usable }
	})
}

func TestAAAAStartsFromTheConfigurationFileAndSaysSo(t *testing.T) {
	h := aaaaHarness(t, "auto", true, false)
	doc := h.ok("GET", "/api/dns/aaaa", "", 200)
	if doc["mode"] != "auto" {
		t.Errorf("mode = %v", doc["mode"])
	}
	// from_config is what lets the screen say where the setting came from,
	// which is the whole point: it should not have to be edited in a file.
	if doc["from_config"] != true {
		t.Errorf("from_config = %v, want true before anything is saved", doc["from_config"])
	}
	if doc["filtering"] != true || doc["ipv6_usable"] != false {
		t.Errorf("filtering = %v, ipv6_usable = %v", doc["filtering"], doc["ipv6_usable"])
	}
	if ex, ok := doc["exceptions"].([]any); !ok || len(ex) != 0 {
		t.Errorf("exceptions = %v, want an empty list", doc["exceptions"])
	}
}

func TestAAAAModeIsSavedAndCanGoBackToTheConfigurationFile(t *testing.T) {
	h := aaaaHarness(t, "auto", true, false)
	doc := h.ok("PUT", "/api/dns/aaaa", `{"mode":"off"}`, 200)
	if doc["mode"] != "off" || doc["from_config"] != false {
		t.Fatalf("after saving: mode = %v, from_config = %v", doc["mode"], doc["from_config"])
	}
	if got := h.srv.Settings.AAAAMode(); got != "off" {
		t.Errorf("the store holds %q", got)
	}
	// It survives a reload of the store, which is what makes it a setting
	// rather than something lost on the next restart.
	again := h.ok("GET", "/api/dns/aaaa", "", 200)
	if again["mode"] != "off" {
		t.Errorf("GET after PUT = %v", again["mode"])
	}
	back := h.ok("PUT", "/api/dns/aaaa", `{"mode":""}`, 200)
	if back["mode"] != "auto" || back["from_config"] != true {
		t.Errorf("clearing: mode = %v, from_config = %v", back["mode"], back["from_config"])
	}
}

func TestAAAARefusesAnUnknownMode(t *testing.T) {
	h := aaaaHarness(t, "auto", false, true)
	h.expect("PUT", "/api/dns/aaaa", `{"mode":"maybe"}`, 400)
	if h.srv.Settings.AAAAMode() != "" {
		t.Error("a refused mode must not be saved")
	}
}

func TestAAAAWithoutASettingsStoreStillHoldsTheChoice(t *testing.T) {
	h := newHarnessWith(t, func(d *Deps) {
		d.AAAAConfigMode = "auto"
		d.AAAANetwork = func() bool { return true }
	})
	if doc := h.ok("PUT", "/api/dns/aaaa", `{"mode":"on"}`, 200); doc["mode"] != "on" {
		t.Fatalf("mode = %v", doc["mode"])
	}
	if doc := h.ok("GET", "/api/dns/aaaa", "", 200); doc["mode"] != "on" || doc["from_config"] != false {
		t.Errorf("GET = %v / %v", doc["mode"], doc["from_config"])
	}
	// ipv6_usable is left off entirely rather than guessed at.
	doc := h.ok("GET", "/api/dns/aaaa", "", 200)
	if _, has := doc["ipv6_usable"]; has {
		t.Error("ipv6_usable must be absent when nothing reports it")
	}
}

func TestAAAAListsTheDevicesWithTheirOwnSwitch(t *testing.T) {
	h := aaaaHarness(t, "auto", true, false)
	id := h.addDevice("02:00:5e:00:00:01", "192.0.2.10", "solar")
	h.ok("PATCH", "/api/devices/"+id, `{"aaaa":"off"}`, 200)

	dev := h.ok("GET", "/api/devices/"+id, "", 200)
	if dev["aaaa"] != "off" {
		t.Errorf("device aaaa = %v", dev["aaaa"])
	}
	if d, ok := h.reg.Get(id); !ok || d.AAAA != devices.AAAAOff {
		t.Errorf("registry holds %q", d.AAAA)
	}
	doc := h.ok("GET", "/api/dns/aaaa", "", 200)
	ex, ok := doc["exceptions"].([]any)
	if !ok || len(ex) != 1 {
		t.Fatalf("exceptions = %v", doc["exceptions"])
	}
	row := ex[0].(map[string]any)
	if row["id"] != id || row["aaaa"] != "off" || row["name"] == "" {
		t.Errorf("exception row = %v", row)
	}

	// Back to automatic, and it leaves the list.
	h.ok("PATCH", "/api/devices/"+id, `{"aaaa":"auto"}`, 200)
	doc = h.ok("GET", "/api/dns/aaaa", "", 200)
	if ex, _ := doc["exceptions"].([]any); len(ex) != 0 {
		t.Errorf("exceptions after clearing = %v", doc["exceptions"])
	}
}

func TestDeviceAAAASwitchRefusesNonsenseAndWorksInBulk(t *testing.T) {
	h := newHarness(t)
	a := h.addDevice("02:00:5e:00:00:0a", "192.0.2.20", "a")
	b := h.addDevice("02:00:5e:00:00:0b", "192.0.2.21", "b")
	h.expect("PATCH", "/api/devices/"+a, `{"aaaa":"maybe"}`, 400)

	res := h.ok("POST", "/api/devices/bulk", `{"ids":["`+a+`","`+b+`"],"op":"set_aaaa","aaaa":"on"}`, 200)
	if res["changed"] != float64(2) {
		t.Fatalf("changed = %v", res["changed"])
	}
	for _, id := range []string{a, b} {
		if d, _ := h.reg.Get(id); d.AAAA != devices.AAAAOn {
			t.Errorf("%s holds %q", id, d.AAAA)
		}
	}
	h.expect("POST", "/api/devices/bulk", `{"ids":["`+a+`"],"op":"set_aaaa","aaaa":"maybe"}`, 400)
	h.expect("POST", "/api/devices/bulk", `{"ids":["`+a+`"],"op":"set_aaaa"}`, 400)
}

// A data directory that cannot be written to (a read-only mount, a wrong
// owner after a container change) must say so rather than claim the setting
// was saved.
func TestAAAASaveFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "data")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	prefs, err := settings.Open(filepath.Join(sub, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarnessWith(t, func(d *Deps) {
		d.Settings = prefs
		d.AAAAConfigMode = "auto"
		d.AAAANetwork = func() bool { return true }
	})
	if err := os.Chmod(sub, 0o500); err != nil {
		t.Skipf("cannot make the directory read-only here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })

	h.expect("PUT", "/api/dns/aaaa", `{"mode":"on"}`, 500)
	h.expect("PUT", "/api/dns/aaaa", `{"mode":""}`, 500)
}
