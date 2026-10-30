// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidCountryAndNormalize(t *testing.T) {
	for code, want := range map[string]bool{
		"US": true, "us": false, "USA": false, "U": false, "": false, "12": false, "U1": false,
	} {
		if got := validCountry(code); got != want {
			t.Errorf("validCountry(%q) = %v, want %v", code, got, want)
		}
	}
	norm, err := normalizeCountries([]string{" us ", "DE", "de", "FR"})
	if err != nil || len(norm) != 3 || norm[0] != "DE" || norm[1] != "FR" || norm[2] != "US" {
		t.Fatalf("normalizeCountries = %v, %v", norm, err)
	}
	if _, err := normalizeCountries([]string{"usa"}); err == nil {
		t.Error("a three-letter code must be rejected")
	}
	if _, err := normalizeCountries([]string{"1x"}); err == nil {
		t.Error("digits must be rejected")
	}
	if got, err := normalizeCountries(nil); err != nil || len(got) != 0 {
		t.Errorf("normalizeCountries(nil) = %v, %v", got, err)
	}
}

func TestOpenGeoBlockStoreFreshMissingAndCorrupt(t *testing.T) {
	s, err := OpenGeoBlockStore("")
	if err != nil || len(s.Snapshot().Network) != 0 {
		t.Fatalf("empty path store = %+v, %v", s, err)
	}
	if err := s.SetCountries(NetworkScope(), []string{"US"}); err != nil {
		t.Fatalf("set on memory-only store: %v", err)
	}
	if got := s.Countries(NetworkScope()); len(got) != 1 || got[0] != "US" {
		t.Errorf("Countries = %v", got)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "geoblock.json")
	s2, err := OpenGeoBlockStore(path)
	if err != nil {
		t.Fatalf("missing file: %v", err)
	}
	if len(s2.Snapshot().Network) != 0 {
		t.Error("a missing file must start with nothing blocked")
	}

	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{not json"), 0o600)
	if _, err := OpenGeoBlockStore(bad); err == nil {
		t.Error("corrupt JSON must fail to open")
	}

	wrongVer := filepath.Join(dir, "wrongver.json")
	os.WriteFile(wrongVer, []byte(`{"version":99}`), 0o600)
	if _, err := OpenGeoBlockStore(wrongVer); err == nil {
		t.Error("an unsupported version must fail to open")
	}

	badCode := filepath.Join(dir, "badcode.json")
	os.WriteFile(badCode, []byte(`{"version":1,"network":["usa"]}`), 0o600)
	if _, err := OpenGeoBlockStore(badCode); err == nil {
		t.Error("an invalid persisted country code must fail validation")
	}

	badScope := filepath.Join(dir, "badscope.json")
	os.WriteFile(badScope, []byte(`{"version":1,"groups":{"":["US"]}}`), 0o600)
	if _, err := OpenGeoBlockStore(badScope); err == nil {
		t.Error("an invalid persisted scope id must fail validation")
	}

	bare := filepath.Join(dir, "bare.json")
	os.WriteFile(bare, []byte(`{"version":1}`), 0o600)
	s3, err := OpenGeoBlockStore(bare)
	if err != nil {
		t.Fatalf("a bare document with no groups or devices keys must open: %v", err)
	}
	snap := s3.Snapshot()
	if snap.Groups == nil || snap.Devices == nil {
		t.Errorf("missing groups/devices keys must still end up as empty maps: %+v", snap)
	}
}

func TestGeoBlockStorePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geoblock.json")
	s, err := OpenGeoBlockStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetCountries(NetworkScope(), []string{"CN", "RU"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCountries(GroupScope("kids"), []string{"kp"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCountries(DeviceScope("tv-1"), []string{"IR"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected geoblock.json to be written: %v", err)
	}

	reopened, err := OpenGeoBlockStore(path)
	if err != nil {
		t.Fatal(err)
	}
	snap := reopened.Snapshot()
	if len(snap.Network) != 2 || snap.Network[0] != "CN" || snap.Network[1] != "RU" {
		t.Errorf("network = %v", snap.Network)
	}
	if got := snap.Groups["kids"]; len(got) != 1 || got[0] != "KP" {
		t.Errorf("groups[kids] = %v", got)
	}
	if got := snap.Devices["tv-1"]; len(got) != 1 || got[0] != "IR" {
		t.Errorf("devices[tv-1] = %v", got)
	}
}

func TestGeoBlockStoreSetClearAndScopeValidation(t *testing.T) {
	s, _ := OpenGeoBlockStore("")
	if err := s.SetCountries(GroupScope(""), []string{"US"}); err == nil {
		t.Error("an empty group id must be rejected")
	}
	if err := s.SetCountries(DeviceScope(""), []string{"US"}); err == nil {
		t.Error("an empty device id must be rejected")
	}
	if err := s.SetCountries(Scope{Kind: "bogus"}, []string{"US"}); err == nil {
		t.Error("an unknown scope kind must be rejected")
	}
	if err := s.SetCountries(NetworkScope(), []string{"not-a-code"}); err == nil {
		t.Error("an invalid country code must be rejected, leaving nothing set")
	}
	if len(s.Countries(NetworkScope())) != 0 {
		t.Error("a rejected edit must not be applied")
	}

	if err := s.SetCountries(GroupScope("g1"), []string{"US", "us", " US "}); err != nil {
		t.Fatal(err)
	}
	if got := s.Countries(GroupScope("g1")); len(got) != 1 {
		t.Errorf("duplicates must collapse: %v", got)
	}
	if err := s.ClearCountries(GroupScope("g1")); err != nil {
		t.Fatal(err)
	}
	if got := s.Snapshot().Groups["g1"]; got != nil {
		t.Errorf("a cleared group scope must drop its entry entirely, got %v", got)
	}
	if err := s.ClearCountries(DeviceScope("d1")); err != nil { // clearing something never set is a no-op
		t.Fatal(err)
	}
	if got := s.Countries(Scope{Kind: "bogus"}); got != nil {
		t.Errorf("Countries of an unknown scope kind = %v, want nil", got)
	}
}

func TestGeoBlockStoreDeleteScope(t *testing.T) {
	s, _ := OpenGeoBlockStore("")
	s.SetCountries(GroupScope("kids"), []string{"KP"})
	s.SetCountries(DeviceScope("tv-1"), []string{"IR"})
	if err := s.DeleteScope(GroupScope("kids")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteScope(DeviceScope("tv-1")); err != nil {
		t.Fatal(err)
	}
	snap := s.Snapshot()
	if len(snap.Groups) != 0 || len(snap.Devices) != 0 {
		t.Errorf("deleted scopes must be gone: %+v", snap)
	}
	if err := s.DeleteScope(NetworkScope()); err == nil {
		t.Error("the network scope must not be deletable")
	}
}

func TestGeoBlockStoreBlockedForUnionsScopes(t *testing.T) {
	s, _ := OpenGeoBlockStore("")
	if got := s.BlockedFor("192.0.2.1", nil); got != nil {
		t.Errorf("nothing configured must return nil without allocating: %v", got)
	}
	s.SetCountries(NetworkScope(), []string{"CN"})
	s.SetCountries(GroupScope("kids"), []string{"KP"})
	s.SetCountries(DeviceScope("tv-1"), []string{"IR"})

	cs := fakeClients{"192.0.2.1": client("tv-1", "kids"), "192.0.2.2": client("", "kids"), "192.0.2.3": client("")}
	got := s.BlockedFor("192.0.2.1", cs)
	for _, want := range []string{"CN", "KP", "IR"} {
		if !got[want] {
			t.Errorf("BlockedFor device in group = %v, missing %s", got, want)
		}
	}
	got2 := s.BlockedFor("192.0.2.2", cs)
	if !got2["CN"] || !got2["KP"] || got2["IR"] {
		t.Errorf("group-only client = %v", got2)
	}
	got3 := s.BlockedFor("192.0.2.3", cs)
	if !got3["CN"] || got3["KP"] || got3["IR"] {
		t.Errorf("device-with-no-group client = %v", got3)
	}
	// An unknown client (nil ClientScopes or no entry) gets network scope only.
	if got4 := s.BlockedFor("198.51.100.9", cs); !got4["CN"] || got4["KP"] || got4["IR"] {
		t.Errorf("unknown client = %v", got4)
	}
	if got5 := s.BlockedFor("198.51.100.9", nil); !got5["CN"] || len(got5) != 1 {
		t.Errorf("nil ClientScopes = %v", got5)
	}
}
