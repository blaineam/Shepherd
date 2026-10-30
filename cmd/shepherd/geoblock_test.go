// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"

	"shepherd/internal/dnsengine"
	"shepherd/internal/geo"
)

func TestStartGeoBlockNoLocatorNeverBlocks(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	store, err := dnsengine.OpenGeoBlockStore("")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetCountries(dnsengine.NetworkScope(), []string{"FR"}); err != nil {
		t.Fatal(err)
	}
	startGeoBlock(engine, store, reg, nil)
	if engine.CountryBlock == nil {
		t.Fatal("startGeoBlock must always wire CountryBlock")
	}
	if country, blocked := engine.CountryBlock("192.0.2.1", []dnsengine.Dest{{IP: "198.51.100.7", Country: "FR"}}); blocked || country != "" {
		t.Errorf("a nil locator must never block, got %q, %v", country, blocked)
	}
}

func TestStartGeoBlockLocatorNotReadyNeverBlocks(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	store, _ := dnsengine.OpenGeoBlockStore("")
	store.SetCountries(dnsengine.NetworkScope(), []string{"FR"})
	var loc geo.Locator // never opened: not ready
	startGeoBlock(engine, store, reg, &loc)
	if country, blocked := engine.CountryBlock("192.0.2.1", []dnsengine.Dest{{IP: "198.51.100.7", Country: "FR"}}); blocked || country != "" {
		t.Errorf("an unready locator must never block, got %q, %v", country, blocked)
	}
}

func TestStartGeoBlockNothingConfiguredNeverBlocks(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	store, _ := dnsengine.OpenGeoBlockStore("")
	startGeoBlock(engine, store, reg, nil)
	if _, blocked := engine.CountryBlock("192.0.2.1", []dnsengine.Dest{{Country: "FR"}}); blocked {
		t.Error("nothing configured anywhere must never block")
	}
}

// buildCityDB writes a tiny city-level GeoIP database (the same shape
// internal/geo's own tests use) so the locator reports Ready() and resolves
// a country for the fixture address.
func buildCityDB(t *testing.T, path string) {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "GeoLite2-City", RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	_, n, _ := net.ParseCIDR("198.51.100.0/24")
	rec := mmdbtype.Map{
		"city":     mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String("Paris")}},
		"country":  mmdbtype.Map{"iso_code": mmdbtype.String("FR")},
		"location": mmdbtype.Map{"latitude": mmdbtype.Float64(48.85), "longitude": mmdbtype.Float64(2.35)},
	}
	if err := w.Insert(n, rec); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
}

func TestStartGeoBlockMatchesConfiguredCountry(t *testing.T) {
	engine, reg := testEngineAndRegistry(t)
	dbPath := filepath.Join(t.TempDir(), "city.mmdb")
	buildCityDB(t, dbPath)
	var loc geo.Locator
	if err := loc.Open(dbPath); err != nil {
		t.Fatal(err)
	}
	store, _ := dnsengine.OpenGeoBlockStore("")
	store.SetCountries(dnsengine.NetworkScope(), []string{"FR"})
	startGeoBlock(engine, store, reg, &loc)

	dest, ok := loc.Locate(net.ParseIP("198.51.100.7"))
	if !ok || dest.Country != "FR" {
		t.Fatalf("fixture locator did not resolve FR: %+v, %v", dest, ok)
	}
	country, blocked := engine.CountryBlock("192.0.2.1", []dnsengine.Dest{dest})
	if !blocked || country != "FR" {
		t.Errorf("CountryBlock = %q, %v, want FR, true", country, blocked)
	}

	// A different, unconfigured country must not match.
	if _, blocked := engine.CountryBlock("192.0.2.1", []dnsengine.Dest{{Country: "DE"}}); blocked {
		t.Error("an unconfigured country must not block")
	}
}
