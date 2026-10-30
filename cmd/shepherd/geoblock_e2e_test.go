// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/miekg/dns"
)

// seedCityDB writes a tiny, real city-level GeoIP database straight into
// <dataDir>/geo/, the same file name and shape geo.Manager expects, so the
// running server loads it from disk at startup instead of downloading one.
func seedCityDB(t *testing.T, dataDir string) {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "DBIP-City-Lite", RecordSize: 24, IncludeReservedNetworks: true})
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
	dir := filepath.Join(dataDir, "geo")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "dbip-city-lite.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
}

// fixedAnswerServer answers every A query with ip (a reserved documentation
// range such as 198.51.100.0/24 counts as "public" for Shepherd's own
// filters, same as the rest of the test suite relies on).
func fixedAnswerServer(t *testing.T, ip string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP(ip)})
		}
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// resolveA asks addr for name's A record and returns it ("" when there is none).
func resolveA(t *testing.T, addr, name string) string {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	resp, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(q, addr)
	if err != nil {
		t.Fatalf("query %s via %s: %v", name, addr, err)
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

func TestEndToEndCountryBlocking(t *testing.T) {
	dnsPort, portalPort := freePort(t), freePort(t)
	cfgPath := writeConfig(t, dnsPort, portalPort, "")
	dataDir := filepath.Join(filepath.Dir(cfgPath), "data")
	os.MkdirAll(dataDir, 0o750)
	seedCityDB(t, dataDir)

	upstream := fixedAnswerServer(t, "198.51.100.7") // placed in France by the fixture database
	body, _ := os.ReadFile(cfgPath)
	cfg := strings.Replace(string(body), "[map]\nenabled = false", "[map]\nenabled = true\ndatabase_url = \"http://127.0.0.1:1\"", 1)
	cfg = strings.Replace(cfg, `upstreams = ["192.0.2.53"]`, fmt.Sprintf(`upstreams = [%q]`, upstream), 1)
	os.WriteFile(cfgPath, []byte(cfg), 0o600)

	r := start(t, cfgPath)
	defer r.stop()
	v4 := fmt.Sprintf("127.0.0.1:%d", dnsPort)

	// Before anything is configured, the query resolves normally.
	if got := resolveA(t, v4, "site.example."); got != "198.51.100.7" {
		t.Fatalf("unblocked lookup = %q", got)
	}

	g := r.json("GET", "/api/geoblock", "", 200)
	if net, ok := g["network"].([]any); !ok || len(net) != 0 {
		t.Fatalf("fresh geoblock state = %v", g)
	}
	r.json("POST", "/api/geoblock", `{"scope":{"kind":"network","id":""},"countries":["FR"]}`, 200)

	// The local database loads in a background goroutine; poll until the
	// block takes effect.
	waitUntil(t, "the country block to take effect", func() bool { return resolveA(t, v4, "site.example.") == "0.0.0.0" })

	q := r.json("GET", "/api/queries?limit=50", "", 200)
	var sawGeo bool
	for _, e := range q["entries"].([]any) {
		em := e.(map[string]any)
		if em["name"] == "site.example" && em["action"] == "blocked" && em["reason"] == "geo" && em["geo_country"] == "FR" {
			sawGeo = true
		}
	}
	if !sawGeo {
		t.Errorf("no geo-blocked entry with country FR in the log: %v", q["entries"])
	}

	// Clearing the list unblocks it again.
	r.json("POST", "/api/geoblock", `{"scope":{"kind":"network","id":""},"countries":[]}`, 200)
	waitUntil(t, "the country block to clear", func() bool { return resolveA(t, v4, "site.example.") == "198.51.100.7" })
}

func TestEndToEndCountryBlockingNoopWithoutMap(t *testing.T) {
	dnsPort, portalPort := freePort(t), freePort(t)
	cfgPath := writeConfig(t, dnsPort, portalPort, "")
	upstream := fixedAnswerServer(t, "198.51.100.7")
	body, _ := os.ReadFile(cfgPath)
	os.WriteFile(cfgPath, []byte(strings.Replace(string(body), `upstreams = ["192.0.2.53"]`, fmt.Sprintf(`upstreams = [%q]`, upstream), 1)), 0o600)

	r := start(t, cfgPath)
	defer r.stop()
	v4 := fmt.Sprintf("127.0.0.1:%d", dnsPort)

	r.json("POST", "/api/geoblock", `{"scope":{"kind":"network","id":""},"countries":["FR"]}`, 200)
	if got := resolveA(t, v4, "site.example."); got != "198.51.100.7" {
		t.Errorf("with [map] disabled, country blocking must never engage: got %q", got)
	}
}
