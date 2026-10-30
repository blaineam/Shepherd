// SPDX-License-Identifier: AGPL-3.0-or-later

package geo

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// buildASNDB returns the bytes of a tiny ASN database over documentation
// ranges, in the same shape as the DB-IP "IP to ASN Lite" file.
func buildASNDB(t *testing.T, dbType string) []byte {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType, RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	rec := func(n uint32, org string) mmdbtype.Map {
		return mmdbtype.Map{
			"autonomous_system_number":       mmdbtype.Uint32(n),
			"autonomous_system_organization": mmdbtype.String(org),
		}
	}
	for cidr, r := range map[string]mmdbtype.Map{
		"198.51.100.0/24": rec(64500, "Example Streaming Inc."),
		"203.0.113.0/24":  rec(64501, "Example Cloud LLC"),
		"192.0.2.0/24":    rec(0, "Unassigned"), // a record with no AS number
		"2001:db8::/32":   rec(64502, "Example Net"),
	} {
		_, n, _ := net.ParseCIDR(cidr)
		if err := w.Insert(n, r); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if _, err := w.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeASNDB(t *testing.T, dir string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, "geo", asnDBName)
	os.MkdirAll(filepath.Dir(p), 0o750)
	if err := os.WriteFile(p, b, 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func asnManager(t *testing.T, baseURL string, now time.Time) (*ASNManager, *ASNLocator) {
	loc := &ASNLocator{}
	m := NewASNManager(loc, t.TempDir())
	m.BaseURL = baseURL
	m.Now = func() time.Time { return now }
	return m, loc
}

func TestASNLocatorFindsNetworksAndIgnoresTheRest(t *testing.T) {
	var l ASNLocator
	if _, ok := l.Lookup(net.ParseIP("198.51.100.1")); ok || l.Ready() {
		t.Fatal("an unopened locator finds nothing")
	}
	if err := l.Open(writeASNDB(t, t.TempDir(), buildASNDB(t, "DBIP-ASN-Lite"))); err != nil || !l.Ready() {
		t.Fatal(err)
	}
	a, ok := l.Lookup(net.ParseIP("198.51.100.77"))
	if !ok || a.Number != 64500 || a.Org != "Example Streaming Inc." {
		t.Errorf("v4 lookup = %+v %v", a, ok)
	}
	if a, ok := l.Lookup(net.ParseIP("2001:db8::1")); !ok || a.Number != 64502 {
		t.Errorf("v6 lookup = %+v %v", a, ok)
	}
	if a, ok := l.Lookup(net.ParseIP("::ffff:203.0.113.5")); !ok || a.Number != 64501 {
		t.Errorf("v4-mapped lookup = %+v %v", a, ok)
	}
	if a, ok := l.LookupAddr(netip.MustParseAddr("::ffff:203.0.113.6")); !ok || a.Org != "Example Cloud LLC" {
		t.Errorf("LookupAddr = %+v %v", a, ok)
	}
	if _, ok := l.Lookup(net.ParseIP("198.18.0.1")); ok {
		t.Error("an unknown address has no network")
	}
	if _, ok := l.Lookup(net.ParseIP("192.0.2.9")); ok {
		t.Error("a record without an AS number is not an answer")
	}
	if _, ok := l.Lookup(nil); ok {
		t.Error("nil is not an address")
	}
}

func TestASNOpenFailureKeepsThePreviousDatabase(t *testing.T) {
	var l ASNLocator
	good := writeASNDB(t, t.TempDir(), buildASNDB(t, "DBIP-ASN-Lite"))
	l.Open(good)
	bad := filepath.Join(t.TempDir(), "bad.mmdb")
	os.WriteFile(bad, []byte("definitely not a database"), 0o600)
	if err := l.Open(bad); err == nil {
		t.Fatal("a corrupt database must be rejected")
	}
	if _, ok := l.Lookup(net.ParseIP("198.51.100.1")); !ok {
		t.Error("the previous database must stay in use after a failed open")
	}
	if err := l.Open(good); err != nil {
		t.Error(err)
	}
}

func TestASNEnsureDownloadsValidatesAndLoads(t *testing.T) {
	payload := gz(t, buildASNDB(t, "DBIP-ASN-Lite (compat=GeoLite2-ASN)"))
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dbip-asn-lite-2026-10.mmdb.gz" || r.Header.Get("User-Agent") != "shepherd" {
			http.NotFound(w, r)
			return
		}
		w.Write(payload)
	})
	m, loc := asnManager(t, srv.URL+"/", october)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a, ok := loc.Lookup(net.ParseIP("203.0.113.9")); !ok || a.Number != 64501 {
		t.Error("the downloaded database is not in use")
	}
	st := m.Status()
	if !st.Ready || st.Error != "" || st.Attribution != ASNAttribution || !strings.Contains(st.Attribution, "DB-IP") || st.Updated.IsZero() {
		t.Errorf("status = %+v", st)
	}
	if _, err := os.Stat(m.path() + ".tmp"); err == nil {
		t.Error("the temporary download must be cleaned up")
	}
	before := srv.hits.Load()
	if err := m.Ensure(context.Background()); err != nil || srv.hits.Load() != before {
		t.Errorf("a fresh database must not be re-downloaded (hits %d -> %d, err %v)", before, srv.hits.Load(), err)
	}
}

func TestASNEnsureFallsBackToLastMonth(t *testing.T) {
	payload := gz(t, buildASNDB(t, "DBIP-ASN-Lite"))
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "2026-09") {
			w.Write(payload)
			return
		}
		http.NotFound(w, r)
	})
	m, loc := asnManager(t, srv.URL, october)
	if err := m.Ensure(context.Background()); err != nil || !loc.Ready() {
		t.Fatalf("fallback failed: %v", err)
	}
	if srv.hits.Load() != 2 {
		t.Errorf("expected this month then last month, got %d requests", srv.hits.Load())
	}
}

func TestASNEnsureReportsFailures(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	m, loc := asnManager(t, srv.URL, october)
	if err := m.Ensure(context.Background()); err == nil || loc.Ready() || m.Status().Ready || m.Status().Error == "" {
		t.Errorf("both months missing must be an error: %v %+v", err, m.Status())
	}
	boom := newServer(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) })
	m2, _ := asnManager(t, boom.URL, october)
	if err := m2.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "ASN data download failed: HTTP 500") || boom.hits.Load() != 1 {
		t.Errorf("a 500 is not a missing month: %v after %d requests", err, boom.hits.Load())
	}
}

func TestASNBadDownloadsAreRejectedAndNeverReplaceAGoodDatabase(t *testing.T) {
	good := buildASNDB(t, "DBIP-ASN-Lite")
	cases := map[string][]byte{
		"not gzip":        []byte("plain text, not gzip"),
		"gzip of garbage": gz(t, []byte("this is not a GeoIP database")),
		// A real, well-formed database of the wrong kind must not be trusted.
		"city database":    gz(t, buildDB(t, "DBIP-City-Lite")),
		"truncated stream": gz(t, good)[:40],
	}
	for name, payload := range cases {
		srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write(payload) })
		m, loc := asnManager(t, srv.URL, october)
		path := writeASNDB(t, m.Dir, good)
		old := october.Add(-60 * 24 * time.Hour)
		os.Chtimes(path, old, old)
		err := m.Ensure(context.Background())
		if err == nil {
			t.Errorf("%s: a bad download must be an error", name)
		}
		if name == "city database" && (err == nil || !strings.Contains(err.Error(), "not a ASN database")) {
			t.Errorf("%s: error should name the mismatch, got %v", name, err)
		}
		if _, ok := loc.Lookup(net.ParseIP("198.51.100.1")); !ok {
			t.Errorf("%s: the good database must stay in use", name)
		}
		if b, _ := os.ReadFile(path); !bytes.Equal(b, good) {
			t.Errorf("%s: the good database file was replaced", name)
		}
		if _, err := os.Stat(path + ".tmp"); err == nil {
			t.Errorf("%s: the rejected download must be removed", name)
		}
	}
}

func TestCityManagerRejectsAnASNDatabase(t *testing.T) {
	payload := gz(t, buildASNDB(t, "DBIP-ASN-Lite"))
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write(payload) })
	m, loc := manager(t, srv.URL, october)
	err := m.Ensure(context.Background())
	if err == nil || loc.Ready() || !strings.Contains(err.Error(), "not a city database") {
		t.Errorf("an ASN database must never load as the map: %v", err)
	}
}

func TestASNStaleDatabaseStaysInUseWhenRefreshFails(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", 503) })
	m, loc := asnManager(t, srv.URL, october)
	path := writeASNDB(t, m.Dir, buildASNDB(t, "DBIP-ASN-Lite"))
	old := october.Add(-60 * 24 * time.Hour)
	os.Chtimes(path, old, old)
	if err := m.Ensure(context.Background()); err == nil {
		t.Fatal("the failed refresh must be reported")
	}
	if _, ok := loc.Lookup(net.ParseIP("198.51.100.1")); !ok {
		t.Error("the stale database must keep working")
	}
	if st := m.Status(); !st.Ready || st.Error == "" {
		t.Errorf("ready with a warning expected, got %+v", st)
	}
}

func TestASNEnsureFailsCleanlyWhenTheDirectoryIsUnusable(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, []byte("x"), 0o600)
	m := NewASNManager(&ASNLocator{}, filepath.Join(blocker, "sub"))
	if err := m.Ensure(context.Background()); err == nil || m.Status().Error == "" {
		t.Errorf("an unusable data dir must be an error: %v", err)
	}
	m2, _ := asnManager(t, "http://127.0.0.1:1", october)
	if err := m2.Ensure(context.Background()); err == nil {
		t.Error("an unreachable server must be an error")
	}
	m3, _ := asnManager(t, "http://[::1", october)
	if err := m3.Ensure(context.Background()); err == nil {
		t.Error("a malformed URL must be an error")
	}
	m4, _ := asnManager(t, "http://127.0.0.1:1", october)
	os.MkdirAll(m4.path()+".tmp", 0o750)
	_ = m4.Ensure(context.Background())
}

func TestASNRunEnsuresThenRechecksAndStops(t *testing.T) {
	payload := gz(t, buildASNDB(t, "DBIP-ASN-Lite"))
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write(payload) })
	m, loc := asnManager(t, srv.URL, october)
	m.Now = time.Now
	m.Every = 10 * time.Millisecond
	m.MaxAge = time.Nanosecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for srv.hits.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
	if srv.hits.Load() < 3 || !loc.Ready() {
		t.Errorf("Run must refresh on its interval: %d downloads", srv.hits.Load())
	}
}

func TestASNManagerDefaults(t *testing.T) {
	m := NewASNManager(&ASNLocator{}, t.TempDir())
	m.defaults()
	if m.BaseURL != DefaultBaseURL || m.Client == nil || m.MaxAge != 35*24*time.Hour || m.Every != 12*time.Hour || m.Now == nil {
		t.Errorf("defaults not applied: %+v", m.feed.BaseURL)
	}
	if !strings.HasSuffix(m.path(), filepath.Join("geo", "dbip-asn-lite.mmdb")) {
		t.Errorf("path = %s", m.path())
	}
	// Both databases live side by side without clobbering each other.
	c := NewManager(&Locator{}, m.Dir)
	if c.path() == m.path() {
		t.Error("the city and ASN databases must not share a file")
	}
}
