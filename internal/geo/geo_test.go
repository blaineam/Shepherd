// SPDX-License-Identifier: AGPL-3.0-or-later

package geo

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func place(city, country string, lat, lon float64) mmdbtype.Map {
	return mmdbtype.Map{
		"city":     mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String(city)}},
		"country":  mmdbtype.Map{"iso_code": mmdbtype.String(country)},
		"location": mmdbtype.Map{"latitude": mmdbtype.Float64(lat), "longitude": mmdbtype.Float64(lon)},
	}
}

// buildDB returns the bytes of a tiny GeoIP database over documentation ranges.
func buildDB(t *testing.T, dbType string) []byte {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType, RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, rec := range map[string]mmdbtype.Map{
		"198.51.100.0/24": place("Paris", "FR", 48.8566, 2.3522),
		"203.0.113.0/24":  place("Tokyo", "JP", 35.6762, 139.6503),
		"192.0.2.0/24":    place("Nowhere", "ZZ", 0, 0), // no usable coordinates
		"2001:db8::/32":   place("Sydney", "AU", -33.8688, 151.2093),
	} {
		_, n, _ := net.ParseCIDR(cidr)
		if err := w.Insert(n, rec); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if _, err := w.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func writeDB(t *testing.T, dir string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, "geo", dbName)
	os.MkdirAll(filepath.Dir(p), 0o750)
	if err := os.WriteFile(p, b, 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLocatorFindsPlacesAndIgnoresTheRest(t *testing.T) {
	var l Locator
	if _, ok := l.Locate(net.ParseIP("198.51.100.1")); ok || l.Ready() {
		t.Fatal("an unopened locator finds nothing")
	}
	path := writeDB(t, t.TempDir(), buildDB(t, "DBIP-City-Lite"))
	if err := l.Open(path); err != nil || !l.Ready() {
		t.Fatal(err)
	}
	d, ok := l.Locate(net.ParseIP("198.51.100.77"))
	if !ok || d.City != "Paris" || d.Country != "FR" || d.Lat != 48.8566 || d.Lon != 2.3522 {
		t.Errorf("v4 lookup = %+v %v", d, ok)
	}
	if d, ok := l.Locate(net.ParseIP("2001:db8::1")); !ok || d.City != "Sydney" || d.Lat >= 0 {
		t.Errorf("v6 lookup = %+v %v", d, ok)
	}
	if d, ok := l.Locate(net.ParseIP("::ffff:203.0.113.5")); !ok || d.City != "Tokyo" {
		t.Errorf("v4-mapped lookup = %+v %v", d, ok)
	}
	if _, ok := l.Locate(net.ParseIP("198.18.0.1")); ok {
		t.Error("an unknown address must not be placed")
	}
	if _, ok := l.Locate(net.ParseIP("192.0.2.9")); ok {
		t.Error("a record without coordinates must not be placed at 0,0")
	}
	if _, ok := l.Locate(nil); ok {
		t.Error("nil is not an address")
	}
}

func TestOpenFailureKeepsThePreviousDatabase(t *testing.T) {
	var l Locator
	good := writeDB(t, t.TempDir(), buildDB(t, "DBIP-City-Lite"))
	l.Open(good)
	bad := filepath.Join(t.TempDir(), "bad.mmdb")
	os.WriteFile(bad, []byte("definitely not a database"), 0o600)
	if err := l.Open(bad); err == nil {
		t.Fatal("a corrupt database must be rejected")
	}
	if _, ok := l.Locate(net.ParseIP("198.51.100.1")); !ok {
		t.Error("the previous database must stay in use after a failed open")
	}
	// Replacing with another good database swaps cleanly.
	if err := l.Open(good); err != nil {
		t.Error(err)
	}
}

type server struct {
	*httptest.Server
	hits atomic.Int32
}

func newServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *server {
	s := &server{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func manager(t *testing.T, baseURL string, now time.Time) (*Manager, *Locator) {
	loc := &Locator{}
	m := NewManager(loc, t.TempDir())
	m.BaseURL = baseURL
	m.Now = func() time.Time { return now }
	return m, loc
}

var october = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func TestEnsureDownloadsValidatesAndLoads(t *testing.T) {
	payload := gz(t, buildDB(t, "DBIP-City-Lite"))
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dbip-city-lite-2026-10.mmdb.gz" || r.Header.Get("User-Agent") != "shepherd" {
			http.NotFound(w, r)
			return
		}
		w.Write(payload)
	})
	m, loc := manager(t, srv.URL+"/", october)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := loc.Locate(net.ParseIP("203.0.113.9")); !ok {
		t.Error("the downloaded database is not in use")
	}
	st := m.Status()
	if !st.Ready || st.Error != "" || !strings.Contains(st.Attribution, "DB-IP") || st.Updated.IsZero() {
		t.Errorf("status = %+v", st)
	}
	if _, err := os.Stat(m.path() + ".tmp"); err == nil {
		t.Error("the temporary download must be cleaned up")
	}
	// A fresh file is not downloaded again.
	before := srv.hits.Load()
	if err := m.Ensure(context.Background()); err != nil || srv.hits.Load() != before {
		t.Errorf("a fresh database must not be re-downloaded (hits %d -> %d, err %v)", before, srv.hits.Load(), err)
	}
}

func TestEnsureFallsBackToLastMonth(t *testing.T) {
	payload := gz(t, buildDB(t, "DBIP-City-Lite"))
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "2026-09") {
			w.Write(payload)
			return
		}
		http.NotFound(w, r)
	})
	m, loc := manager(t, srv.URL, october)
	if err := m.Ensure(context.Background()); err != nil || !loc.Ready() {
		t.Fatalf("fallback failed: %v", err)
	}
	if srv.hits.Load() != 2 {
		t.Errorf("expected this month then last month, got %d requests", srv.hits.Load())
	}
}

func TestEnsureReportsWhenNothingIsAvailable(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	m, loc := manager(t, srv.URL, october)
	err := m.Ensure(context.Background())
	if err == nil || loc.Ready() || m.Status().Ready || m.Status().Error == "" {
		t.Errorf("both months missing must be an error: %v %+v", err, m.Status())
	}
}

func TestServerErrorsDoNotTryAnotherMonth(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) })
	m, _ := manager(t, srv.URL, october)
	err := m.Ensure(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") || srv.hits.Load() != 1 {
		t.Errorf("a 500 is not a missing month: %v after %d requests", err, srv.hits.Load())
	}
}

func TestStaleDatabaseStaysInUseWhenRefreshFails(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", 503) })
	m, loc := manager(t, srv.URL, october)
	path := writeDB(t, m.Dir, buildDB(t, "DBIP-City-Lite"))
	old := october.Add(-60 * 24 * time.Hour)
	os.Chtimes(path, old, old)

	err := m.Ensure(context.Background())
	if err == nil {
		t.Fatal("the failed refresh must be reported")
	}
	if _, ok := loc.Locate(net.ParseIP("198.51.100.1")); !ok {
		t.Error("the stale database must keep working")
	}
	if st := m.Status(); !st.Ready || st.Error == "" {
		t.Errorf("ready with a warning expected, got %+v", st)
	}
}

func TestBadDownloadsAreRejectedAndNeverReplaceAGoodDatabase(t *testing.T) {
	good := buildDB(t, "DBIP-City-Lite")
	cases := map[string][]byte{
		"not gzip":         []byte("plain text, not gzip"),
		"gzip of garbage":  gz(t, []byte("this is not a GeoIP database")),
		"wrong db type":    gz(t, buildDB(t, "DBIP-Country-Lite")),
		"truncated stream": gz(t, good)[:40],
	}
	for name, payload := range cases {
		srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write(payload) })
		m, loc := manager(t, srv.URL, october)
		path := writeDB(t, m.Dir, good)
		old := october.Add(-60 * 24 * time.Hour)
		os.Chtimes(path, old, old)
		if err := m.Ensure(context.Background()); err == nil {
			t.Errorf("%s: a bad download must be an error", name)
		}
		if _, ok := loc.Locate(net.ParseIP("198.51.100.1")); !ok {
			t.Errorf("%s: the good database must stay in use", name)
		}
		b, _ := os.ReadFile(path)
		if !bytes.Equal(b, good) {
			t.Errorf("%s: the good database file was replaced", name)
		}
		if _, err := os.Stat(path + ".tmp"); err == nil {
			t.Errorf("%s: the rejected download must be removed", name)
		}
	}
}

func TestEnsureFailsCleanlyWhenTheDirectoryIsUnusable(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, []byte("x"), 0o600)
	m := NewManager(&Locator{}, filepath.Join(blocker, "sub"))
	if err := m.Ensure(context.Background()); err == nil || m.Status().Error == "" {
		t.Errorf("an unusable data dir must be an error: %v", err)
	}
	m2, _ := manager(t, "http://127.0.0.1:1", october) // nothing listens there
	if err := m2.Ensure(context.Background()); err == nil {
		t.Error("an unreachable server must be an error")
	}
	m3, _ := manager(t, "http://[::1", october) // malformed URL
	if err := m3.Ensure(context.Background()); err == nil {
		t.Error("a malformed URL must be an error")
	}
	// The destination path is a directory, so the download cannot be written.
	m4, _ := manager(t, "http://127.0.0.1:1", october)
	os.MkdirAll(m4.path()+".tmp", 0o750)
	_ = m4.Ensure(context.Background())
}

func TestRunEnsuresThenRechecksAndStops(t *testing.T) {
	payload := gz(t, buildDB(t, "DBIP-City-Lite"))
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write(payload) })
	m, loc := manager(t, srv.URL, october)
	m.Now = time.Now // file times are real, so the clock must be too
	m.Every = 10 * time.Millisecond
	m.MaxAge = time.Nanosecond // everything is always stale, so every tick downloads
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

func TestDefaults(t *testing.T) {
	m := NewManager(&Locator{}, t.TempDir())
	m.defaults()
	if m.BaseURL != DefaultBaseURL || m.Client == nil || m.MaxAge != 35*24*time.Hour || m.Every != 12*time.Hour || m.Now == nil {
		t.Errorf("defaults not applied: %+v", m)
	}
	if fmt.Sprint(m.path()) == "" {
		t.Error("path")
	}
}
