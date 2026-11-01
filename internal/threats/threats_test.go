// SPDX-License-Identifier: AGPL-3.0-or-later

package threats

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"shepherd/internal/dnsengine"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func TestParseReadsTheFormatsTheFeedsUse(t *testing.T) {
	d, skipped, err := Parse(KindDomain, strings.NewReader(`# comment
127.0.0.1 bad.example.com
0.0.0.0 Evil.Example.NET. ; trailing
plain.example.org
localhost
127.0.0.1 localhost.localdomain
not a domain
nodots

`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.domains, ",") != "bad.example.com,evil.example.net,plain.example.org" || skipped != 4 {
		t.Fatalf("domains = %v skipped %d", d.domains, skipped)
	}
	p, skipped, err := Parse(KindIP, strings.NewReader(`; Spamhaus DROP
192.0.2.0/24 ; SBL1
198.51.100.7
203.0.113.9/32
2001:db8::/32
garbage
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ips) != 2 || p.ips[0] != netip.MustParseAddr("198.51.100.7") || p.ips[1] != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("ips = %v", p.ips)
	}
	if len(p.prefixes) != 2 || p.prefixes[0].String() != "192.0.2.0/24" || skipped != 1 {
		t.Fatalf("prefixes = %v skipped %d", p.prefixes, skipped)
	}
	if _, _, err := Parse(Kind("weird"), strings.NewReader("x")); err == nil {
		t.Fatal("an unknown kind should fail")
	}
}

func feedServer(t *testing.T, bodies map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(b))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRefreshLoadsMatchesAndCaches(t *testing.T) {
	srv := feedServer(t, map[string]string{
		"/dom": "127.0.0.1 bad.example.com\nevil.example.net\n",
		"/ip":  "192.0.2.0/24\n198.51.100.7\n",
	})
	dir := t.TempDir()
	var matches []Match
	e := New(Options{Dir: dir, Now: func() time.Time { return t0 }, Client: srv.Client(),
		Feeds: []Feed{{ID: "d", Name: "D", Kind: KindDomain, URL: srv.URL + "/dom", Describes: "a malware host"},
			{ID: "i", Name: "I", Kind: KindIP, URL: srv.URL + "/ip", Describes: "a C2"}},
		OnMatch: func(m Match) { matches = append(matches, m) }})
	e.Refresh(context.Background())
	st := e.Status()
	if len(st) != 2 || st[0].Count != 2 || st[1].Count != 2 || st[0].Error != "" || !st[0].Updated.Equal(t0) || st[0].Bytes == 0 {
		t.Fatalf("status = %+v", st)
	}
	if e.Loaded() != 4 {
		t.Fatalf("loaded = %d", e.Loaded())
	}

	// Matching: a parent domain covers subdomains; addresses match exactly
	// or by prefix; unrelated names and addresses do not.
	hits := e.Check("x.bad.example.com", []netip.Addr{netip.MustParseAddr("192.0.2.77"), netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.1")})
	if len(hits) != 3 || hits[0].Indicator != "bad.example.com" || hits[1].Indicator != "192.0.2.0/24" || hits[2].Indicator != "198.51.100.7" {
		t.Fatalf("hits = %+v", hits)
	}
	if h := e.Check("example.com", nil); len(h) != 0 {
		t.Fatalf("example.com should not match a feed naming bad.example.com: %+v", h)
	}
	if h := e.Check("EVIL.example.NET.", []netip.Addr{netip.MustParseAddr("::ffff:198.51.100.7")}); len(h) != 2 {
		t.Fatalf("case, trailing dot and 4-in-6 should still match: %+v", h)
	}

	// Observe reports a match once per client and indicator per Quiet.
	entry := dnsengine.Entry{Client: "10.0.0.5", DeviceID: "dev1", Device: "Laptop", Name: "bad.example.com", Action: "blocked"}
	e.Observe(entry)
	e.Observe(entry)
	e.Observe(dnsengine.Entry{Client: "10.0.0.6", Name: "ok.example.org", Action: "allowed", Dests: []dnsengine.Dest{{IP: "192.0.2.9"}, {IP: "nonsense"}}})
	if len(matches) != 2 || matches[0].DeviceID != "dev1" || matches[0].Action != "blocked" || matches[1].Indicator != "192.0.2.0/24" || matches[1].Kind != KindIP {
		t.Fatalf("matches = %+v", matches)
	}
	recent := e.Recent()
	if len(recent) != 2 || recent[0].Client != "10.0.0.6" {
		t.Fatalf("recent (newest first) = %+v", recent)
	}
	if e.Describe("d") != "a malware host" || e.Describe("nope") != "a known threat" {
		t.Fatal("Describe")
	}

	// The cache feeds a fresh engine before any download.
	if _, err := os.Stat(filepath.Join(dir, "d.txt")); err != nil {
		t.Fatal("feed not cached")
	}
	f := New(Options{Dir: dir, Feeds: e.Feeds()})
	f.LoadCached()
	if f.Loaded() != 4 {
		t.Fatalf("loaded from cache = %d", f.Loaded())
	}
}

func TestRefreshKeepsThePreviousCopyOnFailure(t *testing.T) {
	var fail atomic.Bool
	var empty atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case fail.Load():
			http.Error(w, "nope", 503)
		case empty.Load():
			w.Write([]byte("# nothing today\n"))
		default:
			w.Write([]byte("bad.example.com\n"))
		}
	}))
	defer srv.Close()
	e := New(Options{Client: srv.Client(), Feeds: []Feed{{ID: "d", Kind: KindDomain, URL: srv.URL}}})
	e.Refresh(context.Background())
	if e.Loaded() != 1 {
		t.Fatal("first refresh did not load")
	}
	fail.Store(true)
	e.Refresh(context.Background())
	if e.Loaded() != 1 || !strings.Contains(e.Status()[0].Error, "HTTP 503") {
		t.Fatalf("after a failed refresh: loaded %d status %+v", e.Loaded(), e.Status()[0])
	}
	fail.Store(false)
	empty.Store(true)
	e.Refresh(context.Background())
	if e.Loaded() != 1 || !strings.Contains(e.Status()[0].Error, "empty") {
		t.Fatalf("after an empty refresh: loaded %d status %+v", e.Loaded(), e.Status()[0])
	}
	empty.Store(false)
	e.Refresh(context.Background())
	if e.Status()[0].Error != "" {
		t.Fatal("a good refresh should clear the error")
	}
	// Too large is refused; a cancelled context stops the loop.
	big := New(Options{Client: srv.Client(), MaxBytes: 4, Feeds: []Feed{{ID: "d", Kind: KindDomain, URL: srv.URL}}})
	big.Refresh(context.Background())
	if !strings.Contains(big.Status()[0].Error, "cap") {
		t.Fatalf("oversize: %+v", big.Status()[0])
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n := New(Options{Client: srv.Client(), Feeds: []Feed{{ID: "d", Kind: KindDomain, URL: srv.URL}}})
	n.Refresh(ctx)
	if n.Loaded() != 0 {
		t.Fatal("a cancelled refresh should load nothing")
	}
	// A file:// feed works for the configuration's own lists.
	path := filepath.Join(t.TempDir(), "own.txt")
	os.WriteFile(path, []byte("198.51.100.1\n"), 0o600)
	own := New(Options{Feeds: []Feed{{ID: "own", Kind: KindIP, URL: "file://" + path}}})
	own.Refresh(context.Background())
	if own.Loaded() != 1 {
		t.Fatalf("file feed: %+v", own.Status())
	}
	missing := New(Options{Feeds: []Feed{{ID: "own", Kind: KindIP, URL: "file:///nope/none.txt"}}})
	missing.Refresh(context.Background())
	if missing.Status()[0].Error == "" {
		t.Fatal("a missing file feed should record an error")
	}
}

func TestRunRefreshesOnItsInterval(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Write([]byte("bad.example.com\n"))
	}))
	defer srv.Close()
	e := New(Options{Client: srv.Client(), Feeds: []Feed{{ID: "d", Kind: KindDomain, URL: srv.URL}}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx, 20*time.Millisecond); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for n.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if n.Load() < 3 {
		t.Fatalf("refreshed %d times", n.Load())
	}
	if len(Builtin()) != 4 {
		t.Fatalf("builtin feeds = %d", len(Builtin()))
	}
	for _, f := range Builtin() {
		if f.ID == "" || f.URL == "" || f.Describes == "" || (f.Kind != KindDomain && f.Kind != KindIP) {
			t.Fatalf("builtin feed incomplete: %+v", f)
		}
	}
}

func TestObservePrunesItsQuietTableAndSkipsUnreadableCaches(t *testing.T) {
	e := New(Options{Quiet: time.Nanosecond, Now: time.Now, Feeds: []Feed{{ID: "d", Kind: KindDomain, URL: "file:///none"}}})
	e.install(Feed{ID: "d", Kind: KindDomain}, parsed{domains: []string{"bad.example.com"}}, 1, t0, nil)
	// Thousands of distinct clients fill the quiet table past its bound;
	// the next match prunes the expired entries.
	for i := 0; i < 4200; i++ {
		e.Observe(dnsengine.Entry{Client: fmt.Sprintf("192.0.%d.%d", i/250, i%250), Name: "bad.example.com", Action: "blocked"})
	}
	e.mu.RLock()
	n := len(e.lastSeen)
	e.mu.RUnlock()
	if n > 4097 {
		t.Fatalf("quiet table = %d entries, should have been pruned", n)
	}
	if len(e.Recent()) != recentMax {
		t.Fatalf("recent = %d, want the bound %d", len(e.Recent()), recentMax)
	}

	// A cache the engine cannot read or parse is skipped, never fatal.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "weird.txt"), []byte("x\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "locked.txt"), []byte("bad.example.com\n"), 0o000)
	c := New(Options{Dir: dir, Feeds: []Feed{{ID: "weird", Kind: Kind("weird")}, {ID: "locked", Kind: KindDomain}, {ID: "absent", Kind: KindDomain}}})
	c.LoadCached()
	if c.Loaded() != 0 {
		t.Fatalf("loaded %d from unreadable caches", c.Loaded())
	}
	// A cache directory that cannot be created records the error.
	blocked := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocked, []byte("x"), 0o600)
	srv := feedServer(t, map[string]string{"/d": "bad.example.com\n"})
	b := New(Options{Dir: filepath.Join(blocked, "sub"), Client: srv.Client(), Feeds: []Feed{{ID: "d", Kind: KindDomain, URL: srv.URL + "/d"}}})
	b.Refresh(context.Background())
	if b.Status()[0].Error == "" || b.Loaded() != 0 {
		t.Fatalf("an uncreatable cache dir should fail the refresh: %+v", b.Status()[0])
	}
}
