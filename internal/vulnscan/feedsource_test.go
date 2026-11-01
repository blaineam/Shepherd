// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// feedServer serves whatever body is set, with an ETag, honoring
// If-None-Match, and counts requests.
type feedServer struct {
	mu   sync.Mutex
	body string
	etag string
	hits int
	ts   *httptest.Server
}

func newFeedServer(t *testing.T, body string) *feedServer {
	t.Helper()
	fs := &feedServer{body: body, etag: `"v1"`}
	fs.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		fs.hits++
		if r.Header.Get("If-None-Match") == fs.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", fs.etag)
		_, _ = w.Write([]byte(fs.body))
	}))
	t.Cleanup(fs.ts.Close)
	return fs
}

func (fs *feedServer) set(body, etag string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.body, fs.etag = body, etag
}

type changeLog struct {
	mu    sync.Mutex
	calls []struct {
		n       int
		initial bool
	}
}

func (c *changeLog) fn(sigs []Signature, initial bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, struct {
		n       int
		initial bool
	}{len(sigs), initial})
}

func TestFeedUpdaterRefreshFetchesCachesAndAppliesOnce(t *testing.T) {
	srv := newFeedServer(t, validSampleFeed())
	dir := t.TempDir()
	var log changeLog
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	u := &FeedUpdater{URL: srv.ts.URL, Path: filepath.Join(dir, "feed.json"), OnChange: log.fn, Now: func() time.Time { return now }}

	changed, err := u.Refresh(t.Context())
	if err != nil || !changed {
		t.Fatalf("first refresh: changed=%v err=%v", changed, err)
	}
	st := u.Status()
	if st.Signatures != 4 || st.Skipped != 1 || st.LastError != "" || !st.LastChecked.Equal(now) || !st.LastUpdated.Equal(now) || st.URL != srv.ts.URL {
		t.Fatalf("status = %+v", st)
	}
	if st.GeneratedAt.IsZero() {
		t.Fatal("generated_at should come from the feed document")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "feed.json")); err != nil || string(b) != validSampleFeed() {
		t.Fatalf("cache not written: %v", err)
	}
	if info, _ := os.Stat(filepath.Join(dir, "feed.json")); info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %v, want 0600", info.Mode().Perm())
	}

	// Unchanged upstream: the ETag turns into a 304 and nothing is applied.
	now = now.Add(time.Hour)
	changed, err = u.Refresh(t.Context())
	if err != nil || changed {
		t.Fatalf("second refresh: changed=%v err=%v", changed, err)
	}
	if st := u.Status(); !st.LastChecked.Equal(now) || st.LastUpdated.Equal(now) {
		t.Fatalf("a 304 should bump LastChecked only: %+v", st)
	}
	if srv.hits != 2 {
		t.Fatalf("hits = %d", srv.hits)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.calls) != 1 || log.calls[0].n != 4 || log.calls[0].initial {
		t.Fatalf("OnChange calls = %+v", log.calls)
	}
}

func TestFeedUpdaterKeepsTheOldFeedOnABadDownload(t *testing.T) {
	srv := newFeedServer(t, validSampleFeed())
	var log changeLog
	u := &FeedUpdater{URL: srv.ts.URL, Path: filepath.Join(t.TempDir(), "feed.json"), OnChange: log.fn}
	if _, err := u.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	srv.set(`{"schema": 7}`, `"v2"`)
	changed, err := u.Refresh(t.Context())
	if err == nil || changed {
		t.Fatalf("a bad feed must be rejected: changed=%v err=%v", changed, err)
	}
	st := u.Status()
	if st.Signatures != 4 || !strings.Contains(st.LastError, "schema") {
		t.Fatalf("status after bad download = %+v", st)
	}
	if b, _ := os.ReadFile(u.Path); string(b) != validSampleFeed() {
		t.Fatal("the cache must still hold the last good feed")
	}
	// A server error is reported the same way and clears on recovery.
	srv.ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	if _, err := u.Refresh(t.Context()); err == nil || !strings.Contains(u.Status().LastError, "HTTP 503") {
		t.Fatalf("503: %v / %q", err, u.Status().LastError)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.calls) != 1 {
		t.Fatalf("OnChange must not fire for a rejected feed: %+v", log.calls)
	}
}

func TestFeedUpdaterAppliesAChangedFeed(t *testing.T) {
	srv := newFeedServer(t, validSampleFeed())
	var log changeLog
	u := &FeedUpdater{URL: srv.ts.URL, OnChange: log.fn}
	if _, err := u.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	smaller := `{"schema": 1, "generated_at": "2026-11-02T06:00:00Z", "signatures": [{"id": "a", "name": "A", "severity": "low", "description": "d", "match": {"contains": "a"}}]}`
	srv.set(smaller, `"v2"`)
	changed, err := u.Refresh(t.Context())
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if st := u.Status(); st.Signatures != 1 || st.GeneratedAt.Day() != 2 {
		t.Fatalf("status = %+v", st)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.calls) != 2 || log.calls[1].n != 1 {
		t.Fatalf("calls = %+v", log.calls)
	}
}

func TestFeedUpdaterLoadRestoresTheCacheAsInitial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(path, []byte(validSampleFeed()), 0o600); err != nil {
		t.Fatal(err)
	}
	var log changeLog
	u := &FeedUpdater{URL: "http://127.0.0.1:1/never", Path: path, OnChange: log.fn}
	if err := u.Load(); err != nil {
		t.Fatal(err)
	}
	if u.Status().Signatures != 4 {
		t.Fatalf("status = %+v", u.Status())
	}
	log.mu.Lock()
	if len(log.calls) != 1 || !log.calls[0].initial {
		t.Fatalf("calls = %+v", log.calls)
	}
	log.mu.Unlock()

	// A missing cache is fine; a corrupt one is reported, not fatal.
	if err := (&FeedUpdater{Path: filepath.Join(dir, "none.json")}).Load(); err != nil {
		t.Fatalf("missing cache: %v", err)
	}
	if err := os.WriteFile(path, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&FeedUpdater{Path: path}).Load(); err == nil {
		t.Fatal("corrupt cache should be reported")
	}
	// No Path at all means nothing to load.
	if err := (&FeedUpdater{}).Load(); err != nil {
		t.Fatal(err)
	}
}

func TestFeedUpdaterReadsFileURLs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pinned.json")
	if err := os.WriteFile(path, []byte(validSampleFeed()), 0o600); err != nil {
		t.Fatal(err)
	}
	u := &FeedUpdater{URL: "file://" + path}
	changed, err := u.Refresh(t.Context())
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	// The same bytes again: not a change.
	if changed, err := u.Refresh(t.Context()); err != nil || changed {
		t.Fatalf("second: changed=%v err=%v", changed, err)
	}
	if _, err := (&FeedUpdater{URL: "file://" + path + ".missing"}).Refresh(t.Context()); err == nil {
		t.Fatal("missing file should error")
	}
	if _, err := (&FeedUpdater{}).Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "no feed URL") {
		t.Fatalf("empty URL: %v", err)
	}
}

func TestFeedUpdaterRunLoadsRefreshesAndTicks(t *testing.T) {
	srv := newFeedServer(t, validSampleFeed())
	var log changeLog
	u := &FeedUpdater{URL: srv.ts.URL, Every: 20 * time.Millisecond, OnChange: log.fn}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.Lock()
		hits := srv.hits
		srv.mu.Unlock()
		if hits >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Run did not keep refreshing: %d hits", hits)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.calls) != 1 {
		t.Fatalf("an unchanged feed must be applied exactly once: %+v", log.calls)
	}
}

func TestFeedUpdaterRunReportsACorruptCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := newFeedServer(t, validSampleFeed())
	u := &FeedUpdater{URL: srv.ts.URL, Path: path, Every: time.Hour}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && u.Status().Signatures == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	// The corrupt cache was reported, then the fetch replaced it and cleared the error.
	if st := u.Status(); st.Signatures != 4 || st.LastError != "" {
		t.Fatalf("status = %+v", st)
	}
	if b, _ := os.ReadFile(path); string(b) != validSampleFeed() {
		t.Fatal("the fetched feed should have overwritten the corrupt cache")
	}
}

func TestFeedUpdaterReportsAnUnwritableCache(t *testing.T) {
	srv := newFeedServer(t, validSampleFeed())
	u := &FeedUpdater{URL: srv.ts.URL, Path: filepath.Join(t.TempDir(), "missing-dir", "feed.json")}
	changed, err := u.Refresh(t.Context())
	if err == nil || changed || !strings.Contains(err.Error(), "caching feed") {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if u.Status().Signatures != 0 {
		t.Fatal("a feed that could not be cached must not be applied")
	}
}
