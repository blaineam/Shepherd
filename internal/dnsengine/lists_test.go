// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeList(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return "file://" + p
}

func statusOf(m *ListManager, name string) ListStatus {
	for _, s := range m.Status() {
		if s.Name == name {
			return s
		}
	}
	return ListStatus{}
}

func TestListManagerRefreshAppliesAndCaches(t *testing.T) {
	dir := t.TempDir()
	url := writeList(t, dir, "ads.txt", "0.0.0.0 ads.example\ntrack.example\n")
	f := NewFilter()
	m := NewListManager(f, dir, []ListConfig{{Name: "ads", URL: url}}, nil)
	m.Refresh(context.Background())

	if d := f.Check("x.ads.example"); !d.Blocked || d.Reason != "ads" {
		t.Errorf("list not applied: %+v", d)
	}
	st := statusOf(m, "ads")
	if st.Count != 2 || st.Error != "" || st.Updated.IsZero() {
		t.Errorf("status = %+v", st)
	}
	if listed, _, _ := f.Counts(); listed != 2 {
		t.Errorf("listed = %d, want 2", listed)
	}

	// A new manager starts offline from the cache alone.
	f2 := NewFilter()
	m2 := NewListManager(f2, dir, []ListConfig{{Name: "ads", URL: "file:///does/not/exist"}}, nil)
	m2.LoadCached()
	if !f2.Check("track.example").Blocked {
		t.Error("cached list not loaded at startup")
	}
	if statusOf(m2, "ads").Count != 2 {
		t.Errorf("cached status = %+v", statusOf(m2, "ads"))
	}
}

func TestListManagerKeepsPreviousListWhenUpdateIsRejected(t *testing.T) {
	dir := t.TempDir()
	good := make([]string, 0, 2000)
	for i := 0; i < 2000; i++ {
		good = append(good, fmt.Sprintf("d%d.example", i))
	}
	path := filepath.Join(dir, "l.txt")
	os.WriteFile(path, []byte(strings.Join(good, "\n")), 0o600)
	f := NewFilter()
	m := NewListManager(f, dir, []ListConfig{{Name: "l", URL: "file://" + path}}, nil)
	m.Refresh(context.Background())
	if !f.Check("d5.example").Blocked {
		t.Fatal("first load failed")
	}

	cases := map[string]string{
		"protected domain": "google.com\nfine.example\n",
		"shrank":           "tiny.example\n",
		"empty":            "# nothing here\n",
	}
	for want, body := range cases {
		os.WriteFile(path, []byte(body), 0o600)
		m.Refresh(context.Background())
		st := statusOf(m, "l")
		if !strings.Contains(st.Error, strings.Split(want, " ")[0]) {
			t.Errorf("%s: status error = %q", want, st.Error)
		}
		if !f.Check("d5.example").Blocked || f.Check("fine.example").Blocked {
			t.Errorf("%s: previous list must stay active and the bad one must not", want)
		}
	}
	// The cache file still holds the last good list.
	b, _ := os.ReadFile(filepath.Join(dir, "lists", "l.txt"))
	if !strings.Contains(string(b), "d5.example") {
		t.Error("a rejected update overwrote the cache")
	}
}

func TestListManagerHTTP(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "shepherd" {
			http.Error(w, "no ua", 400)
			return
		}
		fmt.Fprint(w, "web.example\n")
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) }))
	defer bad.Close()

	f := NewFilter()
	m := NewListManager(f, t.TempDir(), []ListConfig{{"ok", ok.URL}, {"bad", bad.URL}, {"gone", "http://127.0.0.1:1/x"}, {"weird", "http://[::1"}}, nil)
	m.Refresh(context.Background())

	if !f.Check("web.example").Blocked || statusOf(m, "ok").Error != "" {
		t.Errorf("http list failed: %+v", statusOf(m, "ok"))
	}
	if e := statusOf(m, "bad").Error; !strings.Contains(e, "HTTP 500") {
		t.Errorf("bad status error = %q", e)
	}
	if statusOf(m, "gone").Error == "" || statusOf(m, "weird").Error == "" {
		t.Error("unreachable and malformed URLs must record errors")
	}
}

func TestListManagerMissingFileAndUnwritableCache(t *testing.T) {
	f := NewFilter()
	m := NewListManager(f, t.TempDir(), []ListConfig{{"nofile", "file:///no/such/list.txt"}}, nil)
	m.Refresh(context.Background())
	if statusOf(m, "nofile").Error == "" {
		t.Error("missing file must record an error")
	}

	// The data dir path is a regular file, so the cache dir cannot be created.
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, []byte("x"), 0o600)
	m2 := NewListManager(f, blocker, []ListConfig{{"a", "file:///x"}}, nil)
	m2.Refresh(context.Background())
	if statusOf(m2, "a").Error == "" {
		t.Error("uncreatable cache dir must record an error")
	}
}

func TestListManagerStopsOnCancelledContext(t *testing.T) {
	f := NewFilter()
	m := NewListManager(f, t.TempDir(), []ListConfig{{"a", "file:///x"}, {"b", "file:///y"}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Refresh(ctx)
	for _, s := range m.Status() {
		if s.Error != "" || s.Count != 0 {
			t.Errorf("cancelled refresh touched %s: %+v", s.Name, s)
		}
	}
}

func TestListManagerRunLoadsRefreshesAndStops(t *testing.T) {
	dir := t.TempDir()
	url := writeList(t, dir, "r.txt", "run.example\n")
	f := NewFilter()
	m := NewListManager(f, dir, []ListConfig{{"r", url}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx, 10*time.Millisecond); close(done) }()

	deadline := time.Now().Add(3 * time.Second)
	for !f.Check("run.example").Blocked && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !f.Check("run.example").Blocked {
		t.Fatal("Run never applied the list")
	}
	time.Sleep(60 * time.Millisecond) // let the ticker refresh at least once
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestValidDomain(t *testing.T) {
	good := []string{"a.co", "sub.example.com", "x-y_z.example", "123.example"}
	bad := []string{"", "a", "localhost", "192.0.2.1", "bad domain.com", "-.", ".example.com", "a..b.com", "UPPER.com",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130) + "com"}
	for _, d := range good {
		if !ValidDomain(d) {
			t.Errorf("%q should be valid", d)
		}
	}
	for _, d := range bad {
		if ValidDomain(d) {
			t.Errorf("%q should be invalid", d)
		}
	}
}

func TestParseListReportsOversizedLines(t *testing.T) {
	_, err := ParseList(strings.NewReader(strings.Repeat("a", 2<<20)))
	if err == nil {
		t.Error("a line over the scanner limit must be an error, not silently truncated")
	}
}
