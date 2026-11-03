// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVersionCompareMixedPrereleaseParts(t *testing.T) {
	num, _ := ParseVersion("1.0.0-1")
	word, _ := ParseVersion("1.0.0-beta")
	if num.Compare(word) != -1 || word.Compare(num) != 1 {
		t.Fatal("numeric prerelease parts sort before alphanumeric ones")
	}
	a, _ := ParseVersion("1.0.0-alpha")
	b, _ := ParseVersion("1.0.0-beta")
	if a.Compare(b) != -1 || b.Compare(a) != 1 || a.Compare(a) != 0 {
		t.Fatal("alphanumeric parts compare as strings")
	}
	rel, _ := ParseVersion("1.0.0")
	if rel.Compare(a) != 1 || a.Compare(rel) != -1 {
		t.Fatal("a release is newer than its prereleases")
	}
}

func TestCheckerAndFetcherErrors(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Write(bytes.Repeat([]byte("x"), 64))
		case "/teapot":
			w.WriteHeader(418)
		default:
			http.Error(w, "down", 503)
		}
	}))
	defer srv.Close()
	// The releases API answering with an error, and an unreachable API.
	if _, err := (Checker{Repo: "o/r", API: srv.URL, Client: srv.Client()}).Latest(ctx, ChannelStable); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("503 should surface: %v", err)
	}
	if _, err := (Checker{Repo: "o/r", API: "http://127.0.0.1:1", Client: &http.Client{Timeout: time.Second}}).Latest(ctx, ChannelBeta); err == nil {
		t.Fatal("an unreachable API should error")
	}
	if _, err := (Checker{Repo: "o/r", API: "http://[::1]:namedport"}).Latest(ctx, ChannelStable); err == nil {
		t.Fatal("a malformed API address should error")
	}
	// The fetcher: a non-200 answer, a body over the cap, a bad address.
	fetch := HTTPFetcher(srv.Client())
	if _, err := fetch(ctx, srv.URL+"/teapot", 1<<20); err == nil || !strings.Contains(err.Error(), "418") {
		t.Fatalf("418 should surface: %v", err)
	}
	if _, err := fetch(ctx, srv.URL+"/big", 16); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("over the cap: %v", err)
	}
	if _, err := fetch(ctx, "http://[::1]:namedport/x", 16); err == nil {
		t.Fatal("a malformed address should error")
	}
	if _, err := HTTPFetcher(nil)(ctx, "http://127.0.0.1:1/x", 16); err == nil {
		t.Fatal("an unreachable server should error")
	}
}

func TestExtractBinaryRefusesBadArchives(t *testing.T) {
	if _, err := extractBinary([]byte("not gzip")); err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Fatalf("plain bytes: %v", err)
	}
	var gzOnly bytes.Buffer
	gz := gzip.NewWriter(&gzOnly)
	gz.Write([]byte("this is not a tar stream, just some bytes that go on for a while"))
	gz.Close()
	if _, err := extractBinary(gzOnly.Bytes()); err == nil || !strings.Contains(err.Error(), "reading the archive") {
		t.Fatalf("gzip but not tar: %v", err)
	}
	mk := func(name string, content []byte) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg})
		tw.Write(content)
		tw.Close()
		gz.Close()
		return buf.Bytes()
	}
	if _, err := extractBinary(mk("shepherd_1.0.0/shepherd", nil)); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty binary: %v", err)
	}
	if _, err := extractBinary(mk("shepherd_1.0.0/README", []byte("hi"))); err == nil || !strings.Contains(err.Error(), "no shepherd binary") {
		t.Fatalf("no binary: %v", err)
	}
}

func TestStateAndRollbackErrors(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	os.MkdirAll(data, 0o700)
	now := time.Now()
	// update.json that cannot be read as a file.
	os.MkdirAll(StatePath(data), 0o700)
	if _, err := LoadState(data); err == nil {
		t.Fatal("a directory where the state file should be is an error")
	}
	os.Remove(StatePath(data))
	// A recorded previous binary that has since vanished.
	exe := filepath.Join(dir, "shepherd")
	os.WriteFile(exe, []byte("cur"), 0o755)
	SaveState(data, State{Applied: "1.0.1", Prev: filepath.Join(dir, "gone")})
	if err := Rollback(exe, data, ReasonAsked, now); err == nil || !strings.Contains(err.Error(), "nothing to roll back") {
		t.Fatalf("missing prev: %v", err)
	}
	// The third unconfirmed start with nothing to roll back to is an error, not a crash.
	SaveState(data, State{Applied: "1.0.1", Starts: MaxUnconfirmedStarts - 1})
	if rb, err := Startup(exe, data, "1.0.1", now); rb || err == nil {
		t.Fatalf("startup rollback without a previous binary: %v %v", rb, err)
	}
	// The running binary itself missing while a previous one exists.
	os.WriteFile(exe+".prev", []byte("old"), 0o755)
	os.Remove(exe)
	SaveState(data, State{})
	if err := Rollback(exe, data, ReasonAsked, now); err == nil {
		t.Fatal("renaming a missing binary aside should error")
	}
	if b, _ := os.ReadFile(exe + ".prev"); string(b) != "old" {
		t.Fatal("the previous binary must be left alone when the rollback fails")
	}
	// Apply where the binary's directory refuses new files.
	ro := filepath.Join(dir, "ro")
	os.MkdirAll(ro, 0o700)
	roExe := filepath.Join(ro, "shepherd")
	os.WriteFile(roExe, []byte("cur"), 0o755)
	os.Chmod(ro, 0o500)
	defer os.Chmod(ro, 0o700)
	if os.Getuid() != 0 {
		if err := Apply(roExe, data, []byte("new"), "2", now); err == nil || !strings.Contains(err.Error(), "cannot be replaced") {
			t.Fatalf("read-only directory: %v", err)
		}
	}
}

func TestRateLimitedCheckSaysSoAndWhenItResets(t *testing.T) {
	for _, reset := range []string{"1793666193", "soon"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", reset)
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := (Checker{Repo: "o/r", API: srv.URL, Client: srv.Client()}).Latest(context.Background(), ChannelStable)
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "403") {
			t.Fatalf("reset %q: %v", reset, err)
		}
		if (reset == "soon") == strings.Contains(err.Error(), "resets at") {
			t.Errorf("reset %q: %v", reset, err)
		}
	}
}
