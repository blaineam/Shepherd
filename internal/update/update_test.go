// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVersionsParseAndOrder(t *testing.T) {
	order := []string{"0.1.0-beta.9", "0.1.0-beta.10", "0.1.0-rc.1", "0.1.0", "0.1.1", "v0.2.0-beta.1", "0.2.0", "1.0.0+build.5"}
	for i := 1; i < len(order); i++ {
		a, ok1 := ParseVersion(order[i-1])
		b, ok2 := ParseVersion(order[i])
		if !ok1 || !ok2 {
			t.Fatalf("parse %q %q", order[i-1], order[i])
		}
		if a.Compare(b) != -1 || b.Compare(a) != 1 || a.Compare(a) != 0 {
			t.Errorf("%s should be older than %s", a, b)
		}
	}
	for _, bad := range []string{"dev", "", "1.2", "x.y.z", "1.2.3.4"} {
		if _, ok := ParseVersion(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
	v, _ := ParseVersion("0.1.0-beta.3")
	if !v.Prerelease() || v.String() != "0.1.0-beta.3" {
		t.Fatalf("%+v", v)
	}
	// Prerelease parts of different length and kind.
	a, _ := ParseVersion("1.0.0-beta")
	b, _ := ParseVersion("1.0.0-beta.1")
	c, _ := ParseVersion("1.0.0-alpha.1")
	if a.Compare(b) != -1 || c.Compare(b) != -1 || b.Compare(c) != 1 {
		t.Fatal("prerelease ordering")
	}
}

func releaseServer(t *testing.T, releases string, latest string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases/latest":
			if latest == "" {
				http.Error(w, "nope", 404)
				return
			}
			w.Write([]byte(latest))
		case "/repos/o/r/releases":
			w.Write([]byte(releases))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLatestOnEachChannel(t *testing.T) {
	latest := `{"tag_name":"v0.1.0","name":"Shepherd 0.1.0","prerelease":false,"html_url":"https://example.com/r/v0.1.0","published_at":"2026-11-01T00:00:00Z","assets":[{"name":"SHA256SUMS","browser_download_url":"https://example.com/sums"}]}`
	releases := `[` + latest + `,{"tag_name":"v0.1.1-beta.12","prerelease":true,"assets":[]},{"tag_name":"v0.1.1-beta.9","prerelease":true,"assets":[]},{"tag_name":"junk","assets":[]},{"tag_name":"v9.9.9","draft":true,"assets":[]}]`
	srv := releaseServer(t, releases, latest)
	c := Checker{Repo: "o/r", API: srv.URL, Client: srv.Client()}
	stable, err := c.Latest(context.Background(), ChannelStable)
	if err != nil || stable.Version.String() != "0.1.0" || stable.Assets["SHA256SUMS"] == "" || stable.URL == "" {
		t.Fatalf("stable = %+v %v", stable, err)
	}
	beta, err := c.Latest(context.Background(), ChannelBeta)
	if err != nil || beta.Tag != "v0.1.1-beta.12" || !beta.Prerelease {
		t.Fatalf("beta = %+v %v", beta, err)
	}
	if stable.VersionString() != "0.1.0" || stable.Tag != "v0.1.0" {
		t.Fatal("VersionString")
	}
	// Failures: an HTTP error, no latest, a latest without a version, no releases.
	none := releaseServer(t, `[{"tag_name":"junk"}]`, `{"tag_name":"junk"}`)
	n := Checker{Repo: "o/r", API: none.URL, Client: none.Client()}
	if _, err := n.Latest(context.Background(), ChannelStable); err == nil {
		t.Fatal("a latest without a version should fail")
	}
	if _, err := n.Latest(context.Background(), ChannelBeta); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("no releases with a version: %v", err)
	}
	// A repository with only betas has no stable release: 404 from GitHub,
	// which is a state, not a failure.
	gone := releaseServer(t, `[]`, "")
	g := Checker{Repo: "o/r", API: gone.URL, Client: gone.Client()}
	if _, err := g.Latest(context.Background(), ChannelStable); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("404: %v", err)
	}
	if _, err := g.Latest(context.Background(), ChannelBeta); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("empty list: %v", err)
	}
	if (Checker{}).repo() != DefaultRepo || (Checker{}).api() != "https://api.github.com" || (Checker{}).client() == nil {
		t.Fatal("defaults")
	}
}

func tarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if name != "" {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg})
		tw.Write(content)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestDownloadVerifiesSumsAndSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("#!/bin/sh\necho shepherd\n")
	archive := tarGz(t, "shepherd_1.0.0_linux_amd64/shepherd", bin)
	sum := sha256.Sum256(archive)
	sums := []byte(hex.EncodeToString(sum[:]) + "  shepherd_1.0.0_linux_amd64.tar.gz\n" + strings.Repeat("0", 64) + "  shepherd_1.0.0_darwin_arm64.tar.gz\nbad line\n")
	sig := Sign(priv, sums)
	files := map[string][]byte{"/a": archive, "/sums": sums, "/sig": sig, "/bad": tarGz(t, "", nil), "/notgz": []byte("nope")}
	fetch := func(_ context.Context, url string, max int64) ([]byte, error) {
		b, ok := files[strings.TrimPrefix(url, "x:")]
		if !ok {
			return nil, errors.New("missing " + url)
		}
		if int64(len(b)) > max {
			return nil, errors.New("too big")
		}
		return b, nil
	}
	v, _ := ParseVersion("1.0.0")
	rel := Release{Version: v, Assets: map[string]string{"shepherd_1.0.0_linux_amd64.tar.gz": "x:/a", "SHA256SUMS": "x:/sums", "SHA256SUMS.sig": "x:/sig", "shepherd_1.0.0_windows_amd64.zip": "x:/a", "shepherd_1.0.0_darwin_arm64.tar.gz": "x:/notgz"}}

	got, err := Download(context.Background(), fetch, rel, "linux", "amd64", pub)
	if err != nil || !bytes.Equal(got, bin) {
		t.Fatalf("download = %q %v", got, err)
	}
	cases := map[string]func() error{
		"no build for the platform": func() error { _, err := Download(context.Background(), fetch, rel, "linux", "mips", pub); return err },
		"no key built in":           func() error { _, err := Download(context.Background(), fetch, rel, "linux", "amd64", nil); return err },
		"wrong key": func() error {
			other, _, _ := ed25519.GenerateKey(rand.Reader)
			_, err := Download(context.Background(), fetch, rel, "linux", "amd64", other)
			return err
		},
		"windows is not applied": func() error {
			_, err := Download(context.Background(), fetch, rel, "windows", "amd64", pub)
			return err
		},
		"checksum mismatch": func() error { _, err := Download(context.Background(), fetch, rel, "darwin", "arm64", pub); return err },
		"unsigned release": func() error {
			r := rel
			r.Assets = map[string]string{"shepherd_1.0.0_linux_amd64.tar.gz": "x:/a", "SHA256SUMS": "x:/sums"}
			_, err := Download(context.Background(), fetch, r, "linux", "amd64", pub)
			return err
		},
		"no sums": func() error {
			r := rel
			r.Assets = map[string]string{"shepherd_1.0.0_linux_amd64.tar.gz": "x:/a"}
			_, err := Download(context.Background(), fetch, r, "linux", "amd64", pub)
			return err
		},
		"sums fetch fails": func() error {
			r := rel
			r.Assets = map[string]string{"shepherd_1.0.0_linux_amd64.tar.gz": "x:/a", "SHA256SUMS": "x:/gone", "SHA256SUMS.sig": "x:/sig"}
			_, err := Download(context.Background(), fetch, r, "linux", "amd64", pub)
			return err
		},
		"sig fetch fails": func() error {
			r := rel
			r.Assets = map[string]string{"shepherd_1.0.0_linux_amd64.tar.gz": "x:/a", "SHA256SUMS": "x:/sums", "SHA256SUMS.sig": "x:/gone"}
			_, err := Download(context.Background(), fetch, r, "linux", "amd64", pub)
			return err
		},
		"archive fetch fails": func() error {
			r := rel
			r.Assets = map[string]string{"shepherd_1.0.0_linux_amd64.tar.gz": "x:/gone", "SHA256SUMS": "x:/sums", "SHA256SUMS.sig": "x:/sig"}
			_, err := Download(context.Background(), fetch, r, "linux", "amd64", pub)
			return err
		},
		"not in sums": func() error {
			r := rel
			r.Version, _ = ParseVersion("1.0.1")
			r.Assets = map[string]string{"shepherd_1.0.1_linux_amd64.tar.gz": "x:/a", "SHA256SUMS": "x:/sums", "SHA256SUMS.sig": "x:/sig"}
			_, err := Download(context.Background(), fetch, r, "linux", "amd64", pub)
			return err
		},
		"bad signature text": func() error { return VerifySignature(pub, sums, []byte("%%%")) },
	}
	for name, f := range cases {
		if err := f(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// Archive contents.
	if _, err := extractBinary(files["/bad"]); err == nil {
		t.Error("an archive without the binary should fail")
	}
	if _, err := extractBinary([]byte("nope")); err == nil {
		t.Error("a non-gzip archive should fail")
	}
	if _, err := extractBinary(tarGz(t, "x/shepherd", nil)); err == nil {
		t.Error("an empty binary should fail")
	}
	if got := ParseSums([]byte("deadbeef short\n")); len(got) != 0 {
		t.Error("a short digest should be ignored")
	}
	// The real fetcher: size cap and HTTP errors.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/404" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("0123456789"))
	}))
	defer srv.Close()
	hf := HTTPFetcher(srv.Client())
	if b, err := hf(context.Background(), srv.URL+"/ok", 100); err != nil || len(b) != 10 {
		t.Fatalf("fetch = %v %v", b, err)
	}
	if _, err := hf(context.Background(), srv.URL+"/ok", 5); err == nil {
		t.Fatal("the cap should refuse")
	}
	if _, err := hf(context.Background(), srv.URL+"/404", 100); err == nil {
		t.Fatal("404 should fail")
	}
	if _, err := hf(context.Background(), "http://127.0.0.1:1/x", 100); err == nil {
		t.Fatal("a refused connection should fail")
	}
	if HTTPFetcher(nil) == nil {
		t.Fatal("default fetcher")
	}
	if AssetName("1.0.0", "windows", "amd64") != "shepherd_1.0.0_windows_amd64.zip" {
		t.Fatal("asset name")
	}
}

func TestApplyRollbackAndStartup(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	os.MkdirAll(data, 0o700)
	exe := filepath.Join(dir, "shepherd")
	os.WriteFile(exe, []byte("old"), 0o755)
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

	if err := Apply(exe, data, []byte("new"), "1.0.1", now); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(exe)
	prev, _ := os.ReadFile(exe + ".prev")
	if string(cur) != "new" || string(prev) != "old" {
		t.Fatalf("after apply: %q %q", cur, prev)
	}
	fi, _ := os.Stat(exe)
	if fi.Mode().Perm()&0o100 == 0 {
		t.Fatal("the new binary must be executable")
	}
	st, err := LoadState(data)
	if err != nil || st.Applied != "1.0.1" || st.Prev != exe+".prev" || st.Confirmed {
		t.Fatalf("state = %+v %v", st, err)
	}

	// A different version starting clears the record (a manual install).
	if rb, err := Startup(exe, data, "9.9.9", now); rb || err != nil {
		t.Fatalf("other version: %v %v", rb, err)
	}
	if st, _ := LoadState(data); st.Applied != "" {
		t.Fatal("the record should be cleared")
	}
	// Apply again, then starts without a Confirm roll back on the third.
	os.WriteFile(exe, []byte("old"), 0o755)
	if err := Apply(exe, data, []byte("new"), "1.0.1", now); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < MaxUnconfirmedStarts; i++ {
		if rb, err := Startup(exe, data, "1.0.1", now); rb || err != nil {
			t.Fatalf("start %d: %v %v", i, rb, err)
		}
	}
	rb, err := Startup(exe, data, "1.0.1", now)
	if err != nil || !rb {
		t.Fatalf("third start should roll back: %v %v", rb, err)
	}
	cur, _ = os.ReadFile(exe)
	if string(cur) != "old" {
		t.Fatalf("after rollback the old binary should be back, got %q", cur)
	}
	st, _ = LoadState(data)
	if st.RolledBack != ReasonCrashed || st.Applied != "" {
		t.Fatalf("state after rollback = %+v", st)
	}
	// A confirmed update never rolls back.
	if err := Apply(exe, data, []byte("new2"), "1.0.2", now); err != nil {
		t.Fatal(err)
	}
	if err := Confirm(data); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxUnconfirmedStarts+1; i++ {
		if rb, err := Startup(exe, data, "1.0.2", now); rb || err != nil {
			t.Fatalf("confirmed start %d: %v %v", i, rb, err)
		}
	}
	if err := Confirm(data); err != nil {
		t.Fatal("confirming twice is fine")
	}
	// Explicit rollback, then nothing left to roll back to.
	if err := Rollback(exe, data, ReasonAsked, now); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(exe, data, ReasonAsked, now); err == nil {
		t.Fatal("a second rollback has nothing to restore")
	}
	// Errors: an unwritable directory, a missing binary, a corrupt state.
	if err := Writable(filepath.Join(dir, "nope", "shepherd")); err == nil {
		t.Fatal("an absent directory is not writable")
	}
	if err := Apply(filepath.Join(dir, "missing"), data, []byte("x"), "1", now); err == nil {
		t.Fatal("a missing binary cannot be replaced")
	}
	os.WriteFile(StatePath(data), []byte("{nope"), 0o600)
	if _, err := LoadState(data); err == nil {
		t.Fatal("corrupt state should error")
	}
	if _, err := Startup(exe, data, "1", now); err == nil {
		t.Fatal("startup with corrupt state should error")
	}
	if err := Confirm(data); err == nil {
		t.Fatal("confirm with corrupt state should error")
	}
	if err := Rollback(exe, data, ReasonAsked, now); err == nil {
		t.Fatal("rollback with corrupt state should error")
	}
	if err := SaveState(filepath.Join(dir, "no", "dir"), State{}); err == nil {
		t.Fatal("saving into a missing dir should error")
	}

	total, parts := DirSize(dir)
	if total == 0 || parts["data"] == 0 || parts["shepherd"] == 0 {
		t.Fatalf("DirSize = %d %v", total, parts)
	}
	if n, _ := DirSize(filepath.Join(dir, "absent")); n != 0 {
		t.Fatal("absent dir")
	}
	// A key is built in (internal/update/pubkey.go) and releases are
	// signed with its private half, so a build whose key does not decode
	// would quietly refuse every update it is offered.
	builtIn := ReleasePublicKeyB64
	defer func() { ReleasePublicKeyB64 = builtIn }()
	if len(ReleasePublicKey()) != ed25519.PublicKeySize {
		t.Fatal("the built-in release key does not decode")
	}
	ReleasePublicKeyB64 = "%%%"
	if ReleasePublicKey() != nil {
		t.Fatal("a malformed key decodes to nil")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ReleasePublicKeyB64 = base64Of(pub)
	if len(ReleasePublicKey()) != ed25519.PublicKeySize {
		t.Fatal("a real key decodes")
	}
	ReleasePublicKeyB64 = ""
	if ReleasePublicKey() != nil {
		t.Fatal("no key built in means nothing to verify against")
	}
}

func base64Of(b []byte) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		for j := 0; j < 3; j++ {
			n <<= 8
			if j < rem {
				n |= uint32(b[i+j])
			}
		}
		for j := 0; j < 4; j++ {
			if j <= rem {
				out.WriteByte(tbl[(n>>(18-6*j))&63])
			} else {
				out.WriteByte('=')
			}
		}
	}
	return out.String()
}
