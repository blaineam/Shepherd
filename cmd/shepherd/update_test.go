// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/update"
)

func updateServer(t *testing.T, latestTag string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			w.Write([]byte(`{"tag_name":"` + latestTag + `","html_url":"https://example.com/r","assets":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestStartUpdateChecksRaisesAndReportsStatus(t *testing.T) {
	srv := updateServer(t, "v99.0.0")
	oldC, oldE, oldV, oldP := updateChecker, updateEvery, version, updateExePath
	updateChecker = update.Checker{Repo: "o/r", API: srv.URL, Client: srv.Client()}
	updateEvery = time.Hour
	version = "1.0.0"
	exe := filepath.Join(tempDir(t), "shepherd")
	os.WriteFile(exe, []byte("x"), 0o755)
	updateExePath = func() (string, error) { return exe, nil }
	t.Cleanup(func() { updateChecker, updateEvery, version, updateExePath = oldC, oldE, oldV, oldP })

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u, err := startUpdate(ctx, cfg, eng)
	if err != nil || u == nil {
		t.Fatalf("startUpdate: %v %v", u, err)
	}
	var page alarms.Page
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		eng.Drain()
		page = eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeSelfUpdate}}})
		if page.Total > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if page.Total != 1 || !strings.Contains(page.Alarms[0].Title, "99.0.0") {
		t.Fatalf("update alarms = %+v", page.Alarms)
	}
	st := u.Status().(updateStatus)
	if !st.Available || st.LatestVersion != "99.0.0" || st.Current != "1.0.0" || st.Channel != "stable" || st.CanApply {
		t.Fatalf("status = %+v", st)
	}
	if !strings.Contains(st.Reason, "signing key") {
		t.Fatalf("without a built-in key the reason should say so: %q", st.Reason)
	}
	if err := u.Apply(ctx); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("apply without a key: %v", err)
	}
	// A dev build always sees the release as available and never applies.
	u2 := &updater{cfg: cfg, current: "dev", exe: u.exe, checker: updateChecker}
	u2.Check(ctx)
	if st := u2.Status().(updateStatus); !st.Available || st.CanApply || !strings.Contains(st.Reason, "development build") {
		t.Fatalf("dev status = %+v", st)
	}
	// Up to date: nothing to apply, no alarm.
	u3 := &updater{cfg: cfg, current: "99.0.0", exe: u.exe, checker: updateChecker}
	u3.version, _ = update.ParseVersion("99.0.0")
	if st := u3.CheckNow(ctx).(updateStatus); st.Available || st.CanApply || !strings.Contains(st.Reason, "up to date") {
		t.Fatalf("up to date = %+v", st)
	}
	// A failing check records the error and keeps the last release.
	bad := updateServer(t, "junk")
	u3.checker = update.Checker{Repo: "o/r", API: bad.URL, Client: bad.Client()}
	u3.Check(ctx)
	if st := u3.Status().(updateStatus); st.LastError == "" {
		t.Fatalf("a failed check should record its error: %+v", st)
	}
	// A channel with no release yet: a state the card explains, not an error.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	t.Cleanup(empty.Close)
	u5 := &updater{cfg: cfg, current: "1.0.0", exe: u.exe, checker: update.Checker{Repo: "o/r", API: empty.URL, Client: empty.Client()}}
	u5.version, _ = update.ParseVersion("1.0.0")
	if st := u5.CheckNow(ctx).(updateStatus); st.LastError != "" || st.Available || !strings.Contains(st.Reason, "no release has been published on the stable channel") {
		t.Fatalf("no release yet = %+v", st)
	}
	// Off in the configuration.
	cfg.Update.Enabled = false
	if u, err := startUpdate(ctx, cfg, nil); u != nil || err != nil {
		t.Fatalf("disabled: %v %v", u, err)
	}
	// The beta channel.
	cfg.Update.Enabled, cfg.Update.Channel = true, "beta"
	u4, _ := startUpdate(ctx, cfg, nil)
	if u4.channel() != update.ChannelBeta {
		t.Fatal("channel")
	}
}

func TestApplyDownloadsSwapsAndRestarts(t *testing.T) {
	// A full release: a signed SHA256SUMS over an archive holding the new
	// binary, served from a local server, with the key built in.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	oldKey := update.ReleasePublicKeyB64
	update.ReleasePublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { update.ReleasePublicKeyB64 = oldKey })

	dir := tempDir(t)
	exe := filepath.Join(dir, "shepherd")
	os.WriteFile(exe, []byte("old"), 0o755)
	newBin := []byte("new binary")
	archive := tarGzWith(t, "shepherd_2.0.0_linux_amd64/shepherd", newBin)
	sums := shaLine(archive, "shepherd_2.0.0_linux_amd64.tar.gz") + shaLine(archive, "shepherd_2.0.0_linux_arm64.tar.gz") + shaLine(archive, "shepherd_2.0.0_darwin_arm64.tar.gz") + shaLine(archive, "shepherd_2.0.0_darwin_amd64.tar.gz")
	sig := update.Sign(priv, []byte(sums))
	files := map[string][]byte{"/archive": archive, "/sums": []byte(sums), "/sig": sig}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			assets := ""
			for _, plat := range []string{"linux_amd64", "linux_arm64", "darwin_arm64", "darwin_amd64"} {
				assets += `{"name":"shepherd_2.0.0_` + plat + `.tar.gz","browser_download_url":"` + "http://" + r.Host + `/archive"},`
			}
			w.Write([]byte(`{"tag_name":"v2.0.0","html_url":"https://example.com/r","assets":[` + assets + `{"name":"SHA256SUMS","browser_download_url":"http://` + r.Host + `/sums"},{"name":"SHA256SUMS.sig","browser_download_url":"http://` + r.Host + `/sig"}]}`))
			return
		}
		if b, ok := files[r.URL.Path]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	oldC, oldF, oldX, oldV, oldP := updateChecker, updateFetcher, updateExec, version, updateExePath
	updateChecker = update.Checker{Repo: "o/r", API: srv.URL, Client: srv.Client()}
	updateFetcher = update.HTTPFetcher(srv.Client())
	restarted := make(chan string, 1)
	updateExec = func(path string) error { restarted <- path; return nil }
	updateExePath = func() (string, error) { return exe, nil }
	version = "1.0.0"
	t.Cleanup(func() {
		updateChecker, updateFetcher, updateExec, version, updateExePath = oldC, oldF, oldX, oldV, oldP
	})

	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	os.MkdirAll(cfg.DataDir, 0o700)
	u := &updater{cfg: cfg, current: version, exe: exe, checker: updateChecker, fetch: updateFetcher}
	u.version, _ = update.ParseVersion(version)
	u.Check(context.Background())
	if st := u.Status().(updateStatus); !st.CanApply {
		t.Fatalf("should be applicable: %+v", st)
	}
	if err := u.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(exe)
	prev, _ := os.ReadFile(exe + ".prev")
	if string(got) != "new binary" || string(prev) != "old" {
		t.Fatalf("after apply: %q %q", got, prev)
	}
	select {
	case p := <-restarted:
		if p != exe {
			t.Fatalf("restarted %s", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no restart")
	}
	if st := u.Status().(updateStatus); st.Applied != "2.0.0" || st.State.Applied != "2.0.0" || st.DataDirBytes == 0 {
		t.Fatalf("status after apply = %+v", st)
	}
	// The next start of the new binary: counted, then rolled back after
	// enough unconfirmed starts, then the -rollback flag has nothing left.
	version = "2.0.0"
	for i := 1; i < update.MaxUnconfirmedStarts; i++ {
		if err := startupRollback(cfg); err != nil {
			t.Fatal(err)
		}
	}
	if err := startupRollback(cfg); err != nil {
		t.Fatal(err)
	}
	select {
	case <-restarted:
	case <-time.After(time.Second):
		t.Fatal("the rollback should restart into the previous binary")
	}
	if got, _ := os.ReadFile(exe); string(got) != "old" {
		t.Fatalf("rolled back binary = %q", got)
	}
	if err := rollbackNow(cfg); err == nil {
		t.Fatal("nothing left to roll back")
	}
	// A corrupt update record is logged, not fatal.
	os.WriteFile(update.StatePath(cfg.DataDir), []byte("{nope"), 0o600)
	if err := startupRollback(cfg); err != nil {
		t.Fatal(err)
	}
	// A second concurrent apply is refused while one runs.
	u.mu.Lock()
	u.applying = true
	u.mu.Unlock()
	if err := u.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("concurrent apply: %v", err)
	}
}

func TestRollbackFlagThroughMain(t *testing.T) {
	dir := tempDir(t)
	cfgPath := filepath.Join(dir, "shepherd.toml")
	os.WriteFile(cfgPath, []byte("data_dir = \""+filepath.Join(dir, "data")+"\"\n"), 0o600)
	var out, errb strings.Builder
	if code := realMain([]string{"-config", cfgPath, "-rollback"}, nil, &out, &errb); code != 1 || !strings.Contains(errb.String(), "nothing to roll back") {
		t.Fatalf("rollback with nothing to restore: exit %d, %q", code, errb.String())
	}
	if code := realMain([]string{"-config", filepath.Join(dir, "missing.toml"), "-rollback"}, nil, &out, &errb); code != 1 {
		t.Fatalf("rollback with a missing config: exit %d", code)
	}
}

// tarGzWith and shaLine build a release archive and its SHA256SUMS line.
func tarGzWith(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg})
	tw.Write(content)
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func shaLine(b []byte, name string) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func TestUpdateRefusesWhereItCannotWriteAndRollsBackByHand(t *testing.T) {
	dir := tempDir(t)
	exe := filepath.Join(dir, "shepherd")
	os.WriteFile(exe, []byte("new"), 0o755)
	os.WriteFile(exe+".prev", []byte("old"), 0o755)
	oldP, oldX := updateExePath, updateExec
	updateExePath = func() (string, error) { return exe, nil }
	updateExec = func(string) error { return nil }
	t.Cleanup(func() { updateExePath, updateExec = oldP, oldX })
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	os.MkdirAll(cfg.DataDir, 0o700)

	// -rollback with a previous binary beside the running one puts it back.
	if err := rollbackNow(cfg); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old" {
		t.Fatalf("after rollback: %q", got)
	}
	if st, _ := update.LoadState(cfg.DataDir); st.RolledBack != update.ReasonAsked {
		t.Fatalf("state = %+v", st)
	}

	// With a key built in but the binary's directory read-only, the reason
	// is the directory, and apply refuses with it.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	oldKey := update.ReleasePublicKeyB64
	update.ReleasePublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { update.ReleasePublicKeyB64 = oldKey })
	u := &updater{cfg: cfg, current: "1.0.0", exe: exe}
	u.version, _ = update.ParseVersion("1.0.0")
	rel := update.Release{Tag: "v2.0.0"}
	rel.Version, _ = update.ParseVersion("2.0.0")
	u.latest = &rel
	if os.Getuid() != 0 {
		os.Chmod(dir, 0o500)
		defer os.Chmod(dir, 0o700)
		if ok, why := u.canApply(); ok || !strings.Contains(why, "cannot be replaced") {
			t.Fatalf("read-only: %v %q", ok, why)
		}
		if err := u.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "cannot be replaced") {
			t.Fatalf("apply read-only: %v", err)
		}
		os.Chmod(dir, 0o700)
	}
	// A download that fails leaves nothing applied.
	u.fetch = func(context.Context, string, int64) ([]byte, error) { return nil, errors.New("offline") }
	if err := u.Apply(context.Background()); err == nil {
		t.Fatal("a failed download is an error")
	}
	if st := u.Status().(updateStatus); st.Applied != "" || st.Applying {
		t.Fatalf("after a failed apply: %+v", st)
	}

	// startUpdate without a known executable path.
	updateExePath = func() (string, error) { return "", errors.New("unknown") }
	if _, err := startUpdate(context.Background(), cfg, nil); err == nil {
		t.Fatal("no executable path")
	}
	if err := rollbackNow(cfg); err == nil {
		t.Fatal("rollback without an executable path")
	}
	if err := startupRollback(cfg); err != nil {
		t.Fatal("startup rollback without an executable path is a no-op")
	}
}
