// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"shepherd/internal/config"
	"shepherd/internal/secrets"
	"shepherd/internal/setup"
)

const setupTestToken = "cmd-setup-test-token"

// scriptedSetup makes the setup server's outside edges deterministic: this
// host's own held ports and addresses would otherwise decide what the page
// offers. The real seams have tests of their own further down.
func scriptedSetup(t *testing.T) {
	t.Helper()
	setupSeams = func(s *setup.Server) {
		s.Token = setupTestToken
		s.HostAddrs = func() ([]setup.Addr, error) {
			return []setup.Addr{{Interface: "eth0", IP: "192.0.2.10"}}, nil
		}
		s.PortFree = func(string, int) bool { return true }
		s.TestUpstream = func(context.Context, string) error { return nil }
		s.ConnectRouter = func(context.Context, string, setup.RouterConn) error { return nil }
	}
	t.Cleanup(func() { setupSeams = nil })
}

const finishBody = `{"dns_listen":["192.0.2.10"],"dns_port":5353,` +
	`"upstreams":["9.9.9.10"],"portal_host":"127.0.0.1","portal_port":8787}`

// finishSetupAt completes setup over its own API, the way the page does.
func finishSetupAt(t *testing.T, port int) {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/api/setup/finish?token=%s", port, setupTestToken)
	deadline := time.Now().Add(10 * time.Second)
	for {
		res, err := http.Post(url, "application/json", strings.NewReader(finishBody))
		if err == nil {
			defer res.Body.Close()
			if res.StatusCode != 200 {
				b, _ := io.ReadAll(res.Body)
				t.Fatalf("finish = %d: %s", res.StatusCode, b)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("setup never came up on port %d: %v", port, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestSetupSubcommandServesThePageAndWritesTheConfig(t *testing.T) {
	scriptedSetup(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "shepherd.toml")
	port := freeTCPPort(t)
	var errb bytes.Buffer
	codes := make(chan int, 1)
	go func() {
		// Through realMain, because the dispatch has to happen before
		// the flags are parsed: "setup" is not a flag.
		codes <- realMain([]string{"setup", "-config", cfg, "-port", fmt.Sprint(port)}, nil, io.Discard, &errb)
	}()
	finishSetupAt(t, port)
	select {
	case code := <-codes:
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("setup did not exit after finishing")
	}
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "[dns]") {
		t.Errorf("the written config looks wrong:\n%s", b)
	}
}

func TestSetupSubcommandReportsBadFlagsAndAPortItCannotTake(t *testing.T) {
	scriptedSetup(t)
	var errb bytes.Buffer
	if code := realMain([]string{"setup", "-nope"}, nil, io.Discard, &errb); code != 2 {
		t.Errorf("an unknown flag should exit 2, got %d", code)
	}
	if code := realMain([]string{"setup", "-h"}, nil, io.Discard, &errb); code != 0 {
		t.Errorf("-h should exit 0, got %d", code)
	}
	// A port already taken on every address: the subcommand was asked for
	// this port explicitly, so it reports rather than quietly moving.
	// Held on the wildcard, since that is the bind setup itself makes.
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	errb.Reset()
	if code := realMain([]string{"setup", "-config", filepath.Join(t.TempDir(), "c.toml"), "-port", fmt.Sprint(port)}, nil, io.Discard, &errb); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "setup:") {
		t.Errorf("the failure should be reported: %q", errb.String())
	}
}

func TestAnInstallWithNoConfigIsSetUpFirstAndThenStartsOnIt(t *testing.T) {
	// The whole flow the owner sees: start Shepherd, open the address it
	// printed, finish the page, and Shepherd carries on with what was
	// written. No second start, no terminal.
	scriptedSetup(t)
	dir := tempDir(t)
	t.Chdir(dir)
	cfgPath := filepath.Join(dir, "shepherd.toml")
	port := freeTCPPort(t)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ok, err := runSetup(ctx, cfgPath, port)
		if err == nil && !ok {
			err = fmt.Errorf("setup reported nothing written")
		}
		done <- err
	}()
	finishSetupAt(t, port)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runSetup did not return after the page finished")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("the config setup wrote does not load: %v", err)
	}
	if len(cfg.DNS.Listen) != 1 || cfg.DNS.Listen[0] != "192.0.2.10:5353" {
		t.Errorf("loaded = %+v", cfg.DNS.Listen)
	}
	// An install that already has a file is never interrupted by setup.
	before := time.Now()
	setupIfUnconfigured(ctx, cfgPath)
	if time.Since(before) > 2*time.Second {
		t.Error("a configured install should not have waited for setup")
	}
}

func TestSetupMovesToAFreePortRatherThanRefusingToStart(t *testing.T) {
	// On a NAS the portal's port is often taken by something else, and
	// binding the wildcard can succeed while another process still owns
	// loopback -- so the page would answer somebody else's service.
	scriptedSetup(t)
	logs := captureLog(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	taken := l.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if ok, err := runSetup(ctx, filepath.Join(dir, "shepherd.toml"), taken); ok || err != nil {
		t.Fatalf("runSetup = %v %v", ok, err)
	}
	if !strings.Contains(logs.String(), "taking a free port instead") {
		t.Errorf("it should say why the port moved:\n%s", logs.String())
	}
}

func TestAFailedSetupListenerDoesNotStopShepherdStarting(t *testing.T) {
	// A setup page that cannot come up must not cost an install whose
	// defaults would have worked.
	scriptedSetup(t)
	logs := captureLog(t)
	setupSeams = func(s *setup.Server) { s.PortFree = func(string, int) bool { return true } }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	setupIfUnconfigured(ctx, filepath.Join(t.TempDir(), "shepherd.toml"))
	if !strings.Contains(logs.String(), "setup:") {
		t.Errorf("something should have been said:\n%s", logs.String())
	}
}

// ---- the seams setup is given --------------------------------------------

func TestTestUpstreamProbesARealResolver(t *testing.T) {
	addr := fakeResolver(t, dns.RcodeNameError)
	if err := testUpstream(context.Background(), addr); err != nil {
		t.Errorf("a resolver that answers should pass: %v", err)
	}
	// SERVFAIL is not an answer: a resolver that cannot resolve is worse
	// than none, because Shepherd would hand its failures to every device.
	if err := testUpstream(context.Background(), fakeResolver(t, dns.RcodeServerFailure)); err == nil {
		t.Error("SERVFAIL should not count as an answer")
	}
	if err := testUpstream(context.Background(), "not a resolver"); err == nil {
		t.Error("an unparseable upstream should fail")
	}
}

// fakeResolver is a UDP DNS server on loopback that answers every query with
// rcode. It stands in for a public resolver so the probe is real without
// leaving the machine.
func fakeResolver(t *testing.T, rcode int) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestConnectUniFiVerifiesBeforeItStores(t *testing.T) {
	ctrl := fakeController(t, "ro-user", "pw-9f3")
	dir := filepath.Join(t.TempDir(), "data")
	conn := setup.RouterConn{BaseURL: ctrl, Username: "ro-user", Password: "pw-9f3", Site: "default"}
	if err := connectUniFi(context.Background(), dir, conn); err != nil {
		t.Fatalf("connectUniFi: %v", err)
	}
	store, err := secrets.Open(filepath.Join(dir, secrets.FileName))
	if err != nil {
		t.Fatal(err)
	}
	u, ok := store.UniFi()
	if !ok || !u.Enabled || u.BaseURL != ctrl || u.Password != "pw-9f3" {
		t.Errorf("the controller was not stored as connected: %s", u)
	}
	info, err := os.Stat(filepath.Join(dir, secrets.FileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("secrets.json permissions: %v %v", info, err)
	}
}

func TestConnectUniFiRefusesWhatItCannotRead(t *testing.T) {
	ctrl := fakeController(t, "ro-user", "pw-9f3")
	dir := filepath.Join(t.TempDir(), "data")
	// A wrong password must fail now rather than days later, as an empty
	// Bandwidth screen nobody can explain.
	if err := connectUniFi(context.Background(), dir, setup.RouterConn{BaseURL: ctrl, Username: "ro-user", Password: "wrong"}); err == nil {
		t.Error("a refused login should fail")
	}
	if _, err := os.Stat(filepath.Join(dir, secrets.FileName)); err == nil {
		t.Error("nothing should have been stored")
	}
	if err := connectUniFi(context.Background(), dir, setup.RouterConn{BaseURL: "not a url"}); err == nil {
		t.Error("an unusable controller address should fail")
	}
	// A data directory that cannot be created is the owner's to fix, and
	// must not be reported as a controller problem.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := connectUniFi(context.Background(), filepath.Join(blocker, "data"), setup.RouterConn{
		BaseURL: ctrl, Username: "ro-user", Password: "pw-9f3"}); err == nil {
		t.Error("an unusable data directory should fail")
	}
	// And a value the store refuses (a username with a space) must not
	// pass silently just because the controller accepted the login.
	spaced := fakeController(t, "ro user", "pw-9f3")
	if err := connectUniFi(context.Background(), t.TempDir(), setup.RouterConn{
		BaseURL: spaced, Username: "ro user", Password: "pw-9f3"}); err == nil {
		t.Error("a username the store refuses should fail")
	}
}

// fakeController is the smallest self-hosted UniFi Network Application that
// internal/routerusage will log into and poll.
func fakeController(t *testing.T, user, pass string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			var in struct{ Username, Password string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Username != user || in.Password != pass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "unifises", Value: "s"})
			fmt.Fprint(w, `{"meta":{"rc":"ok"}}`)
		case "/api/s/default/stat/sta":
			fmt.Fprint(w, `{"meta":{"rc":"ok"},"data":[{"mac":"02:00:5e:11:22:33","rx_bytes":10,"tx_bytes":20}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
