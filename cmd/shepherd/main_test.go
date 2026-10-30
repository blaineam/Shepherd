// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestMain(m *testing.M) {
	// Cheap Argon2id for the passphrase tests; production keeps the strong defaults.
	argonTime, argonMemKiB = 1, 64
	os.Exit(m.Run())
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func writeConfig(t *testing.T, dnsPort, portalPort int, extra string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "shepherd.toml")
	body := fmt.Sprintf(`data_dir = %q
no_default_lists = true
[dns]
listen = ["127.0.0.1:%d"]
upstreams = ["192.0.2.53"]
[privacy]
block_private_relay = true
[portal]
listen = "127.0.0.1:%d"
[map]
enabled = false
[devices]
neighbors = false
mdns = false
reverse_dns = false
[arp]
enabled = false
%s`, filepath.Join(dir, "data"), dnsPort, portalPort, extra)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRealMainVersionAndFlags(t *testing.T) {
	var out, errb bytes.Buffer
	if code := realMain([]string{"-version"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "shepherd") {
		t.Errorf("-version: code %d out %q", code, out.String())
	}
	if code := realMain([]string{"-nope"}, &out, &errb); code != 2 {
		t.Errorf("unknown flag: code %d, want 2", code)
	}
	if code := realMain([]string{"-h"}, &out, &errb); code != 0 {
		t.Errorf("-h: code %d, want 0", code)
	}
}

func TestRealMainPrintTokenAndConfigErrors(t *testing.T) {
	cfg := writeConfig(t, freePort(t), freePort(t), "")
	var out, errb bytes.Buffer
	if code := realMain([]string{"-config", cfg, "-print-token"}, &out, &errb); code != 0 {
		t.Fatalf("print-token: code %d err %q", code, errb.String())
	}
	tok := strings.TrimSpace(out.String())
	if len(tok) < 32 {
		t.Errorf("token %q too short", tok)
	}
	out.Reset()
	realMain([]string{"-config", cfg, "-print-token"}, &out, &errb)
	if strings.TrimSpace(out.String()) != tok {
		t.Error("token must be stable across runs")
	}

	bad := filepath.Join(t.TempDir(), "bad.toml")
	os.WriteFile(bad, []byte("[dns]\nblock_mode = \"nope\"\n"), 0o600)
	errb.Reset()
	if code := realMain([]string{"-config", bad}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "block_mode") {
		t.Errorf("bad config: code %d err %q", code, errb.String())
	}
}

func TestRunServesDNSAndPortalThenStopsCleanly(t *testing.T) {
	dnsPort, portalPort := freePort(t), freePort(t)
	cfg := writeConfig(t, dnsPort, portalPort, "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, false, os.Stdout) }()

	// Private Relay policy comes from the config default and needs no upstream.
	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	deadline := time.Now().Add(5 * time.Second)
	var rcode = -1
	for time.Now().Before(deadline) {
		q := new(dns.Msg)
		q.SetQuestion("mask.icloud.com.", dns.TypeA)
		if r, _, err := (&dns.Client{Timeout: 500 * time.Millisecond}).Exchange(q, addr); err == nil {
			rcode = r.Rcode
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("private relay lookup rcode = %d, want NXDOMAIN", rcode)
	}

	res, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/status", portalPort))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("portal without token = %d, want 401", res.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v on clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop after cancel")
	}
}

func TestRunFailsFastOnBusyPorts(t *testing.T) {
	// DNS port already taken.
	taken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	dnsPort := taken.LocalAddr().(*net.UDPAddr).Port
	cfg := writeConfig(t, dnsPort, freePort(t), "")
	if err := run(context.Background(), cfg, false, os.Stdout); err == nil || !strings.Contains(err.Error(), "listening") {
		t.Errorf("busy dns port: err = %v", err)
	}

	// Portal port already taken: run must report it, not exit silently.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cfg = writeConfig(t, freePort(t), busy.Addr().(*net.TCPAddr).Port, "")
	if err := run(context.Background(), cfg, false, os.Stdout); err == nil || !strings.Contains(err.Error(), "portal") {
		t.Errorf("busy portal port: err = %v", err)
	}
}

func TestRunRejectsBadSetup(t *testing.T) {
	cfg := writeConfig(t, freePort(t), freePort(t), "")
	// data_dir under a regular file cannot be created.
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, []byte("x"), 0o600)
	body, _ := os.ReadFile(cfg)
	broken := strings.Replace(string(body), filepath.Dir(cfg)+"/data", file+"/data", 1)
	os.WriteFile(cfg, []byte(broken), 0o600)
	if err := run(context.Background(), cfg, false, os.Stdout); err == nil {
		t.Error("expected an error for an uncreatable data_dir")
	}

	cfg = writeConfig(t, freePort(t), freePort(t), "")
	body, _ = os.ReadFile(cfg)
	os.WriteFile(cfg, []byte(strings.Replace(string(body), `["192.0.2.53"]`, `["ftp://nope"]`, 1)), 0o600)
	if err := run(context.Background(), cfg, false, os.Stdout); err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
		t.Errorf("bad upstream scheme: err = %v", err)
	}

	cfg = writeConfig(t, freePort(t), freePort(t), "")
	dataDir := filepath.Join(filepath.Dir(cfg), "data")
	os.MkdirAll(dataDir, 0o750)
	os.WriteFile(filepath.Join(dataDir, "rules.json"), []byte("{broken"), 0o600)
	if err := run(context.Background(), cfg, false, os.Stdout); err == nil || !strings.Contains(err.Error(), "rules.json") {
		t.Errorf("corrupt rules.json: err = %v", err)
	}
}

// running starts the binary's run loop and returns helpers bound to it.
type running struct {
	t          *testing.T
	dnsAddr    string
	portalBase string
	token      string
	stop       func()
}

func start(t *testing.T, cfg string) *running {
	t.Helper()
	body, _ := os.ReadFile(cfg)
	var dnsPort, portalPort int
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "listen = [\"127.0.0.1:") {
			fmt.Sscanf(line, "listen = [\"127.0.0.1:%d", &dnsPort)
		}
		if strings.HasPrefix(line, "listen = \"127.0.0.1:") {
			fmt.Sscanf(line, "listen = \"127.0.0.1:%d", &portalPort)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, false, os.Stdout) }()
	r := &running{t: t, dnsAddr: fmt.Sprintf("127.0.0.1:%d", dnsPort), portalBase: fmt.Sprintf("http://127.0.0.1:%d", portalPort)}
	r.stop = func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("run did not stop")
		}
	}
	// wait until DNS answers, then read the token the server created
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		q := new(dns.Msg)
		q.SetQuestion("mask.icloud.com.", dns.TypeA) // answered locally; a name that went upstream would leave a slow query behind
		if _, _, err := (&dns.Client{Timeout: 300 * time.Millisecond}).Exchange(q, r.dnsAddr); err == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(cfg), "data", "portal-token"))
	if err != nil {
		t.Fatal(err)
	}
	r.token = strings.TrimSpace(string(b))
	return r
}

func (r *running) relayLookup() {
	r.t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("mask.icloud.com.", dns.TypeA)
	resp, _, err := (&dns.Client{Timeout: time.Second}).Exchange(q, r.dnsAddr)
	if err != nil || resp.Rcode != dns.RcodeNameError {
		r.t.Fatalf("relay lookup: %v %v", err, resp)
	}
}

func (r *running) api(method, path, body string) (int, string) {
	r.t.Helper()
	req, _ := http.NewRequest(method, r.portalBase+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("X-Shepherd", "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestEncryptedHistorySurvivesARestart(t *testing.T) {
	dns1, portal1 := freePort(t), freePort(t)
	keyFile := filepath.Join(t.TempDir(), "history.key")
	cfg := writeConfig(t, dns1, portal1, fmt.Sprintf("[history]\nmode = \"encrypted\"\nkey_file = %q\n", keyFile))

	first := start(t, cfg)
	first.relayLookup()
	first.stop() // shutting down flushes to disk

	second := start(t, cfg) // a fresh process, same data directory
	defer second.stop()
	code, body := second.api("GET", "/api/history?q=mask", "")
	if code != 200 || !strings.Contains(body, "mask.icloud.com") || !strings.Contains(body, `"source":"encrypted"`) {
		t.Fatalf("history after restart = %d %s", code, body)
	}
	// The live view was repopulated from the past, so the feed is not empty after a restart.
	if code, body := second.api("GET", "/api/queries?limit=50", ""); code != 200 || !strings.Contains(body, "mask.icloud.com") {
		t.Errorf("the live ring should be preloaded from history: %d %s", code, body)
	}
	// Nothing on disk is readable.
	filepath.Walk(filepath.Join(filepath.Dir(cfg), "data", "history"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("mask.icloud.com")) {
				t.Errorf("%s holds plaintext", p)
			}
		}
		return nil
	})
}

func TestPassphraseHistoryStartsLockedAndUnlocksThroughThePortal(t *testing.T) {
	cfg := writeConfig(t, freePort(t), freePort(t), "[history]\nmode = \"encrypted\"\nkey_source = \"passphrase\"\n")
	r := start(t, cfg)
	defer r.stop()
	r.relayLookup() // recorded in memory while locked

	if code, body := r.api("GET", "/api/history", ""); code != http.StatusLocked || !strings.Contains(body, `"locked":true`) {
		t.Fatalf("locked history = %d %s", code, body)
	}
	if code, _ := r.api("POST", "/api/history/unlock", `{"passphrase":""}`); code != http.StatusUnauthorized {
		t.Errorf("empty passphrase = %d", code)
	}
	if code, _ := r.api("POST", "/api/history/unlock", `{"passphrase":"first passphrase"}`); code != 200 {
		t.Fatalf("first unlock (creates the passphrase) = %d", code)
	}
	if code, body := r.api("GET", "/api/history?q=mask", ""); code != 200 || !strings.Contains(body, "mask.icloud.com") {
		t.Errorf("entries recorded while locked must appear after unlock: %d %s", code, body)
	}
	if code, body := r.api("GET", "/api/settings", ""); code != 200 || !strings.Contains(body, `"locked":false`) {
		t.Errorf("settings = %d %s", code, body)
	}
}

func TestPassphraseFromTheEnvironmentUnlocksAtStartup(t *testing.T) {
	t.Setenv("SHEPHERD_HISTORY_PASSPHRASE", "an unattended passphrase")
	cfg := writeConfig(t, freePort(t), freePort(t), "[history]\nmode = \"encrypted\"\nkey_source = \"passphrase\"\n")
	r := start(t, cfg)
	defer r.stop()
	if code, _ := r.api("GET", "/api/history", ""); code != 200 {
		t.Errorf("an environment passphrase must unlock at startup, got %d", code)
	}
}

func TestWrongEnvironmentPassphraseLeavesHistoryLocked(t *testing.T) {
	cfg := writeConfig(t, freePort(t), freePort(t), "[history]\nmode = \"encrypted\"\nkey_source = \"passphrase\"\n")
	t.Setenv("SHEPHERD_HISTORY_PASSPHRASE", "the right one")
	first := start(t, cfg)
	first.stop()
	t.Setenv("SHEPHERD_HISTORY_PASSPHRASE", "the wrong one")
	second := start(t, cfg)
	defer second.stop()
	if code, _ := second.api("GET", "/api/history", ""); code != http.StatusLocked {
		t.Errorf("a wrong passphrase must leave the history locked (and DNS running), got %d", code)
	}
}

func TestBadHistoryKeyFileStopsStartup(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "bad.key")
	os.WriteFile(keyFile, []byte("not a key"), 0o600)
	cfg := writeConfig(t, freePort(t), freePort(t), fmt.Sprintf("[history]\nmode = \"encrypted\"\nkey_file = %q\n", keyFile))
	if err := run(context.Background(), cfg, false, os.Stdout); err == nil || !strings.Contains(err.Error(), "key") {
		t.Errorf("a broken key file must stop startup rather than run unprotected: %v", err)
	}
}

func TestRunServesHTTPSWhenTLSEnabled(t *testing.T) {
	resetTLSSeams(t)
	hostname := "shepherd.example.com"
	tlsEvery = 10 * time.Millisecond
	tlsACMEClient = newFakeTLSACME(hostname)
	tlsDNS01 = &fakeTLSDNS01{}
	tlsPropagationCheck = func(context.Context, string, string) error { return nil }

	tlsPort := freePort(t)
	extra := fmt.Sprintf(`[tls]
enabled = true
hostname = %q
listen = "127.0.0.1:%d"
cloudflare_api_token = "unused-fake"
`, hostname, tlsPort)
	cfg := writeConfig(t, freePort(t), freePort(t), extra)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, false, os.Stdout) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("run did not stop")
		}
	})

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: time.Second}
	url := fmt.Sprintf("https://127.0.0.1:%d/api/status", tlsPort)
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		res, err := client.Get(url)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusUnauthorized {
				return // the HTTPS listener is up and serving the same portal handler
			}
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("HTTPS portal never came up on %s: %v", url, lastErr)
}

func TestMapAndAutoHomeStartWhenEnabled(t *testing.T) {
	cfgPath := writeConfig(t, freePort(t), freePort(t), "")
	body, _ := os.ReadFile(cfgPath)
	// enable the map but point nothing at the network: the geo manager and auto-home
	// loops must start and stop cleanly without the real database being available.
	os.WriteFile(cfgPath, []byte(strings.Replace(string(body), "[map]\nenabled = false", "[map]\nenabled = true\nauto_home = true\ndatabase_url = \"http://127.0.0.1:1\"", 1)), 0o600)
	r := start(t, cfgPath)
	if code, body := r.api("GET", "/api/settings", ""); code != 200 || !strings.Contains(body, `"auto_home":true`) || !strings.Contains(body, `"enabled":true`) {
		t.Errorf("settings with the map enabled = %d %s", code, body)
	}
	r.stop()
}
