// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

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
