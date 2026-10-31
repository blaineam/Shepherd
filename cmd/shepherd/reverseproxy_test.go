// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"shepherd/internal/config"
	"shepherd/internal/reverseproxy"
)

// resetReverseProxySeams saves and restores every reverseproxy.go seam.
func resetReverseProxySeams(t *testing.T) {
	t.Helper()
	oldEvery, oldACME, oldDNS01, oldProp := rproxyEvery, rproxyACMEClient, rproxyDNS01, rproxyPropagationCheck
	t.Cleanup(func() {
		rproxyEvery, rproxyACMEClient, rproxyDNS01, rproxyPropagationCheck = oldEvery, oldACME, oldDNS01, oldProp
	})
}

// fakeWildcardIssuance points every reverseproxy seam at in-memory fakes:
// no test here ever reaches Let's Encrypt or Cloudflare.
func fakeWildcardIssuance(t *testing.T) *fakeTLSDNS01 {
	t.Helper()
	resetReverseProxySeams(t)
	rproxyEvery = 10 * time.Millisecond
	rproxyACMEClient = newFakeTLSACME("*.example.com")
	dns01 := &fakeTLSDNS01{}
	rproxyDNS01 = dns01
	rproxyPropagationCheck = func(context.Context, string, string) error { return nil }
	return dns01
}

func reverseProxyConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.ReverseProxy = config.ReverseProxy{Enabled: true, Listen: "127.0.0.1:0", Domain: "example.com", CloudflareAPIToken: "unused-fake"}
	return cfg
}

func openTestStore(t *testing.T, cfg config.Config) *reverseproxy.Store {
	t.Helper()
	s, err := reverseproxy.Open(filepath.Join(cfg.DataDir, "reverseproxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func backendHost(t *testing.T, domain string, backend *httptest.Server) reverseproxy.Host {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return reverseproxy.Host{Domain: domain, TargetScheme: "http", TargetHost: host, TargetPort: port, Enabled: true}
}

func waitForCert(t *testing.T, rp *reverseProxyServer) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rp.cert.Certificate() != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no wildcard certificate was obtained within the deadline")
}

func TestStartReverseProxyDisabledStartsNothing(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	rp, err := startReverseProxy(context.Background(), cfg, openTestStore(t, cfg), nil)
	if err != nil || rp != nil {
		t.Fatalf("startReverseProxy(disabled) = %v, %v; want nil, nil", rp, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "reverseproxy")); !os.IsNotExist(err) {
		t.Errorf("a disabled reverse proxy must not create anything on disk: %v", err)
	}
}

func TestStartReverseProxyServesAWildcardAndProxies(t *testing.T) {
	dns01 := fakeWildcardIssuance(t)
	cfg := reverseProxyConfig(t)
	store := openTestStore(t, cfg)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "backend saw %s %s proto=%s", r.Host, r.URL.RequestURI(), r.Header.Get("X-Forwarded-Proto"))
	}))
	t.Cleanup(backend.Close)
	if _, err := store.Add(backendHost(t, "jellyfin.example.com", backend)); err != nil {
		t.Fatal(err)
	}
	// One name too deep for the wildcard (startup warns about it) and one
	// whose backend is gone (a 502, logged by name only).
	if _, err := store.Add(backendHost(t, "deep.jellyfin.example.com", backend)); err != nil {
		t.Fatal(err)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	goneHost := backendHost(t, "gone.example.com", gone)
	gone.Close()
	if _, err := store.Add(goneHost); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rp, err := startReverseProxy(ctx, cfg, store, nil)
	if err != nil {
		t.Fatalf("startReverseProxy: %v", err)
	}
	defer rp.Close()
	waitForCert(t, rp)
	if dns01.presentCalls == 0 {
		t.Error("the DNS-01 provider was never asked to publish a record")
	}
	if leaf := rp.cert.Certificate().Leaf; leaf.Subject.CommonName != "*.example.com" {
		t.Errorf("certificate CN = %q, want *.example.com", leaf.Subject.CommonName)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "reverseproxy", "tls", "cert.pem")); err != nil {
		t.Errorf("the wildcard must persist under <data_dir>/reverseproxy/tls, apart from [tls]'s own: %v", err)
	}

	addr := rp.addr.String()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "jellyfin.example.com"})
	if err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	if err := conn.ConnectionState().PeerCertificates[0].VerifyHostname("jellyfin.example.com"); err != nil {
		t.Errorf("served certificate does not cover the proxied name: %v", err)
	}
	conn.Close()

	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	get := func(host, path string) (int, string) {
		req, _ := http.NewRequest("GET", "https://"+addr+path, nil)
		req.Host = host
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, body := get("jellyfin.example.com", "/web/?x=1"); code != 200 || body != "backend saw jellyfin.example.com /web/?x=1 proto=https" {
		t.Errorf("proxied GET = %d %q", code, body)
	}
	if code, _ := get("gone.example.com", "/"); code != http.StatusBadGateway {
		t.Errorf("a host whose backend is down = %d, want 502", code)
	}
	if code, body := get("unknown.example.com", "/"); code != 404 || strings.Contains(body, "<html") {
		t.Errorf("unknown host = %d %q, want a plain 404 and never the portal", code, body)
	}

	// Edits in the store take effect on the very next request.
	if _, err := store.Add(backendHost(t, "immich.example.com", backend)); err != nil {
		t.Fatal(err)
	}
	if code, _ := get("immich.example.com", "/"); code != 200 {
		t.Errorf("a host added while running = %d, want 200", code)
	}
}

func TestStartReverseProxyCarriesWebSockets(t *testing.T) {
	fakeWildcardIssuance(t)
	cfg := reverseProxyConfig(t)
	store := openTestStore(t, cfg)
	backend := httptest.NewServer(http.HandlerFunc(wsEchoBackend(t)))
	t.Cleanup(backend.Close)
	if _, err := store.Add(backendHost(t, "jellyfin.example.com", backend)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rp, err := startReverseProxy(ctx, cfg, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rp.Close()
	waitForCert(t, rp)
	wsRoundTrip(t, rp.addr.String(), "jellyfin.example.com")
}

// TestStartReverseProxyCertificateAlsoCoversTheBareBaseDomain proves the
// fix for a real gap: "*.example.com" alone never covers "example.com"
// itself, which is exactly the surprise a maintainer migrating a bare-apex
// host (an existing site at the root domain, not under a subdomain) onto
// this certificate would otherwise hit.
func TestStartReverseProxyCertificateAlsoCoversTheBareBaseDomain(t *testing.T) {
	fakeWildcardIssuance(t)
	cfg := reverseProxyConfig(t)
	store := openTestStore(t, cfg)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "backend saw %s", r.Host)
	}))
	t.Cleanup(backend.Close)
	if _, err := store.Add(backendHost(t, "example.com", backend)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rp, err := startReverseProxy(ctx, cfg, store, nil)
	if err != nil {
		t.Fatalf("startReverseProxy: %v", err)
	}
	defer rp.Close()
	waitForCert(t, rp)
	if leaf := rp.cert.Certificate().Leaf; !slices.Contains(leaf.DNSNames, "example.com") {
		t.Fatalf("certificate SANs = %v, want the bare base domain alongside the wildcard", leaf.DNSNames)
	}

	addr := rp.addr.String()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "example.com"})
	if err != nil {
		t.Fatalf("TLS handshake for the bare base domain: %v", err)
	}
	if err := conn.ConnectionState().PeerCertificates[0].VerifyHostname("example.com"); err != nil {
		t.Errorf("served certificate does not cover the bare base domain: %v", err)
	}
	conn.Close()

	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	req.Host = "example.com"
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(b) != "backend saw example.com" {
		t.Errorf("proxied GET to the bare base domain = %d %q", res.StatusCode, b)
	}
}

func TestStartReverseProxyRedirectsPlainHTTPToHTTPS(t *testing.T) {
	fakeWildcardIssuance(t)
	cfg := reverseProxyConfig(t)
	cfg.ReverseProxy.RedirectListen = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rp, err := startReverseProxy(ctx, cfg, openTestStore(t, cfg), nil)
	if err != nil {
		t.Fatalf("startReverseProxy: %v", err)
	}
	defer rp.Close()
	waitForCert(t, rp) // nothing may still be writing into the temp dir when the test ends
	if rp.redirectLn == nil {
		t.Fatal("RedirectListen was set but no redirect listener was started")
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", "http://"+rp.redirectLn.Addr().String()+"/web/?x=1", nil)
	req.Host = "jellyfin.example.com:" + req.URL.Port()
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusFound)
	}
	if got, want := res.Header.Get("Location"), "https://jellyfin.example.com/web/?x=1"; got != want {
		t.Errorf("Location = %q, want %q (no port, same path and query)", got, want)
	}
}

func TestStartReverseProxyRedirectListenEmptyLeavesItOff(t *testing.T) {
	fakeWildcardIssuance(t)
	cfg := reverseProxyConfig(t) // RedirectListen left at its zero value
	rp, err := startReverseProxy(context.Background(), cfg, openTestStore(t, cfg), nil)
	if err != nil {
		t.Fatalf("startReverseProxy: %v", err)
	}
	defer rp.Close()
	waitForCert(t, rp) // nothing may still be writing into the temp dir when the test ends
	if rp.redirectLn != nil || rp.redirectSrv != nil {
		t.Error("an empty RedirectListen must start no redirect listener at all")
	}
}

func TestStartReverseProxyRedirectFailsFastOnABusyPort(t *testing.T) {
	fakeWildcardIssuance(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cfg := reverseProxyConfig(t)
	cfg.ReverseProxy.RedirectListen = busy.Addr().String()
	if rp, err := startReverseProxy(context.Background(), cfg, openTestStore(t, cfg), nil); err == nil {
		rp.Close()
		t.Fatal("expected an error for a redirect_listen address already in use")
	}
}

func TestStartReverseProxyFailsFastOnABusyPort(t *testing.T) {
	fakeWildcardIssuance(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cfg := reverseProxyConfig(t)
	cfg.ReverseProxy.Listen = busy.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if rp, err := startReverseProxy(ctx, cfg, openTestStore(t, cfg), nil); err == nil {
		rp.Close()
		t.Fatal("expected an error for a listen address already in use")
	}
}

func TestStartReverseProxyNeverBlocksOnAnUnreachableCA(t *testing.T) {
	resetReverseProxySeams(t)
	rproxyEvery = time.Hour
	rproxyACMEClient = failingACME{}
	rproxyDNS01 = &fakeTLSDNS01{}
	cfg := reverseProxyConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *reverseProxyServer, 1)
	go func() {
		rp, err := startReverseProxy(ctx, cfg, openTestStore(t, cfg), nil)
		if err != nil {
			t.Errorf("startReverseProxy: %v", err)
		}
		done <- rp
	}()
	var rp *reverseProxyServer
	select {
	case rp = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("startReverseProxy blocked on an unreachable ACME server")
	}
	if rp == nil {
		return
	}
	defer rp.Close()
	// With no certificate yet the listener is up but every handshake fails.
	if conn, err := tls.Dial("tcp", rp.addr.String(), &tls.Config{InsecureSkipVerify: true, ServerName: "a.example.com"}); err == nil {
		conn.Close()
		t.Error("a handshake succeeded with no certificate obtained")
	}
}

func TestStartReverseProxyBadTokenFileFailsFast(t *testing.T) {
	resetReverseProxySeams(t) // rproxyDNS01 nil: the token is really resolved
	cfg := reverseProxyConfig(t)
	cfg.ReverseProxy.CloudflareAPIToken = ""
	cfg.ReverseProxy.CloudflareAPITokenFile = filepath.Join(t.TempDir(), "missing")
	if rp, err := startReverseProxy(context.Background(), cfg, openTestStore(t, cfg), nil); err == nil {
		rp.Close()
		t.Fatal("expected an error for a missing Cloudflare token file")
	} else if !strings.Contains(err.Error(), "reverseproxy.cloudflare_api_token_file") {
		t.Errorf("error %q should name the setting", err)
	}
}

func TestStartReverseProxyReportsAServeFailure(t *testing.T) {
	fakeWildcardIssuance(t)
	cfg := reverseProxyConfig(t)
	failed := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rp, err := startReverseProxy(ctx, cfg, openTestStore(t, cfg), func(err error) { failed <- err })
	if err != nil {
		t.Fatal(err)
	}
	waitForCert(t, rp) // nothing may still be writing into the temp dir when the test ends
	// Pull the listener out from under the server: Serve returns an error
	// that is not ErrServerClosed, which run must hear about.
	rp.ln.Close()
	select {
	case err := <-failed:
		if err == nil {
			t.Error("onFail called with nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a listener that died was never reported")
	}
	rp.Close()
}

func TestRunServesTheReverseProxyWhenEnabled(t *testing.T) {
	fakeWildcardIssuance(t)
	backend := httptest.NewServer(http.HandlerFunc(wsEchoBackend(t)))
	t.Cleanup(backend.Close)
	rpPort := freePort(t)
	// "listen=" without spaces keeps start() from mistaking this for the
	// portal's own listen line when it parses the ports back out.
	extra := fmt.Sprintf(`[reverseproxy]
enabled = true
listen="127.0.0.1:%d"
domain = "example.com"
cloudflare_api_token = "unused-fake"
`, rpPort)
	r := start(t, writeConfig(t, freePort(t), freePort(t), extra))
	defer r.stop()

	code, body := r.api("GET", "/api/reverseproxy", "")
	if code != 200 || !strings.Contains(body, `"enabled":true`) || !strings.Contains(body, `"wildcard":"*.example.com"`) {
		t.Fatalf("GET /api/reverseproxy = %d %s", code, body)
	}
	h := backendHost(t, "jellyfin.example.com", backend)
	code, body = r.api("POST", "/api/reverseproxy/hosts", fmt.Sprintf(`{"domain":%q,"target_host":%q,"target_port":%d}`, h.Domain, h.TargetHost, h.TargetPort))
	if code != 200 {
		t.Fatalf("adding a host through the portal = %d %s", code, body)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", rpPort)
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "jellyfin.example.com"})
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the reverse proxy never completed a handshake: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	wsRoundTrip(t, addr, "jellyfin.example.com")
}

func TestStopOnFailureKeepsTheFirstReasonAndCancels(t *testing.T) {
	errs := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	fail := stopOnFailure(errs, cancel)
	fail(fmt.Errorf("first"))
	fail(fmt.Errorf("second")) // must not block with the channel full
	if ctx.Err() == nil {
		t.Error("stopOnFailure did not cancel")
	}
	if err := <-errs; err.Error() != "first" {
		t.Errorf("kept %v, want the first reason", err)
	}
}

func TestRunRefusesACorruptReverseProxyFile(t *testing.T) {
	cfg := writeConfig(t, freePort(t), freePort(t), "")
	dataDir := filepath.Join(filepath.Dir(cfg), "data")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "reverseproxy.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), cfg, false, io.Discard); err == nil || !strings.Contains(err.Error(), "reverseproxy.json") {
		t.Errorf("a corrupt reverseproxy.json must stop startup rather than be overwritten later: %v", err)
	}
}

func TestRunFailsFastWhenTheReverseProxyPortIsTaken(t *testing.T) {
	fakeWildcardIssuance(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	extra := fmt.Sprintf("[reverseproxy]\nenabled = true\nlisten=%q\ndomain = \"example.com\"\ncloudflare_api_token = \"unused-fake\"\n", busy.Addr().String())
	cfg := writeConfig(t, freePort(t), freePort(t), extra)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run(ctx, cfg, false, io.Discard); err == nil || !strings.Contains(err.Error(), "reverseproxy") {
		t.Errorf("a taken reverseproxy.listen must stop startup with a clear error: %v", err)
	}
}

func TestRunLeavesTheReverseProxyOffByDefault(t *testing.T) {
	r := start(t, writeConfig(t, freePort(t), freePort(t), ""))
	defer r.stop()
	code, body := r.api("GET", "/api/reverseproxy", "")
	if code != 200 || !strings.Contains(body, `"enabled":false`) || !strings.Contains(body, `"certificate":null`) {
		t.Errorf("GET /api/reverseproxy on a default install = %d %s", code, body)
	}
}

// wsEchoBackend is the smallest honest WebSocket server: a real RFC 6455
// handshake, an unprompted first message, then an echo of each client
// frame (payloads under 126 bytes, which is all wsRoundTrip sends).
func wsEchoBackend(t *testing.T) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "upgrade expected", http.StatusBadRequest)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acceptKey(r.Header.Get("Sec-WebSocket-Key")))
		rw.Write(frame([]byte("pushed"), nil))
		rw.Flush()
		for {
			payload, err := readFrame(rw.Reader)
			if err != nil {
				return
			}
			rw.Write(frame(append([]byte("echo: "), payload...), nil))
			rw.Flush()
		}
	}
}

func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}

// frame builds one final text frame; a non-nil mask makes it a client frame.
func frame(payload, mask []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x81)
	if mask == nil {
		b.WriteByte(byte(len(payload)))
		b.Write(payload)
		return b.Bytes()
	}
	b.WriteByte(0x80 | byte(len(payload)))
	b.Write(mask)
	for i, c := range payload {
		b.WriteByte(c ^ mask[i%4])
	}
	return b.Bytes()
}

func readFrame(r *bufio.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(h[1] & 0x7f)
	if n >= 126 {
		return nil, fmt.Errorf("frame length form %d not used here", n)
	}
	var mask [4]byte
	masked := h[1]&0x80 != 0
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return nil, err
		}
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	if masked {
		for i := range p {
			p[i] ^= mask[i%4]
		}
	}
	return p, nil
}

// wsRoundTrip upgrades through the running listener the way a browser
// does and requires bytes to flow both ways after the 101.
func wsRoundTrip(t *testing.T, addr, domain string) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: domain, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var raw [16]byte
	rand.Read(raw[:])
	key := base64.StdEncoding.EncodeToString(raw[:])
	fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", domain, key)
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusSwitchingProtocols || res.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		t.Fatalf("handshake = %d accept %q", res.StatusCode, res.Header.Get("Sec-WebSocket-Accept"))
	}
	if p, err := readFrame(br); err != nil || string(p) != "pushed" {
		t.Fatalf("backend's unprompted message = %q, %v", p, err)
	}
	var mask [4]byte
	binary.BigEndian.PutUint32(mask[:], 0x5ca1ab1e)
	for _, msg := range []string{"one", "two"} {
		conn.Write(frame([]byte(msg), mask[:]))
		if p, err := readFrame(br); err != nil || string(p) != "echo: "+msg {
			t.Fatalf("echo of %q = %q, %v", msg, p, err)
		}
	}
}
