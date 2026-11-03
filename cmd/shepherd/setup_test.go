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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"shepherd/internal/config"
	"shepherd/internal/dnsengine"
	"shepherd/internal/secrets"
	"shepherd/internal/selftest"
	"shepherd/internal/setup"
	"shepherd/internal/tlscert"
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

// finishSetup completes setup over its own API, the way the page does.
func finishSetup(t *testing.T, base string) {
	t.Helper()
	// Retried, because a shared CI runner can drop the first connection
	// to a listener that has only just come up.
	deadline := time.Now().Add(10 * time.Second)
	for {
		res, err := http.Post(base+"/api/setup/finish?token="+setupTestToken, "application/json", strings.NewReader(finishBody))
		if err == nil {
			defer res.Body.Close()
			if res.StatusCode != 200 {
				b, _ := io.ReadAll(res.Body)
				t.Fatalf("finish = %d: %s", res.StatusCode, b)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("finishing setup at %s: %v", base, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// setupURL waits for setup to come up and returns its loopback address.
// The port is read back rather than guessed: setup picks a free one when
// the preferred port is taken, and a port that was free a moment ago can
// be gone by the time it binds.
func setupURL(t *testing.T, port func() string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if p := port(); p != "" {
			base := "http://127.0.0.1:" + p
			res, err := http.Get(base + "/?token=" + setupTestToken)
			if err == nil {
				res.Body.Close()
				return base
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("setup never came up")
	return ""
}

// portFromLog reads the port out of the address setup printed, which is
// where the owner reads it too. The most recent one: the captured log is
// the whole process's, and another test's setup server may have printed
// its own address into it and since gone away.
func portFromLog(logs fmt.Stringer) func() string {
	re := regexp.MustCompile(`http://127\.0\.0\.1:(\d+)/\?token=` + setupTestToken)
	return func() string {
		ms := re.FindAllStringSubmatch(logs.String(), -1)
		if len(ms) == 0 {
			return ""
		}
		return ms[len(ms)-1][1]
	}
}

func TestSetupSubcommandServesThePageAndWritesTheConfig(t *testing.T) {
	scriptedSetup(t)
	logs := captureLog(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "shepherd.toml")
	var errb bytes.Buffer
	codes := make(chan int, 1)
	go func() {
		// Through realMain, because the dispatch has to happen before
		// the flags are parsed: "setup" is not a flag. Port 0 lets the
		// operating system pick, and the address is read back from what
		// setup printed.
		codes <- realMain([]string{"setup", "-config", cfg, "-port", "0"}, nil, io.Discard, &errb)
	}()
	finishSetup(t, setupURL(t, portFromLog(logs)))
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
	// A port that is not a port is the owner's typo and is reported. (A
	// port merely in use is not this case: setup moves to a free one,
	// which TestSetupMovesToAFreePortRatherThanRefusingToStart covers.
	// Whether binding the wildcard succeeds while another process holds
	// one address of it differs between operating systems, so it is not
	// something to assert on.)
	errb.Reset()
	if code := realMain([]string{"setup", "-config", filepath.Join(t.TempDir(), "c.toml"), "-port", "99999"}, nil, io.Discard, &errb); code != 1 {
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
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := newSetupServer(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		written, err := serveSetup(ctx, srv, 0)
		if err == nil && written == "" {
			err = fmt.Errorf("setup reported nothing written")
		}
		done <- err
	}()
	finishSetup(t, setupURL(t, srv.Port))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveSetup did not return after the page finished")
	}
	// It is still serving: the second half of the page happens while
	// Shepherd starts.
	if _, err := http.Get("http://127.0.0.1:" + srv.Port() + "/"); err != nil {
		t.Errorf("the setup page should still be up: %v", err)
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
	srv, err := newSetupServer(filepath.Join(dir, "shepherd.toml"))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if written, err := serveSetup(ctx, srv, taken); written != "" || err != nil {
		t.Fatalf("serveSetup = %q %v", written, err)
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

func TestTheSetupPageIsHandedTheRunningShepherd(t *testing.T) {
	// What the second half of the page needs: a portal to link to and
	// sign into, a way to prove filtering works, and the catalog
	// categories it offered being real.
	dir := tempDir(t)
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.Portal.Listen = "127.0.0.1:8787"
	cfg.DNS.Listen = []string{"127.0.0.1:1"} // nothing has to be listening

	filter := dnsengine.NewFilter()
	policy, err := dnsengine.OpenPolicyStore(filepath.Join(dir, "policy.json"), filter, dnsengine.PolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	run := runningSetup(cfg, "a-token", policy, &skipSet{}, nil)
	if run.PortalURL != "http://127.0.0.1:8787" || run.Token != "a-token" {
		t.Errorf("running = %+v", run)
	}
	if run.Verify == nil || run.SetCategories == nil {
		t.Fatal("the page needs both to do its second half")
	}
	// A category chosen on the page is switched on in the policy the
	// portal owns from now on, not copied into the config file.
	if err := run.SetCategories([]string{"adult"}); err != nil {
		t.Fatal(err)
	}
	snap := policy.Snapshot()
	if !snap.Network.Items["adult"] {
		t.Errorf("adult was not switched on at network scope: %+v", snap.Network.Items)
	}
	if err := run.SetCategories([]string{"no-such-category"}); err == nil {
		t.Error("a category the catalog does not have should be reported")
	}
}

func TestVerifyDNSAsksShepherdsOwnListeners(t *testing.T) {
	// Not a second implementation: it runs the same self-test the portal
	// shows later, so setup cannot call something working that the portal
	// will call broken an hour from now.
	cfg := config.Default()
	cfg.DNS.Listen = []string{"127.0.0.1:1"} // nothing is listening there
	checks := verifyDNS(cfg, &skipSet{})(context.Background())
	if len(checks) == 0 {
		t.Fatal("a listener that answers nothing is still a result")
	}
	for _, c := range checks {
		if c.Answers {
			t.Errorf("%+v should not have answered", c)
		}
		if c.Proto != "udp" && c.Proto != "tcp" {
			t.Errorf("both protocols are checked, got %q", c.Proto)
		}
	}
	// An address Shepherd could not bind is left out rather than reported
	// as broken: startup already tolerated it on purpose.
	skipped := &skipSet{}
	// Including the loopback addresses Shepherd adds by itself, which are
	// part of what it tried to bind.
	for _, a := range cfg.DNS.ListenAddrs() {
		skipped.add(a)
	}
	if got := verifyDNS(cfg, skipped)(context.Background()); len(got) != 0 {
		t.Errorf("a skipped address should not be checked: %+v", got)
	}
}

func TestChecksFromFlattensASelfTestReport(t *testing.T) {
	got := checksFrom(selftest.Report{Listeners: []selftest.ListenerResult{{
		Addr: "192.0.2.10:53",
		Probes: []selftest.Probe{
			{Proto: "udp", Check: "listener", OK: true},
			{Proto: "udp", Check: "resolve", OK: true},
			{Proto: "udp", Check: "block", OK: false, Detail: "it answered an address"},
			{Proto: "tcp", Check: "listener", OK: true},
			{Proto: "tcp", Check: "resolve", OK: true},
			{Proto: "tcp", Check: "block", OK: true},
		},
	}}})
	if len(got) != 2 {
		t.Fatalf("checks = %+v", got)
	}
	if got[0].Proto != "udp" || got[0].Blocks || got[0].Detail != "it answered an address" {
		t.Errorf("udp = %+v", got[0])
	}
	if got[1].Proto != "tcp" || !got[1].Blocks || !got[1].Resolve {
		t.Errorf("tcp = %+v", got[1])
	}
}

func TestTheOfferedCategoriesExistInTheShippedCatalog(t *testing.T) {
	cats := setupCategories()
	if len(cats) < 5 {
		t.Fatalf("only %d categories offered", len(cats))
	}
	suggested := 0
	for _, c := range cats {
		e, ok := dnsengine.CatalogByID(c.ID)
		if !ok || e.Kind != dnsengine.KindCategory {
			t.Errorf("%s is not a category in the shipped catalog", c.ID)
		}
		if c.Name == "" || c.Description == "" {
			t.Errorf("%+v needs something to show", c)
		}
		if c.Suggested {
			suggested++
		}
	}
	// The ticked ones are the two nobody argues with; everything else is
	// the owner's call.
	if suggested != 2 {
		t.Errorf("%d suggested, want 2", suggested)
	}
}

func TestApplyCategoriesWithoutAPolicyIsNothingToOffer(t *testing.T) {
	if applyCategories(nil) != nil {
		t.Error("no policy store means the page should not offer blocking")
	}
}

func TestSetupKeepsAWorkingCloudflareTokenAndRefusesABadOne(t *testing.T) {
	// HTTPS is what makes a passkey possible at all, and the one thing
	// about it that can fail silently is a token without edit rights on
	// the zone. Setup checks it while the owner is still on the page.
	const good = "cf-setup-token-good"
	newFakeCF(t, good)
	dir := filepath.Join(t.TempDir(), "data")

	if err := saveSetupDNSToken(context.Background(), dir, "shepherd.example.com", good); err != nil {
		t.Fatalf("a token that can edit the zone should be kept: %v", err)
	}
	store, err := secrets.Open(filepath.Join(dir, secrets.FileName))
	if err != nil {
		t.Fatal(err)
	}
	d, ok := store.DNSProvider()
	if !ok || d.APIToken != good || d.Provider != secrets.ProviderCloudflare {
		t.Errorf("the token was not kept as the portal's own: %s", d)
	}

	// A token Cloudflare refuses is reported, and nothing is stored.
	fresh := filepath.Join(t.TempDir(), "data")
	err = saveSetupDNSToken(context.Background(), fresh, "shepherd.example.com", "cf-setup-token-bad")
	if err == nil || !strings.Contains(err.Error(), "did not accept") {
		t.Errorf("a refused token = %v", err)
	}
	if _, err := os.Stat(filepath.Join(fresh, secrets.FileName)); err == nil {
		t.Error("nothing should have been stored for a refused token")
	}

	// A zone the token cannot see is the same kind of failure, caught the
	// same way: this is what a token scoped to the wrong zone looks like.
	err = saveSetupDNSToken(context.Background(), fresh, "shepherd.example.net", good)
	if err == nil {
		t.Error("a hostname outside the token's zone should be refused")
	}
}

func TestRunningSetupOffersHTTPSOnlyWhenItIsConfigured(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	if r := runningSetup(cfg, "tok", nil, &skipSet{}, nil); r.TLSURL != "" || r.CertReady != nil {
		t.Errorf("with [tls] off there is no HTTPS to offer: %+v", r)
	}
	cfg.TLS = config.TLS{Enabled: true, Hostname: "shepherd.example.com", Listen: "0.0.0.0:8443"}
	r := runningSetup(cfg, "tok", nil, &skipSet{}, nil)
	if r.TLSURL != "https://shepherd.example.com:8443" {
		t.Errorf("TLSURL = %q", r.TLSURL)
	}
	// No manager means HTTPS was configured but did not start, which the
	// page has to say rather than waiting for a certificate for ever.
	ready, detail := r.CertReady()
	if ready || !strings.Contains(detail, "did not start") {
		t.Errorf("CertReady with no manager = %v %q", ready, detail)
	}
}

func TestCertReadyWaitsThenReports(t *testing.T) {
	mgr := &tlscert.Manager{}
	ready, detail := certReady(mgr, "shepherd.example.com")()
	if ready {
		t.Error("no certificate yet")
	}
	// The wait is explained, with the two things that actually hold it up.
	if !strings.Contains(detail, "DNS-01") || !strings.Contains(detail, "resolve") {
		t.Errorf("detail = %q", detail)
	}
}

// TestSetupHandsOverAWorkingHTTPSAddress is the whole HTTPS half of setup,
// end to end and through run() itself: no configuration file, so Shepherd
// serves the setup page, the page writes [tls], Shepherd starts on it and
// gets a certificate, and the same page is handed the address where a
// passkey can actually be registered. It is the step the owner is told to
// go and do, so the address they are given has to be one that works.
func TestSetupHandsOverAWorkingHTTPSAddress(t *testing.T) {
	scriptedSetup(t)
	resetTLSSeams(t)
	logs := captureLog(t)
	const hostname = "shepherd.example.com"
	tlsEvery = 10 * time.Millisecond
	tlsACMEClient = newFakeTLSACME(hostname)
	tlsDNS01 = &fakeTLSDNS01{}
	tlsPropagationCheck = func(context.Context, string, string) error { return nil }

	dir := tempDir(t)
	t.Chdir(dir)
	cfgPath := filepath.Join(dir, "shepherd.toml")
	tlsPort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath, false, io.Discard) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("run did not stop")
		}
	})

	base := setupURL(t, portFromLog(logs))
	// What the page posts once the Cloudflare token has been checked.
	body := fmt.Sprintf(`{"dns_listen":["127.0.0.1"],"dns_port":%d,"upstreams":["9.9.9.10"],`+
		`"portal_host":"127.0.0.1","portal_port":%d,"tls_hostname":%q,"tls_port":%d}`,
		freePort(t), freePort(t), hostname, tlsPort)
	res, err := http.Post(base+"/api/setup/finish?token="+setupTestToken, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("finish = %d", res.StatusCode)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("the config setup wrote does not load: %v", err)
	}
	if !cfg.TLS.Enabled || cfg.TLS.Hostname != hostname {
		t.Fatalf("tls = %+v", cfg.TLS)
	}
	// The listener has to be reachable from wherever the hostname
	// resolves, so setup binds every address rather than loopback.
	if cfg.TLS.Listen != fmt.Sprintf("0.0.0.0:%d", tlsPort) {
		t.Errorf("tls.listen = %q", cfg.TLS.Listen)
	}

	// The page polls this while Let's Encrypt is being asked, and it is
	// the same page: setup kept serving while Shepherd started.
	deadline := time.Now().Add(25 * time.Second)
	var got map[string]any
	for time.Now().Before(deadline) {
		res, err := http.Get(base + "/api/setup/certificate?token=" + setupTestToken)
		if err == nil {
			got = nil
			_ = json.NewDecoder(res.Body).Decode(&got)
			res.Body.Close()
			if got["ready"] == true {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got["ready"] != true {
		t.Fatalf("the certificate never arrived: %+v", got)
	}
	want := fmt.Sprintf("https://%s:%d", hostname, tlsPort)
	if got["url"] != want {
		t.Errorf("url = %v, want %s (where a passkey is registered)", got["url"], want)
	}
}
