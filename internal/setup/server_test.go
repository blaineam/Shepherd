// SPDX-License-Identifier: AGPL-3.0-or-later

package setup

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shepherd/internal/config"
)

const testToken = "setup-test-token"

// twoAddrs is the shape setup exists for: one host with a wired and a
// wireless address, plus an IPv6 address on the same interface.
func twoAddrs() ([]Addr, error) {
	return []Addr{
		{Interface: "eth0", IP: "192.0.2.10"},
		{Interface: "wlan0", IP: "198.51.100.10"},
		{Interface: "eth0", IP: "2001:db8::10", V6: true},
	}, nil
}

type rig struct {
	t        *testing.T
	s        *Server
	srv      *httptest.Server
	dir      string
	tested   []string
	upFail   map[string]bool
	connErr  error
	connSeen []RouterConn
	connDirs []string
}

// newRig builds a setup server whose every outside edge is a fake, so the
// tests drive the real handlers with no network and no host dependency.
func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, dir: t.TempDir(), upFail: map[string]bool{}}
	t.Chdir(r.dir) // the data directory is created relative to the process
	s, err := NewServer(&Server{
		ConfigPath: filepath.Join(r.dir, "shepherd.toml"),
		Token:      testToken,
		HostAddrs:  twoAddrs,
		PortFree:   func(string, int) bool { return true },
		TestUpstream: func(_ context.Context, addr string) error {
			r.tested = append(r.tested, addr)
			if r.upFail[addr] {
				return errors.New("no answer from " + addr)
			}
			return nil
		},
		ConnectRouter: func(_ context.Context, dir string, c RouterConn) error {
			r.connDirs = append(r.connDirs, dir)
			r.connSeen = append(r.connSeen, c)
			return r.connErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.s = s
	r.srv = httptest.NewServer(s.Handler())
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rig) do(method, path, body string) (int, string) {
	r.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	req, err := http.NewRequest(method, r.srv.URL+path+sep+"token="+testToken, rdr)
	if err != nil {
		r.t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(out)
}

func (r *rig) json(method, path, body string, want int) map[string]any {
	r.t.Helper()
	code, out := r.do(method, path, body)
	if code != want {
		r.t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, out)
	}
	var m map[string]any
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			r.t.Fatalf("%s %s: bad JSON %q: %v", method, path, out, err)
		}
	}
	return m
}

func TestThePageAndItsAssetsAreServed(t *testing.T) {
	// Every asset has to be in the //go:embed directive, or it is a 404
	// at runtime that no other test catches.
	r := newRig(t)
	for _, path := range []string{"/", "/setup.css", "/setup.js"} {
		code, body := r.do("GET", path, "")
		if code != 200 || body == "" {
			t.Errorf("GET %s = %d (%d bytes)", path, code, len(body))
		}
	}
	if _, body := r.do("GET", "/", ""); !strings.Contains(body, "Set up Shepherd") {
		t.Errorf("the page does not look like the setup page: %.120s", body)
	}
	if code, _ := r.do("GET", "/nope", ""); code != 404 {
		t.Errorf("an unknown path = %d, want 404", code)
	}
}

func TestEverythingNeedsTheToken(t *testing.T) {
	// Setup listens on every address so it can be reached from the
	// owner's laptop, which means the rest of the network can reach it
	// too; the token printed on the console is what separates them.
	r := newRig(t)
	for _, path := range []string{"/", "/setup.js", "/api/setup/state"} {
		res, err := http.Get(r.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Errorf("GET %s without a token = %d, want 403", path, res.StatusCode)
		}
	}
	res, err := http.Get(r.srv.URL + "/?token=wrong")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Errorf("a wrong token = %d, want 403", res.StatusCode)
	}
}

func TestTheTokenMovesIntoACookieSoItLeavesTheURL(t *testing.T) {
	r := newRig(t)
	res, err := http.Get(r.srv.URL + "/?token=" + testToken)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var got *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == setupCookie {
			got = c
		}
	}
	if got == nil || got.Value != testToken || !got.HttpOnly {
		t.Fatalf("cookie = %v", got)
	}
	// And the cookie alone is then enough, so no later request has to
	// carry the token in a URL.
	req, _ := http.NewRequest("GET", r.srv.URL+"/api/setup/state", nil)
	req.AddCookie(got)
	res2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != 200 {
		t.Errorf("with the cookie = %d", res2.StatusCode)
	}
}

func TestStateDescribesThisHostAndTheDefaults(t *testing.T) {
	r := newRig(t)
	got := r.json("GET", "/api/setup/state", "", 200)
	addrs, _ := got["addrs"].([]any)
	if len(addrs) != 3 {
		t.Fatalf("addrs = %v", got["addrs"])
	}
	first, _ := addrs[0].(map[string]any)
	if first["ip"] != "192.0.2.10" || first["interface"] != "eth0" {
		t.Errorf("the page needs the interface with the address: %v", first)
	}
	if got["data_dir"] != "data" || got["dns_port"] != 53.0 || got["portal_port"] != 8787.0 {
		t.Errorf("defaults = %+v", got)
	}
	if got["config_exists"] != false || got["can_router"] != true || got["dns_port_free"] != true {
		t.Errorf("state = %+v", got)
	}
	if presets, _ := got["presets"].([]any); len(presets) != len(Presets) {
		t.Errorf("presets = %v", got["presets"])
	}
}

func TestStateReportsAHostItCouldNotRead(t *testing.T) {
	r := newRig(t)
	r.s.HostAddrs = func() ([]Addr, error) { return nil, errors.New("no interfaces") }
	got := r.json("GET", "/api/setup/state", "", 200)
	if got["addrs_error"] != "no interfaces" {
		t.Errorf("state = %+v", got)
	}
}

func TestStateSaysWhenAConfigIsAlreadyThere(t *testing.T) {
	r := newRig(t)
	if err := os.WriteFile(r.s.ConfigPath, []byte("data_dir = \"mine\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := r.json("GET", "/api/setup/state", "", 200); got["config_exists"] != true {
		t.Errorf("state = %+v", got)
	}
}

func TestAHeldDNSPortIsReportedRatherThanRefused(t *testing.T) {
	// The holder is usually the resolver Shepherd is about to replace, so
	// this is something to say, not something to block on.
	r := newRig(t)
	r.s.PortFree = func(_ string, port int) bool { return port != 53 }
	if got := r.json("GET", "/api/setup/state", "", 200); got["dns_port_free"] != false {
		t.Errorf("state = %+v", got)
	}
	got := r.json("POST", "/api/setup/port-check", `{"port":53,"addrs":["192.0.2.10","198.51.100.10"]}`, 200)
	if got["free"] != false {
		t.Fatalf("port-check = %+v", got)
	}
	if held, _ := got["held"].([]any); len(held) != 2 {
		t.Errorf("held = %v", got["held"])
	}
	if got := r.json("POST", "/api/setup/port-check", `{"port":5353,"addrs":["192.0.2.10"]}`, 200); got["free"] != true {
		t.Errorf("a free port = %+v", got)
	}
	if code, _ := r.do("POST", "/api/setup/port-check", `{"port":70000}`); code != 400 {
		t.Errorf("a port outside the range = %d, want 400", code)
	}
}

func TestAResolverIsProbedTwiceBeforeItIsCalledAFailure(t *testing.T) {
	// Public resolvers drop the odd uncached query, and one lost packet
	// is not a reason to send someone off to debug a resolver that works.
	r := newRig(t)
	got := r.json("POST", "/api/setup/upstream-test", `{"addr":"9.9.9.10"}`, 200)
	if got["ok"] != true {
		t.Errorf("a working resolver = %+v", got)
	}
	if len(r.tested) != 1 {
		t.Errorf("a resolver that answers should be probed once, got %v", r.tested)
	}
	r.upFail["1.1.1.1"] = true
	got = r.json("POST", "/api/setup/upstream-test", `{"addr":"1.1.1.1"}`, 200)
	if got["ok"] != false || !strings.Contains(got["error"].(string), "no answer") {
		t.Errorf("a failing resolver = %+v", got)
	}
	if n := strings.Count(strings.Join(r.tested, " "), "1.1.1.1"); n != 2 {
		t.Errorf("a failing resolver should be probed twice, got %v", r.tested)
	}
}

func TestUpstreamTestSaysWhenTheBuildCannotProbe(t *testing.T) {
	r := newRig(t)
	r.s.TestUpstream = nil
	if got := r.json("POST", "/api/setup/upstream-test", `{"addr":"9.9.9.10"}`, 200); got["ok"] != false {
		t.Errorf("= %+v", got)
	}
	if code, _ := r.do("POST", "/api/setup/upstream-test", `not json`); code != 400 {
		t.Error("a body that is not JSON should be refused")
	}
}

func TestConnectingARouterIsOptionalAndVerifiedFirst(t *testing.T) {
	r := newRig(t)
	body := `{"data_dir":"mydata","base_url":"https://198.51.100.20","username":"ro-user","password":"pw-9f3","site":"default","allow_self_signed":true}`
	if got := r.json("POST", "/api/setup/router", body, 200); got["ok"] != true {
		t.Fatalf("connect = %+v", got)
	}
	if len(r.connSeen) != 1 || r.connSeen[0].Username != "ro-user" || !r.connSeen[0].AllowSelfSigned {
		t.Errorf("collected = %+v", r.connSeen)
	}
	// The credentials are stored under the data directory the owner
	// chose on the page, not under a default nobody picked.
	if len(r.connDirs) != 1 || r.connDirs[0] != "mydata" {
		t.Errorf("data dirs = %v", r.connDirs)
	}
	r.connErr = errors.New("the controller refused the username or password")
	got := r.json("POST", "/api/setup/router", body, 200)
	if got["ok"] != false || !strings.Contains(got["error"].(string), "refused") {
		t.Errorf("a refused controller = %+v", got)
	}
	r.s.ConnectRouter = nil
	if code, _ := r.do("POST", "/api/setup/router", body); code != 404 {
		t.Error("a build that cannot read a router should say so")
	}
}

const finishBody = `{"data_dir":"data","dns_listen":["192.0.2.10","198.51.100.10"],"dns_port":53,` +
	`"upstreams":["9.9.9.10","149.112.112.10"],"portal_host":"127.0.0.1","portal_port":8787}`

func TestFinishWritesAConfigShepherdCanLoad(t *testing.T) {
	r := newRig(t)
	got := r.json("POST", "/api/setup/finish", finishBody, 200)
	if got["written"] != r.s.ConfigPath || got["portal"] != "http://127.0.0.1:8787" {
		t.Errorf("finish = %+v", got)
	}
	if got["dig"] != "@192.0.2.10" {
		t.Errorf("the page should suggest a dig at a chosen address: %+v", got)
	}
	cfg, err := config.Load(r.s.ConfigPath)
	if err != nil {
		t.Fatalf("the config setup wrote does not load: %v", err)
	}
	if len(cfg.DNS.Listen) != 2 || cfg.DNS.Listen[0] != "192.0.2.10:53" || cfg.Portal.Listen != "127.0.0.1:8787" {
		t.Errorf("loaded = %+v", cfg.DNS.Listen)
	}
	// Only the asked-about keys are written, so every other default keeps
	// following Shepherd's own.
	if !cfg.Privacy.BlockPrivateRelay || cfg.Watch.Enabled || cfg.DNS.BlockMode != "null" {
		t.Errorf("a default was frozen into the file: %+v", cfg)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "data")); err != nil {
		t.Errorf("the data directory was not created: %v", err)
	}
	// Finishing is what hands control back to cmd/shepherd.
	select {
	case <-r.s.Done():
	default:
		t.Error("finishing should have released the caller")
	}
	// A second finish must not panic on the closed channel.
	r.json("POST", "/api/setup/finish", finishBody, 200)
}

func TestFinishRefusesAnswersThatCouldNotWork(t *testing.T) {
	r := newRig(t)
	for _, body := range []string{
		`{"data_dir":"","dns_listen":["192.0.2.10"],"dns_port":53,"upstreams":["9.9.9.10"],"portal_host":"127.0.0.1","portal_port":8787}`,
		`{"data_dir":"data","dns_listen":[],"dns_port":53,"upstreams":["9.9.9.10"],"portal_host":"127.0.0.1","portal_port":8787}`,
		`{"data_dir":"data","dns_listen":["not an address"],"dns_port":53,"upstreams":["9.9.9.10"],"portal_host":"127.0.0.1","portal_port":8787}`,
		`{"data_dir":"data","dns_listen":["192.0.2.10"],"dns_port":0,"upstreams":["9.9.9.10"],"portal_host":"127.0.0.1","portal_port":8787}`,
		`{"data_dir":"data","dns_listen":["192.0.2.10"],"dns_port":53,"upstreams":[],"portal_host":"127.0.0.1","portal_port":8787}`,
		`{"data_dir":"data","dns_listen":["192.0.2.10"],"dns_port":53,"upstreams":["9.9.9.10"],"portal_host":"nope","portal_port":8787}`,
		`{"data_dir":"data","dns_listen":["192.0.2.10"],"dns_port":53,"upstreams":["9.9.9.10"],"portal_host":"127.0.0.1","portal_port":99999}`,
		`not json`,
	} {
		if code, out := r.do("POST", "/api/setup/finish", body); code != 400 {
			t.Errorf("%s = %d, want 400: %s", body, code, out)
		}
	}
	if _, err := os.Stat(r.s.ConfigPath); !os.IsNotExist(err) {
		t.Error("nothing should have been written")
	}
}

func TestFinishKeepsAnExistingConfigAsABackup(t *testing.T) {
	// The old file may hold settings this page never asked about, so it
	// is always kept rather than replaced outright.
	r := newRig(t)
	if err := os.WriteFile(r.s.ConfigPath, []byte("data_dir = \"mine\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.json("POST", "/api/setup/finish", finishBody, 200)
	b, err := os.ReadFile(r.s.ConfigPath + ".bak")
	if err != nil || string(b) != "data_dir = \"mine\"\n" {
		t.Errorf("backup = %q %v", b, err)
	}
}

func TestFinishReportsAPathItCannotUse(t *testing.T) {
	r := newRig(t)
	r.s.ConfigPath = filepath.Join(r.dir, "no-such-dir", "shepherd.toml")
	if code, out := r.do("POST", "/api/setup/finish", finishBody); code != 500 {
		t.Errorf("= %d: %s", code, out)
	}
	// A data directory that cannot be made is the owner's to fix, and is
	// reported as their mistake rather than ours.
	blocker := filepath.Join(r.dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r.s.ConfigPath = filepath.Join(r.dir, "shepherd.toml")
	body := `{"data_dir":"` + filepath.ToSlash(filepath.Join(blocker, "data")) + `","dns_listen":["192.0.2.10"],"dns_port":53,` +
		`"upstreams":["9.9.9.10"],"portal_host":"127.0.0.1","portal_port":8787}`
	if code, out := r.do("POST", "/api/setup/finish", body); code != 400 {
		t.Errorf("= %d: %s", code, out)
	}
}

func TestFinishRefusesAnUnreadableExistingConfig(t *testing.T) {
	r := newRig(t)
	if err := os.Mkdir(r.s.ConfigPath, 0o750); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.do("POST", "/api/setup/finish", finishBody); code != 500 {
		t.Error("a config path that is a directory should fail")
	}
}

func TestFinishRefusesABackupItCannotWrite(t *testing.T) {
	r := newRig(t)
	if err := os.WriteFile(r.s.ConfigPath, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(r.s.ConfigPath+".bak", 0o750); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.do("POST", "/api/setup/finish", finishBody); code != 500 {
		t.Error("a backup that cannot be written should stop the replacement")
	}
	if b, _ := os.ReadFile(r.s.ConfigPath); string(b) != "old\n" {
		t.Errorf("the existing config was replaced anyway: %q", b)
	}
}

func TestRunServesUntilSetupFinishesAndThenStops(t *testing.T) {
	// This is the whole flow cmd/shepherd relies on: serve, wait, hand
	// back the file that was written.
	dir := t.TempDir()
	t.Chdir(dir)
	s, err := NewServer(&Server{ConfigPath: filepath.Join(dir, "shepherd.toml"), Token: testToken,
		HostAddrs: twoAddrs, PortFree: func(string, int) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	done := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		written, err := s.Run(ctx, "127.0.0.1:0", func(f string, a ...any) { lines = append(lines, f) })
		if err != nil {
			t.Error(err)
		}
		done <- written
	}()

	// The listener is up as soon as Run has printed its URLs; find it by
	// polling the port it chose, which the log lines carry.
	var base string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && base == "" {
		for _, u := range s.URLs(s.Port()) {
			if strings.HasPrefix(u, "http://127.0.0.1:") {
				base = strings.SplitN(u, "/?", 2)[0]
			}
		}
		if base != "" && reachable(base) {
			break
		}
		base = ""
		time.Sleep(20 * time.Millisecond)
	}
	if base == "" {
		t.Fatal("setup never came up")
	}
	res, err := http.Post(base+"/api/setup/finish?token="+testToken, "application/json", strings.NewReader(finishBody))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	select {
	case written := <-done:
		if written != s.ConfigPath {
			t.Errorf("Run returned %q", written)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after setup finished")
	}
	if !reachableFails(base) {
		t.Error("the setup listener should be closed once setup is done")
	}
}

func reachable(base string) bool {
	c := http.Client{Timeout: 500 * time.Millisecond}
	res, err := c.Get(base + "/?token=" + testToken)
	if err != nil {
		return false
	}
	res.Body.Close()
	return res.StatusCode == 200
}

func reachableFails(base string) bool { return !reachable(base) }

func TestRunStopsWhenTheProcessIsAskedTo(t *testing.T) {
	dir := t.TempDir()
	s, err := NewServer(&Server{ConfigPath: filepath.Join(dir, "shepherd.toml"), Token: testToken,
		HostAddrs: twoAddrs, PortFree: func(string, int) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	written, err := s.Run(ctx, "127.0.0.1:0", func(string, ...any) {})
	if err != nil || written != "" {
		t.Errorf("Run with a cancelled context = %q %v", written, err)
	}
}

func TestRunReportsAPortItCannotTake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s, err := NewServer(&Server{Token: testToken, HostAddrs: twoAddrs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(context.Background(), ln.Addr().String(), func(string, ...any) {}); err == nil {
		t.Error("a port already taken should be reported")
	}
}

func TestURLsLeadWithLoopbackAndCarryTheToken(t *testing.T) {
	s, err := NewServer(&Server{Token: testToken, HostAddrs: twoAddrs})
	if err != nil {
		t.Fatal(err)
	}
	urls := s.URLs("8787")
	if len(urls) != 4 || !strings.HasPrefix(urls[0], "http://127.0.0.1:8787/?token=") {
		t.Fatalf("urls = %v", urls)
	}
	// An IPv6 address has to be bracketed or the URL is not one.
	if !strings.Contains(urls[3], "http://[2001:db8::10]:8787/") {
		t.Errorf("IPv6 url = %s", urls[3])
	}
	for _, u := range urls {
		if !strings.HasSuffix(u, testToken) {
			t.Errorf("%s does not carry the token", u)
		}
	}
	s.HostAddrs = func() ([]Addr, error) { return nil, errors.New("no interfaces") }
	if urls := s.URLs("8787"); len(urls) != 1 {
		t.Errorf("with no readable addresses, loopback is still offered: %v", urls)
	}
}

func TestNewServerFillsInWhatWasNotGiven(t *testing.T) {
	s, err := NewServer(&Server{})
	if err != nil {
		t.Fatal(err)
	}
	if s.ConfigPath != "shepherd.toml" || s.HostAddrs == nil || s.PortFree == nil {
		t.Errorf("defaults = %+v", s)
	}
	if len(s.Token) < 32 {
		t.Errorf("the generated token is too short to be worth having: %q", s.Token)
	}
	other, err := NewServer(&Server{})
	if err != nil {
		t.Fatal(err)
	}
	if other.Token == s.Token {
		t.Error("each run must get its own token")
	}
}

func TestBodiesThatAreNotUsableAreRefused(t *testing.T) {
	r := newRig(t)
	for _, path := range []string{"/api/setup/port-check", "/api/setup/router", "/api/setup/finish"} {
		if code, _ := r.do("POST", path, "not json"); code != 400 {
			t.Errorf("%s with a body that is not JSON should be 400", path)
		}
		// And a body too large to be anything setup asks for.
		if code, _ := r.do("POST", path, `{"x":"`+strings.Repeat("a", 70<<10)+`"}`); code != 400 {
			t.Errorf("%s with an oversized body should be 400", path)
		}
	}
}

func TestConnectingARouterWithoutADataDirectoryUsesTheDefault(t *testing.T) {
	// The page sends what is in the field; empty means the owner has not
	// changed it, and the default is what the rest of setup assumes.
	r := newRig(t)
	r.json("POST", "/api/setup/router", `{"base_url":"https://198.51.100.20","username":"u","password":"p"}`, 200)
	if len(r.connDirs) != 1 || r.connDirs[0] != "data" {
		t.Errorf("data dirs = %v", r.connDirs)
	}
}

func TestRunLogsThroughTheStandardLoggerWhenGivenNoLogger(t *testing.T) {
	// cmd/shepherd passes log.Printf, but nothing should break for a
	// caller that passes nothing.
	s, err := NewServer(&Server{ConfigPath: filepath.Join(t.TempDir(), "shepherd.toml"), Token: testToken,
		HostAddrs: twoAddrs, PortFree: func(string, int) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if written, err := s.Run(ctx, "127.0.0.1:0", nil); err != nil || written != "" {
		t.Errorf("Run = %q %v", written, err)
	}
}
