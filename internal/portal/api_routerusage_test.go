// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"shepherd/internal/secrets"

	"shepherd/internal/routerusage"
)

type fakeUsage struct {
	mu      sync.Mutex
	reloads int
	st      routerusage.Status
	live    []routerusage.LiveDevice
}

func (f *fakeUsage) Status() routerusage.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st
}

func (f *fakeUsage) Live() []routerusage.LiveDevice {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live
}

func (f *fakeUsage) Reload() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
}

func (f *fakeUsage) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reloads
}

// signedInSession runs the sign-in the owner would do in the portal and
// returns a session that has verified its code.
func signedInSession(t *testing.T, h *harness) string {
	t.Helper()
	m := h.ok("POST", "/api/import/eero/start", fmt.Sprintf(`{"login":%q}`, impTestLogin), 200)
	sid, _ := m["session_id"].(string)
	if sid == "" {
		t.Fatal("no session id")
	}
	h.ok("POST", "/api/import/eero/verify", fmt.Sprintf(`{"session_id":%q,"code":%q}`, sid, impTestCode), 200)
	return sid
}

func TestRouterUsageIsAbsentUntilTheBuildWiresItUp(t *testing.T) {
	h := newHarness(t)
	out := h.ok("GET", "/api/routerusage", "", 200)
	if out["available"] != false || out["connected"] != false {
		t.Fatalf("status = %v", out)
	}
	// Every write says so rather than half-working.
	h.expect("POST", "/api/routerusage/connect", `{"session_id":"x","network_id":"y"}`, 404)
	h.expect("POST", "/api/routerusage/enabled", `{"enabled":true}`, 404)
	h.expect("DELETE", "/api/routerusage", "", 404)
}

func TestRouterUsageConnectKeepsTheSessionAndStartsReading(t *testing.T) {
	h := newHarness(t)
	h.withEero(newFakeEero(t))
	usage := &fakeUsage{}
	h.srv.RouterUsage = usage

	if out := h.ok("GET", "/api/routerusage", "", 200); out["available"] != true || out["connected"] != false {
		t.Fatalf("before connecting = %v", out)
	}

	sid := signedInSession(t, h)
	out := h.ok("POST", "/api/routerusage/connect", fmt.Sprintf(`{"session_id":%q,"network_id":"3001"}`, sid), 200)
	if out["connected"] != true || out["source"] != "eero" || out["network"] != "3001" || out["enabled"] != true {
		t.Fatalf("after connecting = %v", out)
	}
	if usage.count() != 1 {
		t.Fatalf("the reader was reloaded %d times, want 1", usage.count())
	}
	// The token is kept, and never comes back out of the API.
	e, ok := h.srv.Secrets.Eero()
	if !ok || e.Token == "" || e.NetworkID != "3001" || !e.Enabled {
		t.Fatalf("stored session = %+v, %v", e, ok)
	}
	for k, v := range out {
		if s, isStr := v.(string); isStr && s == e.Token {
			t.Fatalf("the token leaked through %q", k)
		}
	}
	// The import session is spent, so the same one cannot be reused.
	h.expect("POST", "/api/routerusage/connect", fmt.Sprintf(`{"session_id":%q,"network_id":"3001"}`, sid), 404)
}

func TestRouterUsageConnectRefusesAnythingButAVerifiedSessionAndAKnownNetwork(t *testing.T) {
	h := newHarness(t)
	h.withEero(newFakeEero(t))
	h.srv.RouterUsage = &fakeUsage{}

	h.expect("POST", "/api/routerusage/connect", `{"session_id":"nope","network_id":"3001"}`, 404)

	// Started but not verified: there is no session to keep yet.
	m := h.ok("POST", "/api/import/eero/start", fmt.Sprintf(`{"login":%q}`, impTestLogin), 200)
	unverified, _ := m["session_id"].(string)
	h.expect("POST", "/api/routerusage/connect", fmt.Sprintf(`{"session_id":%q,"network_id":"3001"}`, unverified), 401)

	sid := signedInSession(t, h)
	for _, body := range []string{
		fmt.Sprintf(`{"session_id":%q,"network_id":""}`, sid),
		fmt.Sprintf(`{"session_id":%q,"network_id":"a-network-on-someone-elses-account"}`, sid),
	} {
		h.expect("POST", "/api/routerusage/connect", body, 400)
	}
	if _, ok := h.srv.Secrets.Eero(); ok {
		t.Fatal("a refused connect stored a session anyway")
	}
}

func TestRouterUsageSwitchesOffWithoutForgettingTheSignIn(t *testing.T) {
	h := newHarness(t)
	h.withEero(newFakeEero(t))
	usage := &fakeUsage{}
	h.srv.RouterUsage = usage
	h.ok("POST", "/api/routerusage/connect", fmt.Sprintf(`{"session_id":%q,"network_id":"3001"}`, signedInSession(t, h)), 200)

	out := h.ok("POST", "/api/routerusage/enabled", `{"enabled":false}`, 200)
	if out["enabled"] != false || out["connected"] != true {
		t.Fatalf("after switching off = %v", out)
	}
	e, _ := h.srv.Secrets.Eero()
	if e.Token == "" {
		t.Fatal("switching off forgot the sign-in, so turning it back on would need a new code")
	}
	if out := h.ok("POST", "/api/routerusage/enabled", `{"enabled":true}`, 200); out["enabled"] != true {
		t.Fatalf("after switching on = %v", out)
	}
	if usage.count() != 3 {
		t.Fatalf("reloads = %d, want one per change", usage.count())
	}
}

func TestRouterUsageForgetDropsTheSessionEntirely(t *testing.T) {
	h := newHarness(t)
	h.withEero(newFakeEero(t))
	usage := &fakeUsage{}
	h.srv.RouterUsage = usage
	h.ok("POST", "/api/routerusage/connect", fmt.Sprintf(`{"session_id":%q,"network_id":"3001"}`, signedInSession(t, h)), 200)

	out := h.ok("DELETE", "/api/routerusage", "", 200)
	if out["connected"] != false {
		t.Fatalf("after forgetting = %v", out)
	}
	if _, ok := h.srv.Secrets.Eero(); ok {
		t.Fatal("the session is still stored")
	}
	// With nothing connected the switch has nothing to act on.
	h.expect("POST", "/api/routerusage/enabled", `{"enabled":true}`, 404)
}

func TestRouterUsageStatusReachesTheBandwidthScreen(t *testing.T) {
	h := newHarness(t)
	usage := &fakeUsage{st: routerusage.Status{Source: "eero", Enabled: true, Estimated: true, DevicesSeen: 7, Matched: 5}}
	h.srv.RouterUsage = usage
	out := h.ok("GET", "/api/traffic", "", 200)
	router, ok := out["router"].(map[string]any)
	if !ok {
		t.Fatalf("GET /api/traffic carried no router section: %v", out)
	}
	st, _ := router["status"].(map[string]any)
	if st["source"] != "eero" || st["devices_seen"] != 7.0 || st["estimated"] != true {
		t.Fatalf("router status = %v", router)
	}
}

func TestKnownNetworkRefusesAnEmptyOrUnlistedID(t *testing.T) {
	if knownNetwork(nil, "") || knownNetwork(nil, "x") {
		t.Fatal("an empty list matched something")
	}
}

// A store that cannot be written must fail the request rather than report
// a change that was never saved. Replacing the file with a directory makes
// the atomic rename fail deterministically, whoever the test runs as.
func wedgeSecrets(t *testing.T, h *harness) {
	t.Helper()
	path := h.srv.Secrets.Path()
	if path == "" {
		t.Fatal("this test needs a file-backed secrets store")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

// onDisk gives the harness a secrets store that really writes, so a failed
// write can be provoked.
func onDisk(t *testing.T) func(*Deps) {
	t.Helper()
	store, err := secrets.Open(filepath.Join(t.TempDir(), secrets.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return func(d *Deps) { d.Secrets = store }
}

func TestRouterUsageReportsAChangeItCouldNotSave(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	h.withEero(newFakeEero(t))
	h.srv.RouterUsage = &fakeUsage{}
	h.ok("POST", "/api/routerusage/connect", fmt.Sprintf(`{"session_id":%q,"network_id":"3001"}`, signedInSession(t, h)), 200)

	wedgeSecrets(t, h)
	h.expect("POST", "/api/routerusage/enabled", `{"enabled":false}`, 500)
	h.expect("DELETE", "/api/routerusage", "", 500)
}

func TestRouterUsageConnectReportsAConnectionItCouldNotSave(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	h.withEero(newFakeEero(t))
	h.srv.RouterUsage = &fakeUsage{}
	sid := signedInSession(t, h)
	wedgeSecrets(t, h)
	h.expect("POST", "/api/routerusage/connect", fmt.Sprintf(`{"session_id":%q,"network_id":"3001"}`, sid), 500)
}

// With Watch mode not measuring, the "Right now" card has to come from the
// router reader, or the screen shows zeros while the reader is working.
func TestTheLiveCardComesFromTheRouterWhenWatchModeIsNotMeasuring(t *testing.T) {
	h := newHarness(t)
	at := time.Now()
	h.srv.RouterUsage = &fakeUsage{
		st: routerusage.Status{Source: "eero", Enabled: true, Estimated: true, LastPoll: &at, DevicesSeen: 2, Matched: 2},
		live: []routerusage.LiveDevice{
			{DeviceID: "d-busy", Name: "Living Room TV", DownBitsPerSecond: 80e6, UpBitsPerSecond: 8e6, DownBytes: 1000, UpBytes: 100},
			{DeviceID: "d-quiet", Name: "Printer"},
		},
	}
	out := h.ok("GET", "/api/traffic", "", 200)
	live := out["live"].(map[string]any)
	// 80 Mbit/s down and 8 Mbit/s up, as bytes per second.
	if live["down_bytes_per_second"] != 10_000_000.0 || live["up_bytes_per_second"] != 1_000_000.0 {
		t.Fatalf("live = %v, want the rates summed and converted to bytes", live)
	}
	devs := out["devices"].([]any)
	if len(devs) != 2 {
		t.Fatalf("devices = %v", devs)
	}
	first := devs[0].(map[string]any)
	if first["device_id"] != "d-busy" || first["name"] != "Living Room TV" || first["down_bytes_per_second"] != 10_000_000.0 {
		t.Fatalf("first device = %v", first)
	}
}

// Anything that means "not reading right now" must leave the card alone
// rather than show a stale or empty reading as if it were live.
func TestTheLiveCardIgnoresARouterReaderThatIsNotReading(t *testing.T) {
	at := time.Now()
	for name, st := range map[string]routerusage.Status{
		"never polled": {Source: "eero", Enabled: true},
		"switched off": {Source: "eero", Enabled: false, LastPoll: &at},
		"failing":      {Source: "eero", Enabled: true, LastPoll: &at, LastError: "the router did not answer"},
		"no source":    {Enabled: true, LastPoll: &at},
	} {
		h := newHarness(t)
		h.srv.RouterUsage = &fakeUsage{st: st, live: []routerusage.LiveDevice{{DeviceID: "d-busy", DownBitsPerSecond: 80e6}}}
		out := h.ok("GET", "/api/traffic", "", 200)
		if live := out["live"].(map[string]any); live["down_bytes_per_second"] != 0.0 {
			t.Errorf("%s: live = %v, want zeros", name, live)
		}
		if n := len(out["devices"].([]any)); n != 0 {
			t.Errorf("%s: %d devices, want none", name, n)
		}
	}
}
