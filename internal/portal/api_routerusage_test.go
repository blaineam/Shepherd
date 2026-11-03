// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"shepherd/internal/secrets"

	"shepherd/internal/importers"
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

// withStoredEero points the kept-sign-in client at the fake eero too.
func (h *harness) withStoredEero(base string) {
	h.srv.NewStoredEeroClient = func(store importers.TokenStore) (*importers.Client, error) {
		return importers.NewTestClient(base, importers.ClientOptions{MinInterval: -1, TokenStore: store})
	}
}

// connected signs in and keeps the session, which is what every name sync
// below starts from.
func connected(t *testing.T, h *harness) {
	t.Helper()
	base := newFakeEero(t)
	h.withEero(base)
	h.withStoredEero(base)
	h.srv.RouterUsage = &fakeUsage{}
	h.ok("POST", "/api/routerusage/connect", fmt.Sprintf(`{"session_id":%q,"network_id":"3001"}`, signedInSession(t, h)), 200)
}

// The point of syncing names off the kept sign-in is that it needs no new
// verification code, and that the owner's own names survive it.
func TestSyncNamesPreviewsThenAppliesWithoutANewCode(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	connected(t, h)

	prev := h.ok("POST", "/api/routerusage/names", `{"dry_run":true}`, 200)
	if prev["dry_run"] != true {
		t.Fatalf("preview = %v, want a dry run", prev)
	}
	if prev["created"].(float64) < 1 {
		t.Fatalf("the preview found nothing to do: %v", prev)
	}
	// A preview writes nothing.
	if n := len(h.srv.Devices.List()); n != 0 {
		t.Fatalf("the preview created %d devices", n)
	}

	rep := h.ok("POST", "/api/routerusage/names", `{"dry_run":false}`, 200)
	if rep["dry_run"] != false || rep["created"].(float64) < 1 {
		t.Fatalf("apply = %v", rep)
	}
	var named bool
	for _, d := range h.srv.Devices.List() {
		if d.DisplayName() == "Kid iPad" {
			named = true
		}
	}
	if !named {
		t.Fatalf("eero's name was not applied: %+v", h.srv.Devices.List())
	}
	// Running it again changes nothing, so a button can be pressed twice.
	again := h.ok("POST", "/api/routerusage/names", `{"dry_run":false}`, 200)
	if again["created"].(float64) != 0 {
		t.Fatalf("a second sync created devices again: %v", again)
	}
}

func TestSyncNamesLeavesTheOwnersOwnNamesAloneUnlessAsked(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	connected(t, h)
	h.ok("POST", "/api/routerusage/names", `{"dry_run":false}`, 200)

	// The owner renames it to something of their own.
	var id string
	for _, d := range h.srv.Devices.List() {
		if d.DisplayName() == "Kid iPad" {
			id = d.ID
		}
	}
	if id == "" {
		t.Fatal("no device to rename")
	}
	h.ok("PATCH", "/api/devices/"+id, `{"alias":"Harriet's tablet"}`, 200)

	// A plain sync must not take that away.
	if rep := h.ok("POST", "/api/routerusage/names", `{"dry_run":false}`, 200); rep["renamed"].(float64) != 0 {
		t.Fatalf("a plain sync renamed the owner's device: %v", rep)
	}
	if d, _ := h.srv.Devices.Get(id); d.DisplayName() != "Harriet's tablet" {
		t.Fatalf("the owner's name was lost: %q", d.DisplayName())
	}

	// Only an explicit ask replaces it.
	if rep := h.ok("POST", "/api/routerusage/names", `{"dry_run":false,"overwrite_names":true}`, 200); rep["renamed"].(float64) != 1 {
		t.Fatalf("overwrite_names did not rename: %v", rep)
	}
	if d, _ := h.srv.Devices.Get(id); d.DisplayName() != "Kid iPad" {
		t.Fatalf("after overwriting = %q", d.DisplayName())
	}
}

func TestSyncNamesNeedsAKeptSignIn(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	h.withStoredEero(newFakeEero(t))
	h.srv.RouterUsage = &fakeUsage{}
	// Nothing stored at all.
	h.expect("POST", "/api/routerusage/names", `{"dry_run":true}`, 401)

	// A session with no network chosen is not enough either.
	if _, err := h.srv.Secrets.SetEero(secrets.Eero{Token: "eero-token-abc"}); err != nil {
		t.Fatal(err)
	}
	h.expect("POST", "/api/routerusage/names", `{"dry_run":true}`, 401)
}

func TestSyncNamesReportsAReadThatFailedPartWayThrough(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	base := newFakeEeroFailing(t, "/2.2/networks/3001/devices")
	h.withEero(newFakeEero(t)) // the sign-in itself works
	h.withStoredEero(base)     // but reading the devices later does not
	h.srv.RouterUsage = &fakeUsage{}
	h.ok("POST", "/api/routerusage/connect", fmt.Sprintf(`{"session_id":%q,"network_id":"3001"}`, signedInSession(t, h)), 200)

	h.expect("POST", "/api/routerusage/names", `{"dry_run":true}`, 400)
	if n := len(h.srv.Devices.List()); n != 0 {
		t.Fatalf("a failed read still wrote %d devices", n)
	}
}

func TestSyncNamesReportsAClientItCouldNotBuild(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	connected(t, h)
	h.srv.NewStoredEeroClient = func(importers.TokenStore) (*importers.Client, error) {
		return nil, importers.ErrEeroBadURL
	}
	h.expect("POST", "/api/routerusage/names", `{"dry_run":true}`, 400)
}

// A sign-in that was forgotten after the client was configured must ask
// for one rather than reading with no token.
func TestSyncNamesAsksForASignInWhenTheTokenHasGone(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	connected(t, h)
	if err := h.srv.Secrets.ClearEero(); err != nil {
		t.Fatal(err)
	}
	h.expect("POST", "/api/routerusage/names", `{"dry_run":true}`, 401)
}

func TestRouterUsageRefusesMalformedBodies(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	connected(t, h)
	for _, path := range []string{"/api/routerusage/connect", "/api/routerusage/enabled", "/api/routerusage/names"} {
		h.expect("POST", path, "{not json", 400)
	}
}

// Live() is only consulted while the reader is actually reading, so a
// manager with nothing running must not be asked for rows.
func TestTheLiveCardIgnoresAReaderWithNoRows(t *testing.T) {
	at := time.Now()
	h := newHarness(t)
	h.srv.RouterUsage = &fakeUsage{st: routerusage.Status{Source: "eero", Enabled: true, LastPoll: &at}}
	out := h.ok("GET", "/api/traffic", "", 200)
	if n := len(out["devices"].([]any)); n != 0 {
		t.Fatalf("%d devices from an empty reader", n)
	}
	if live := out["live"].(map[string]any); live["down_bytes_per_second"] != 0.0 {
		t.Fatalf("live = %v", live)
	}
}

func TestTheLiveCardIsUntouchedWithoutARouterReader(t *testing.T) {
	h := newHarness(t)
	out := h.ok("GET", "/api/traffic", "", 200)
	if r := out["router"].(map[string]any); r["available"] != false {
		t.Fatalf("router = %v", r)
	}
	if n := len(out["devices"].([]any)); n != 0 {
		t.Fatalf("%d devices with no reader", n)
	}
}

// ---- UniFi ------------------------------------------------------------------

// unifiController is enough of a controller for the portal to connect to.
func unifiController(t *testing.T, user, pass string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			var in struct{ Username, Password string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Username != user || in.Password != pass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("X-Csrf-Token", "c")
			fmt.Fprint(w, `{"meta":{"rc":"ok"}}`)
		case "/proxy/network/api/s/default/stat/sta":
			fmt.Fprint(w, `{"data":[{"mac":"02:00:5e:00:00:41","name":"TV","tx_bytes":10,"rx_bytes":2}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConnectingAUniFiControllerChecksItBeforeStoringIt(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	h.srv.RouterUsage = &fakeUsage{}
	srv := unifiController(t, "ro", "pw")

	// A controller that refuses the credentials is reported, not stored.
	h.expect("POST", "/api/routerusage/unifi", fmt.Sprintf(`{"base_url":%q,"username":"ro","password":"wrong"}`, srv.URL), 400)
	if _, ok := h.srv.Secrets.UniFi(); ok {
		t.Fatal("bad credentials were stored anyway")
	}
	// So is an address that is not a controller at all.
	h.expect("POST", "/api/routerusage/unifi", `{"base_url":"not-a-url","username":"ro","password":"pw"}`, 400)

	out := h.ok("POST", "/api/routerusage/unifi", fmt.Sprintf(`{"base_url":%q,"username":"ro","password":"pw"}`, srv.URL), 200)
	if out["source"] != "unifi" || out["enabled"] != true || out["connected"] != true {
		t.Fatalf("after connecting = %v", out)
	}
	u, ok := h.srv.Secrets.UniFi()
	if !ok || u.Password != "pw" {
		t.Fatalf("stored = %+v", u)
	}
	for k, v := range out {
		if s, isStr := v.(string); isStr && s == "pw" {
			t.Fatalf("the password leaked through %q", k)
		}
	}
}

func TestUniFiSwitchesOffAndIsForgotten(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	usage := &fakeUsage{}
	h.srv.RouterUsage = usage
	srv := unifiController(t, "ro", "pw")
	h.ok("POST", "/api/routerusage/unifi", fmt.Sprintf(`{"base_url":%q,"username":"ro","password":"pw"}`, srv.URL), 200)

	if out := h.ok("POST", "/api/routerusage/unifi/enabled", `{"enabled":false}`, 200); out["enabled"] != false {
		t.Fatalf("after switching off = %v", out)
	}
	if u, _ := h.srv.Secrets.UniFi(); u.Password == "" {
		t.Fatal("switching off forgot the credentials")
	}
	if out := h.ok("DELETE", "/api/routerusage/unifi", "", 200); out["connected"] != false {
		t.Fatalf("after forgetting = %v", out)
	}
	h.expect("POST", "/api/routerusage/unifi/enabled", `{"enabled":true}`, 404)
	h.expect("POST", "/api/routerusage/unifi", "{bad", 400)
}

func TestWithoutAReaderTheUniFiEndpointsSaySo(t *testing.T) {
	h := newHarness(t)
	h.expect("POST", "/api/routerusage/unifi", `{"base_url":"https://192.0.2.10","username":"a","password":"b"}`, 404)
	h.expect("POST", "/api/routerusage/unifi/enabled", `{"enabled":true}`, 404)
	h.expect("DELETE", "/api/routerusage/unifi", "", 404)
}

func TestUniFiConnectRefusesCredentialsTheStoreWouldNotAccept(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	h.srv.RouterUsage = &fakeUsage{}
	srv := unifiController(t, "ro", "pw")
	// The controller accepts it, but the store will not keep a username
	// with a control character in it.
	h.expect("POST", "/api/routerusage/unifi", fmt.Sprintf(`{"base_url":%q,"username":"ro","password":"pw","site":"a\nb"}`, srv.URL), 400)
	if _, ok := h.srv.Secrets.UniFi(); ok {
		t.Fatal("it was stored anyway")
	}
}

func TestUniFiReportsAControllerItCouldNotSave(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	h.srv.RouterUsage = &fakeUsage{}
	srv := unifiController(t, "ro", "pw")
	wedgeSecrets(t, h)
	h.expect("POST", "/api/routerusage/unifi", fmt.Sprintf(`{"base_url":%q,"username":"ro","password":"pw"}`, srv.URL), 500)
}

func TestUniFiChangesThatCouldNotBeSavedAreReported(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	h.srv.RouterUsage = &fakeUsage{}
	srv := unifiController(t, "ro", "pw")
	h.ok("POST", "/api/routerusage/unifi", fmt.Sprintf(`{"base_url":%q,"username":"ro","password":"pw"}`, srv.URL), 200)
	wedgeSecrets(t, h)
	h.expect("POST", "/api/routerusage/unifi/enabled", `{"enabled":false}`, 500)
	h.expect("DELETE", "/api/routerusage/unifi", "", 500)
}
