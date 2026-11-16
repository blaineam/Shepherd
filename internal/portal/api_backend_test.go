// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"shepherd/internal/backends"
	"shepherd/internal/backends/hub"
	"shepherd/internal/secrets"
)

// fakeHub is a BackendHub that records what it was asked to do.
type fakeHub struct {
	mu       sync.Mutex
	reloads  int
	refresh  int
	running  bool
	lastErr  string
	snap     hub.Snapshot
	calls    []string
	err      error // returned by every write
	previews int
	queries  []backends.FlowQuery
}

func (f *fakeHub) Reload()           { f.mu.Lock(); f.reloads++; f.mu.Unlock() }
func (f *fakeHub) LastError() string { return f.lastErr }
func (f *fakeHub) Snapshot() (hub.Snapshot, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snap, f.running
}
func (f *fakeHub) Refresh(context.Context) { f.mu.Lock(); f.refresh++; f.mu.Unlock() }
func (f *fakeHub) PreviewRule(s backends.RuleSpec) (hub.RulePreview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.previews++
	if err := s.Validate(); err != nil {
		return hub.RulePreview{}, err
	}
	return hub.RulePreview{Summary: "Block " + s.Target, NetworkWide: s.ScopeType == ""}, nil
}
func (f *fakeHub) QueryFlows(_ context.Context, q backends.FlowQuery) (backends.FlowPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	if f.err != nil {
		return backends.FlowPage{}, f.err
	}
	return backends.FlowPage{Flows: []backends.Flow{{Domain: "x.example", DeviceMAC: q.DeviceMAC}}, Next: "c2"}, nil
}
func (f *fakeHub) AddSchedule(_ context.Context, s hub.Schedule) (hub.Schedule, error) {
	return s, f.write("schedule " + s.RuleID + " " + s.Start + "-" + s.End + " " + s.TZ)
}
func (f *fakeHub) DeleteSchedule(id string) error { return f.write("unschedule " + id) }
func (f *fakeHub) write(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	return f.err
}
func (f *fakeHub) CreateRule(_ context.Context, s backends.RuleSpec) (backends.Rule, error) {
	return backends.Rule{ID: "new", Action: s.Action, Target: s.Target}, f.write("create " + s.Target + " " + s.ScopeType + ":" + s.Scope)
}
func (f *fakeHub) SetRulePaused(_ context.Context, id string, p bool) error {
	if p {
		return f.write("pause " + id)
	}
	return f.write("resume " + id)
}
func (f *fakeHub) DeleteRule(_ context.Context, id string) error { return f.write("delete " + id) }
func (f *fakeHub) RenameDevice(_ context.Context, r backends.DeviceRef, n string) error {
	return f.write("rename " + r.Box + "/" + r.Native + " " + n)
}
func (f *fakeHub) DismissAlarm(_ context.Context, r backends.AlarmRef) error {
	return f.write("dismiss " + r.Box + "/" + r.ID)
}

func (f *fakeHub) wrote() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func backendHarness(t *testing.T) (*harness, *fakeHub) {
	t.Helper()
	h := newHarnessWith(t, onDisk(t))
	fh := &fakeHub{running: true, snap: hub.Snapshot{
		Name: "firewalla", Capabilities: []backends.Capability{backends.CapDevices, backends.CapRules},
		Rules: []backends.Rule{{ID: "r1", Action: "block", Target: "ads.example"}},
	}}
	h.srv.Backend = fh
	h.srv.RouterUsage = &fakeUsage{}
	h.srv.BackendTransport, _ = firewallaTransport(t, "tok")
	h.ok("POST", "/api/routerusage/firewalla", `{"base_url":"home.firewalla.net","token":"tok"}`, 200)
	return h, fh
}

func TestTheDashboardShowsTheHubsViewAndNeverTheToken(t *testing.T) {
	h, fh := backendHarness(t)
	out := h.ok("GET", "/api/backend", "", 200)
	if out["available"] != true || out["connected"] != true || out["running"] != true || out["writes"] != false {
		t.Fatalf("view = %v", out)
	}
	if out["address"] != "https://home.firewalla.net" || out["name"] != "firewalla" {
		t.Fatalf("view = %v", out)
	}
	for _, k := range []string{"devices", "alarms", "flows", "audit"} {
		if list, ok := out[k].([]any); !ok || len(list) != 0 {
			t.Fatalf("%s = %#v, want []", k, out[k])
		}
	}
	if rules, _ := out["rules"].([]any); len(rules) != 1 {
		t.Fatalf("rules = %v", out["rules"])
	}
	_, body := h.call("GET", "/api/backend", "")
	if strings.Contains(body, "tok\"") {
		t.Fatalf("the token leaked: %s", body)
	}
	if fh.reloads == 0 {
		t.Fatal("connecting did not start the hub")
	}
	// Not running: still describes the connection.
	fh.running, fh.lastErr = false, "address is bad"
	out = h.ok("GET", "/api/backend", "", 200)
	if out["running"] != false || out["error"] != "address is bad" || out["connected"] != true {
		t.Fatalf("view = %v", out)
	}
}

func TestWithoutADashboardTheEndpointsSaySo(t *testing.T) {
	h := newHarness(t)
	if out := h.ok("GET", "/api/backend", "", 200); out["available"] != false || out["connected"] != false {
		t.Fatalf("view = %v", out)
	}
	for _, p := range []string{
		"/api/backend/refresh", "/api/backend/writes", "/api/backend/rules/preview", "/api/backend/rules",
		"/api/backend/rules/r/pause", "/api/backend/rules/r/resume", "/api/backend/rules/r/delete",
		"/api/backend/devices/rename", "/api/backend/alarms/dismiss",
	} {
		body := `{"confirm":true}`
		if p == "/api/backend/writes" {
			body = `{"enabled":true}`
		}
		h.expect("POST", p, body, 404)
	}
}

func TestEveryWriteNeedsAnExplicitConfirm(t *testing.T) {
	h, fh := backendHarness(t)
	rule := `{"action":"block","target_type":"domain","target":"ads.example"}`
	for _, tc := range [][2]string{
		{"/api/backend/rules", rule},
		{"/api/backend/rules/r1/pause", `{}`},
		{"/api/backend/rules/r1/resume", `{"confirm":false}`},
		{"/api/backend/rules/r1/delete", `{}`},
		{"/api/backend/devices/rename", `{"box":"b","native":"d","name":"n"}`},
		{"/api/backend/alarms/dismiss", `{"box":"b","id":"1"}`},
	} {
		h.expect("POST", tc[0], tc[1], 400)
	}
	if got := fh.wrote(); len(got) != 0 {
		t.Fatalf("unconfirmed writes reached the router: %v", got)
	}
}

func TestConfirmedWritesReachTheHub(t *testing.T) {
	h, fh := backendHarness(t)
	rule := h.ok("POST", "/api/backend/rules",
		`{"action":"block","target_type":"domain","target":"ads.example","scope_type":"device","scope":"02:00:5e:00:00:01","confirm":true}`, 200)
	if rule["ID"] != "new" && rule["id"] != "new" {
		t.Fatalf("rule = %v", rule)
	}
	h.ok("POST", "/api/backend/rules/r1/pause", `{"confirm":true}`, 200)
	h.ok("POST", "/api/backend/rules/r1/resume", `{"confirm":true}`, 200)
	h.ok("POST", "/api/backend/rules/r1/delete", `{"confirm":true}`, 200)
	h.ok("POST", "/api/backend/devices/rename", `{"box":"b","native":"d","name":"Den TV","confirm":true}`, 200)
	h.ok("POST", "/api/backend/alarms/dismiss", `{"box":"b","id":"7","confirm":true}`, 200)
	want := []string{
		"create ads.example device:02:00:5e:00:00:01", "pause r1", "resume r1", "delete r1", "rename b/d Den TV", "dismiss b/7",
	}
	got := fh.wrote()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("writes = %v", got)
	}
}

func TestPreviewSendsNothing(t *testing.T) {
	h, fh := backendHarness(t)
	out := h.ok("POST", "/api/backend/rules/preview", `{"action":"block","target_type":"domain","target":"ads.example"}`, 200)
	if out["summary"] != "Block ads.example" || out["network_wide"] != true {
		t.Fatalf("preview = %v", out)
	}
	h.expect("POST", "/api/backend/rules/preview", `{"action":"drop"}`, 400)
	h.expect("POST", "/api/backend/rules/preview", `{bad`, 400)
	if len(fh.wrote()) != 0 {
		t.Fatal("a preview wrote")
	}
}

func TestBackendFailuresBecomeTheStatusAnOwnerCanActOn(t *testing.T) {
	h, fh := backendHarness(t)
	confirm := `{"confirm":true}`
	for err, want := range map[error]int{
		backends.ErrReadOnly:                   403,
		backends.ErrInvalid:                    400,
		backends.ErrNotFound:                   404,
		backends.ErrRateLimited:                429,
		backends.ErrAuth:                       502,
		backends.ErrRefused:                    502,
		errors.New("connection refused"):       502,
		errors.New("firewalla: no such thing"): 502,
	} {
		fh.err = err
		code, body := h.call("POST", "/api/backend/rules/r1/delete", confirm)
		if code != want {
			t.Errorf("%v: HTTP %d, want %d (%s)", err, code, want, body)
		}
	}
	fh.err = backends.ErrReadOnly
	if _, body := h.call("POST", "/api/backend/rules/r1/delete", confirm); !strings.Contains(body, "Allow changes") {
		t.Fatalf("a read-only refusal should say how to fix it: %s", body)
	}
}

func TestWriteAccessIsASeparateSwitchTheOwnerTurnsOn(t *testing.T) {
	h, fh := backendHarness(t)
	before := fh.reloads
	out := h.ok("POST", "/api/backend/writes", `{"enabled":true}`, 200)
	if out["writes"] != true || fh.reloads != before+1 {
		t.Fatalf("view = %v reloads %d->%d", out, before, fh.reloads)
	}
	if w, _ := h.srv.Secrets.Firewalla(); !w.Writes || w.Token == "" {
		t.Fatalf("stored = %+v", w)
	}
	if out := h.ok("POST", "/api/backend/writes", `{"enabled":false}`, 200); out["writes"] != false {
		t.Fatalf("view = %v", out)
	}
	h.expect("POST", "/api/backend/writes", `{bad`, 400)
	if err := h.srv.Secrets.ClearFirewalla(); err != nil {
		t.Fatal(err)
	}
	h.expect("POST", "/api/backend/writes", `{"enabled":true}`, 404)
}

func TestConnectingForBandwidthDoesNotAllowChanges(t *testing.T) {
	h, _ := backendHarness(t)
	if w, _ := h.srv.Secrets.Firewalla(); w.Writes {
		t.Fatal("connecting must not switch writes on")
	}
}

func TestRefreshReadsNow(t *testing.T) {
	h, fh := backendHarness(t)
	h.ok("POST", "/api/backend/refresh", `{}`, 200)
	if fh.refresh != 1 {
		t.Fatalf("refreshes = %d", fh.refresh)
	}
}

func TestSwitchingOffOrForgettingStopsTheHubToo(t *testing.T) {
	h, fh := backendHarness(t)
	n := fh.reloads
	h.ok("POST", "/api/routerusage/firewalla/enabled", `{"enabled":false}`, 200)
	h.ok("DELETE", "/api/routerusage/firewalla", "", 200)
	if fh.reloads != n+2 {
		t.Fatalf("reloads %d -> %d: both changes must restart the hub", n, fh.reloads)
	}
}

func TestSavingFailuresOnTheWriteSwitchAreReported(t *testing.T) {
	h, _ := backendHarness(t)
	wedgeSecrets(t, h)
	h.expect("POST", "/api/backend/writes", `{"enabled":true}`, 500)
}

func TestRequestsCanBeFilteredToOneDevice(t *testing.T) {
	h, fh := backendHarness(t)
	out := h.ok("GET", "/api/backend/flows?device=02005e000001&limit=25", "", 200)
	flows, _ := out["flows"].([]any)
	if len(flows) != 1 || out["next"] != "c2" {
		t.Fatalf("out = %v", out)
	}
	if q := fh.queries[0]; q.DeviceMAC != "02005e000001" || q.Limit != 25 {
		t.Fatalf("query = %+v", q)
	}
	// Defaults and bounds.
	h.ok("GET", "/api/backend/flows?limit=99999&cursor=abc", "", 200)
	if q := fh.queries[1]; q.Limit != 100 || q.Cursor != "abc" || q.DeviceMAC != "" {
		t.Fatalf("query = %+v", q)
	}
	fh.err = backends.ErrInvalid
	h.expect("GET", "/api/backend/flows?device=zz", "", 400)
	h2 := newHarness(t)
	h2.expect("GET", "/api/backend/flows", "", 404)
}

func TestSchedulesNeedConfirmAndReachTheHub(t *testing.T) {
	h, fh := backendHarness(t)
	body := `{"rule_id":"r1","days":[1,2],"start":"21:00","end":"07:00","tz":"America/New_York"`
	h.expect("POST", "/api/backend/schedules", body+`}`, 400)
	h.ok("POST", "/api/backend/schedules", body+`,"confirm":true}`, 200)
	h.ok("POST", "/api/backend/schedules/abc/delete", `{"confirm":true}`, 200)
	h.expect("POST", "/api/backend/schedules/abc/delete", `{}`, 400)
	want := "schedule r1 21:00-07:00 America/New_York|unschedule abc"
	if got := strings.Join(fh.wrote(), "|"); got != want {
		t.Fatalf("writes = %s", got)
	}
	fh.err = backends.ErrReadOnly
	h.expect("POST", "/api/backend/schedules", body+`,"confirm":true}`, 403)
	h2 := newHarness(t)
	h2.expect("POST", "/api/backend/schedules", `{"confirm":true}`, 404)
	h2.expect("POST", "/api/backend/schedules/x/delete", `{"confirm":true}`, 404)
}

func TestWriteFailuresAreReportedForEveryKindOfChange(t *testing.T) {
	h, fh := backendHarness(t)
	fh.err = backends.ErrRefused
	for path, body := range map[string]string{
		"/api/backend/rules":                `{"action":"block","target_type":"domain","target":"a.example","confirm":true}`,
		"/api/backend/devices/rename":       `{"box":"b","native":"d","name":"n","confirm":true}`,
		"/api/backend/alarms/dismiss":       `{"box":"b","id":"1","confirm":true}`,
		"/api/backend/schedules/abc/delete": `{"confirm":true}`,
		"/api/backend/rules/r1/pause":       `{"confirm":true}`,
	} {
		h.expect("POST", path, body, 502)
	}
	for _, p := range []string{"/api/backend/rules", "/api/backend/devices/rename", "/api/backend/alarms/dismiss", "/api/backend/schedules/abc/delete", "/api/backend/rules/r1/pause", "/api/backend/rules/r1/resume", "/api/backend/rules/r1/delete"} {
		h.expect("POST", p, `{bad`, 400)
	}
}

func (f *fakeHub) BlockClient(_ context.Context, r backends.DeviceRef, block bool) error {
	if block {
		return f.write("block " + r.Box + "/" + r.Native)
	}
	return f.write("unblock " + r.Box + "/" + r.Native)
}

// unifiConsole serves just enough of a UniFi console for the portal to
// check an API key against.
func unifiConsoleTransport(t *testing.T, key string) http.RoundTripper {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/proxy/network/integration")
		switch {
		case p == "/v1/info":
			fmt.Fprint(w, `{"applicationVersion":"9"}`)
		case p == "/v1/sites":
			fmt.Fprint(w, `{"totalCount":1,"data":[{"id":"s1","internalReference":"default","name":"Home"}]}`)
		case strings.HasSuffix(p, "/clients"):
			fmt.Fprint(w, `{"totalCount":1,"data":[{"id":"c1","name":"TV","macAddress":"02:00:5e:00:00:01"}]}`)
		case strings.HasSuffix(p, "/devices"):
			fmt.Fprint(w, `{"totalCount":0,"data":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	return fwRoundTrip(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})
}

func TestConnectingAUniFiConsoleChecksTheKeyAndNeverReturnsIt(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	fh := &fakeHub{running: true}
	h.srv.Backend = fh
	h.srv.BackendTransport = unifiConsoleTransport(t, "good-key")

	h.expect("POST", "/api/backend/unifi", `{"base_url":"192.0.2.10","api_key":"wrong"}`, 400)
	if _, ok := h.srv.Secrets.UniFiAPI(); ok {
		t.Fatal("a refused key was stored")
	}
	h.expect("POST", "/api/backend/unifi", `{"base_url":"ftp://x","api_key":"good-key"}`, 400)
	h.expect("POST", "/api/backend/unifi", `{"base_url":"192.0.2.10","api_key":""}`, 400)
	h.expect("POST", "/api/backend/unifi", `{bad`, 400)

	out := h.ok("POST", "/api/backend/unifi", `{"base_url":"192.0.2.10/","api_key":"good-key","site":"Home","allow_self_signed":true}`, 200)
	if out["name"] != "unifi" || out["address"] != "https://192.0.2.10" || out["enabled"] != true || out["box"] != "Home" {
		t.Fatalf("view = %v", out)
	}
	if u, ok := h.srv.Secrets.UniFiAPI(); !ok || u.APIKey != "good-key" || !u.AllowSelfSigned || u.Writes {
		t.Fatalf("stored = %+v", u)
	}
	_, body := h.call("GET", "/api/backend", "")
	if strings.Contains(body, "good-key") {
		t.Fatalf("the key leaked: %s", body)
	}
	if fh.reloads == 0 {
		t.Fatal("connecting did not start the hub")
	}

	// The write switch applies to the connected console.
	if out := h.ok("POST", "/api/backend/writes", `{"enabled":true}`, 200); out["writes"] != true {
		t.Fatalf("view = %v", out)
	}
	if u, _ := h.srv.Secrets.UniFiAPI(); !u.Writes {
		t.Fatal("writes were not stored on the console")
	}
	h.ok("POST", "/api/backend/unifi/enabled", `{"enabled":false}`, 200)
	if out := h.ok("GET", "/api/backend", "", 200); out["enabled"] != false {
		t.Fatalf("view = %v", out)
	}
	h.ok("DELETE", "/api/backend/unifi", "", 200)
	if _, ok := h.srv.Secrets.UniFiAPI(); ok {
		t.Fatal("the console is still stored")
	}
	h.expect("POST", "/api/backend/unifi/enabled", `{"enabled":true}`, 404)
	h.expect("POST", "/api/backend/unifi/enabled", `{bad`, 400)
}

func TestWithNoDashboardTheUniFiEndpointsSaySo(t *testing.T) {
	h := newHarness(t)
	h.expect("POST", "/api/backend/unifi", `{"base_url":"192.0.2.10","api_key":"k"}`, 404)
	h.expect("POST", "/api/backend/unifi/enabled", `{"enabled":true}`, 404)
	h.expect("DELETE", "/api/backend/unifi", "", 404)
	h.expect("POST", "/api/backend/devices/block", `{"confirm":true}`, 404)
}

func TestAFirewallaBeatsAUniFiConsoleInTheView(t *testing.T) {
	h, _ := backendHarness(t) // a Firewalla is connected
	if _, err := h.srv.Secrets.SetUniFiAPI(secrets.UniFiAPI{BaseURL: "https://192.0.2.10", APIKey: "k", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if out := h.ok("GET", "/api/backend", "", 200); out["name"] != "firewalla" {
		t.Fatalf("view = %v", out)
	}
	h.ok("POST", "/api/backend/writes", `{"enabled":true}`, 200)
	if w, _ := h.srv.Secrets.Firewalla(); !w.Writes {
		t.Fatal("the write switch should follow the connection in effect")
	}
	if u, _ := h.srv.Secrets.UniFiAPI(); u.Writes {
		t.Fatal("the other connection was changed")
	}
}

func TestBlockingADeviceNeedsConfirmAndReachesTheHub(t *testing.T) {
	h, fh := backendHarness(t)
	h.expect("POST", "/api/backend/devices/block", `{"box":"s","native":"c","block":true}`, 400)
	h.ok("POST", "/api/backend/devices/block", `{"box":"s","native":"c","block":true,"confirm":true}`, 200)
	h.ok("POST", "/api/backend/devices/block", `{"box":"s","native":"c","block":false,"confirm":true}`, 200)
	if got := strings.Join(fh.wrote(), "|"); got != "block s/c|unblock s/c" {
		t.Fatalf("writes = %s", got)
	}
	fh.err = backends.ErrReadOnly
	h.expect("POST", "/api/backend/devices/block", `{"block":true,"confirm":true}`, 403)
	h.expect("POST", "/api/backend/devices/block", `{bad`, 400)
}
