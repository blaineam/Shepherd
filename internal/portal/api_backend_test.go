// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"shepherd/internal/backends"
	"shepherd/internal/backends/hub"
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
	h.srv.FirewallaTransport, _ = firewallaTransport(t, "tok")
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
