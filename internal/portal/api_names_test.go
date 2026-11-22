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
	"time"

	"shepherd/internal/backends/hub"
	"shepherd/internal/namesync"
	"shepherd/internal/routerusage"
)

// fakeNames is a NameSync that records what it was asked to do.
type fakeNames struct {
	mu         sync.Mutex
	st         namesync.Status
	rep        namesync.Report
	previewErr error
	autoErr    error
	started    int
	busy       bool
}

func (f *fakeNames) Status() namesync.Status { f.mu.Lock(); defer f.mu.Unlock(); return f.st }
func (f *fakeNames) Preview(context.Context) (namesync.Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rep, f.previewErr
}
func (f *fakeNames) Start(ctx context.Context) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	// The run outlives the request that asked for it.
	if f.busy || ctx.Err() != nil {
		return false
	}
	f.started++
	return true
}
func (f *fakeNames) SetAuto(on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.autoErr != nil {
		return f.autoErr
	}
	f.st.Auto = on
	return nil
}

func TestConnectionsListsEveryKindSideBySideAndNoCredential(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	out := h.ok("GET", "/api/connections", "", 200)
	if out["available"] != false {
		t.Fatalf("available with nothing wired = %v", out["available"])
	}
	for _, k := range []string{"eero", "firewalla", "unifi", "unifi_api"} {
		if c, _ := out[k].(map[string]any); c["connected"] != false || len(c) != 1 {
			t.Fatalf("%s with nothing stored = %v", k, out[k])
		}
	}
	if _, ok := out["bandwidth"]; ok {
		t.Fatal("a bandwidth status with no reader")
	}

	// An eero account and a Firewalla, both at once.
	connected(t, h)
	now := time.Now()
	fh := &fakeHub{running: true, lastErr: "an old failure", snap: hub.Snapshot{Name: "firewalla", ReadOnly: true, Status: hub.Status{Name: "firewalla", LastPoll: &now}}}
	h.srv.Backend = fh
	h.srv.RouterUsage = &fakeUsage{st: routerusage.Status{Source: "firewalla", Enabled: true}}
	h.srv.BackendTransport, _ = firewallaTransport(t, "tok")
	h.ok("POST", "/api/routerusage/firewalla", `{"base_url":"home.firewalla.net","token":"tok"}`, 200)

	out = h.ok("GET", "/api/connections", "", 200)
	if out["available"] != true {
		t.Fatalf("view = %v", out)
	}
	eero, _ := out["eero"].(map[string]any)
	if eero["connected"] != true || eero["network"] != "3001" || eero["enabled"] != true {
		t.Fatalf("eero = %v", eero)
	}
	fw, _ := out["firewalla"].(map[string]any)
	if fw["connected"] != true || fw["address"] != "https://home.firewalla.net" || fw["writes"] != false {
		t.Fatalf("firewalla = %v", fw)
	}
	if bw, _ := out["bandwidth"].(map[string]any); bw["source"] != "firewalla" {
		t.Fatalf("bandwidth = %v", out["bandwidth"])
	}
	if dash, _ := out["dashboard"].(map[string]any); dash["name"] != "firewalla" || dash["read_only"] != true {
		t.Fatalf("dashboard = %v", out["dashboard"])
	}
	if out["dashboard_error"] != "an old failure" {
		t.Fatalf("dashboard_error = %v", out["dashboard_error"])
	}
	_, body := h.call("GET", "/api/connections", "")
	if strings.Contains(body, `"tok"`) || strings.Contains(body, `"token"`) || strings.Contains(body, "api_key") || strings.Contains(body, "password") {
		t.Fatalf("a credential leaked: %s", body)
	}
}

func TestNamesAreUnavailableWithoutTheEngine(t *testing.T) {
	h := newHarness(t)
	if out := h.ok("GET", "/api/names", "", 200); out["available"] != false {
		t.Fatalf("view = %v", out)
	}
	h.expect("POST", "/api/names/preview", `{}`, 404)
	h.expect("POST", "/api/names/sync", `{"confirm":true}`, 404)
	h.expect("POST", "/api/names/auto", `{"enabled":true,"confirm":true}`, 404)
}

func TestNamesPreviewWritesNothingAndSyncNeedsConfirming(t *testing.T) {
	h := newHarness(t)
	fn := &fakeNames{rep: namesync.Report{DryRun: true, Written: 2, Changes: []namesync.Change{{MAC: "02005e000001", Name: "Den TV", Reason: "first", From: "eero"}}}}
	h.srv.Names = fn

	out := h.ok("GET", "/api/names", "", 200)
	if out["available"] != true || out["auto"] != false || out["running"] != false {
		t.Fatalf("view = %v", out)
	}
	prev := h.ok("POST", "/api/names/preview", `{}`, 200)
	if prev["dry_run"] != true || prev["written"] != float64(2) {
		t.Fatalf("preview = %v", prev)
	}
	if fn.started != 0 {
		t.Fatal("a preview started a sync")
	}

	h.expect("POST", "/api/names/sync", `{}`, 400)
	if fn.started != 0 {
		t.Fatal("an unconfirmed sync ran")
	}
	if out := h.ok("POST", "/api/names/sync", `{"confirm":true}`, 200); out["running"] != true || fn.started != 1 {
		t.Fatalf("sync = %v, started %d", out, fn.started)
	}
	fn.busy = true
	h.expect("POST", "/api/names/sync", `{"confirm":true}`, 409)
}

func TestNamesPreviewFailuresSayWhatToDo(t *testing.T) {
	h := newHarness(t)
	fn := &fakeNames{}
	h.srv.Names = fn
	for _, c := range []struct {
		err  error
		code int
		want string
	}{
		{namesync.ErrNothingToSync, 409, "Connect a router or firewall first"},
		{context.DeadlineExceeded, 504, "took too long"},
		{errors.New("boom"), 502, "could not be read: boom"},
	} {
		fn.previewErr = c.err
		code, body := h.call("POST", "/api/names/preview", `{}`)
		if code != c.code || !strings.Contains(body, c.want) {
			t.Errorf("%v: %d %q", c.err, code, body)
		}
	}
}

func TestKeepingNamesInSyncNeedsConfirmingAndSwitchingOffDoesNot(t *testing.T) {
	h := newHarness(t)
	fn := &fakeNames{}
	h.srv.Names = fn
	h.expect("POST", "/api/names/auto", `{"enabled":true}`, 400)
	if fn.st.Auto {
		t.Fatal("switched on without confirming")
	}
	if out := h.ok("POST", "/api/names/auto", `{"enabled":true,"confirm":true}`, 200); out["auto"] != true {
		t.Fatalf("view = %v", out)
	}
	if out := h.ok("POST", "/api/names/auto", `{"enabled":false}`, 200); out["auto"] != false {
		t.Fatalf("view = %v", out)
	}
	fn.autoErr = errors.New("disk full")
	h.expect("POST", "/api/names/auto", `{"enabled":false}`, 500)
	h.expect("POST", "/api/names/auto", `not json`, 400)
}

// localBoxTransport answers like a Firewalla's loopback API, wherever the
// request was addressed, and counts the requests.
func localBoxTransport(t *testing.T, up *bool) (http.RoundTripper, *int) {
	t.Helper()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if !*up || r.URL.Path != "/v1/encipher/simple" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, `{"code":200,"data":{"hosts":[{"mac":"02:00:5E:00:00:41","name":"TV"}]}}`)
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	return fwRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "127.0.0.1:8834" {
			t.Errorf("the local API was asked for at %s", r.URL.Host)
		}
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	}), &hits
}

func TestAFirewallaBoxIsConnectedWithNoCredentialOnlyWhenItAnswers(t *testing.T) {
	h := newHarnessWith(t, onDisk(t))
	fh := &fakeHub{}
	usage := &fakeUsage{}
	h.srv.Backend, h.srv.RouterUsage = fh, usage
	up := false
	var hits *int
	h.srv.BackendTransport, hits = localBoxTransport(t, &up)

	// Not on a box: the screen is told so, and connecting is refused.
	if out := h.ok("GET", "/api/connections", "", 200); out["local_firewalla"] != false {
		t.Fatalf("view = %v", out)
	}
	code, body := h.call("POST", "/api/backend/firewalla-local", `{}`)
	if code != 400 || !strings.Contains(body, "not running on a Firewalla box") {
		t.Fatalf("connect off a box = %d %q", code, body)
	}
	if _, ok := h.srv.Secrets.Firewalla(); ok || fh.reloads != 0 {
		t.Fatal("a failed connect was stored")
	}
	// The probe is remembered, so a screen refreshing does not hammer it.
	before := *hits
	h.ok("GET", "/api/connections", "", 200)
	if *hits != before {
		t.Fatalf("the probe ran again: %d then %d", before, *hits)
	}

	up = true
	out := h.ok("POST", "/api/backend/firewalla-local", `{}`, 200)
	if out["connected"] != true || out["local"] != true || out["address"] != "http://127.0.0.1:8834" || out["writes"] != false {
		t.Fatalf("connected = %v", out)
	}
	w, ok := h.srv.Secrets.Firewalla()
	if !ok || !w.Local || !w.Enabled || w.Token != "" || fh.reloads != 1 || usage.reloads != 1 {
		t.Fatalf("stored = %+v, %v, reloads %d/%d", w, ok, fh.reloads, usage.reloads)
	}
	conns := h.ok("GET", "/api/connections", "", 200)
	if fw, _ := conns["firewalla"].(map[string]any); conns["local_firewalla"] != true || fw["local"] != true {
		t.Fatalf("connections = %v", conns)
	}
	if ru := h.ok("GET", "/api/routerusage", "", 200); ru["source"] != "firewalla" || ru["local"] != true {
		t.Fatalf("routerusage = %v", ru)
	}

	// The same switches work on it, and connecting needs the dashboard.
	h.ok("POST", "/api/backend/writes", `{"enabled":true}`, 200)
	if w, _ := h.srv.Secrets.Firewalla(); !w.Writes || !w.Local {
		t.Fatalf("after allowing changes = %+v", w)
	}
	h.srv.RouterUsage = nil
	h.ok("POST", "/api/backend/firewalla-local", `{}`, 200)
	h.srv.Backend = nil
	h.expect("POST", "/api/backend/firewalla-local", `{}`, 404)
	h.expect("POST", "/api/backend/firewalla-local", `nope`, 400)
}

// The group sync answers the same four calls as the name sync, on its own
// engine: one must never drive the other.
func TestTheGroupSyncHasItsOwnEngineAndTheSameRules(t *testing.T) {
	h := newHarness(t)
	if out := h.ok("GET", "/api/groupsync", "", 200); out["available"] != false {
		t.Fatalf("view = %v", out)
	}
	h.expect("POST", "/api/groupsync/preview", `{}`, 404)
	h.expect("POST", "/api/groupsync/sync", `{"confirm":true}`, 404)
	h.expect("POST", "/api/groupsync/auto", `{"enabled":true,"confirm":true}`, 404)

	names := &fakeNames{}
	groups := &fakeNames{rep: namesync.Report{DryRun: true, Written: 3}}
	h.srv.Names, h.srv.Groups = names, groups
	if prev := h.ok("POST", "/api/groupsync/preview", `{}`, 200); prev["written"] != float64(3) {
		t.Fatalf("preview = %v", prev)
	}
	h.expect("POST", "/api/groupsync/sync", `{}`, 400)
	if out := h.ok("POST", "/api/groupsync/sync", `{"confirm":true}`, 200); out["running"] != true {
		t.Fatalf("sync = %v", out)
	}
	h.expect("POST", "/api/groupsync/auto", `{"enabled":true}`, 400)
	if out := h.ok("POST", "/api/groupsync/auto", `{"enabled":true,"confirm":true}`, 200); out["auto"] != true {
		t.Fatalf("auto = %v", out)
	}
	if groups.started != 1 || !groups.st.Auto || names.started != 0 || names.st.Auto {
		t.Fatalf("groups %+v, names %+v", groups, names)
	}
	groups.previewErr = namesync.ErrNothingToSync
	code, body := h.call("POST", "/api/groupsync/preview", `{}`)
	if code != 409 || !strings.Contains(body, "sync device groups with") {
		t.Fatalf("nothing to sync = %d %q", code, body)
	}
	groups.busy = true
	code, body = h.call("POST", "/api/groupsync/sync", `{"confirm":true}`)
	if code != 409 || !strings.Contains(body, "device groups is already running") {
		t.Fatalf("busy = %d %q", code, body)
	}
	h.expect("POST", "/api/groupsync/sync", `nope`, 400)
}
