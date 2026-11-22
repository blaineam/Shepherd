// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
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
