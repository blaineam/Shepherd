// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"testing"
)

type fakeUpdater struct {
	checks, applies int
	applyErr        error
}

func (f *fakeUpdater) Status() any { return map[string]any{"current": "1.0.0", "available": true} }
func (f *fakeUpdater) CheckNow(context.Context) any {
	f.checks++
	return map[string]any{"current": "1.0.0", "available": false}
}
func (f *fakeUpdater) Apply(context.Context) error { f.applies++; return f.applyErr }

var _ Updater = (*fakeUpdater)(nil)

func TestUpdateReportsOffWithoutAService(t *testing.T) {
	h := newHarness(t)
	out := h.ok("GET", "/api/update", "", 200)
	if out["enabled"] != false || out["current"] != "test" {
		t.Fatalf("status = %v", out)
	}
	h.expect("POST", "/api/update/check", "", 404)
	h.expect("POST", "/api/update/apply", "", 404)
}

func TestUpdateStatusCheckAndApply(t *testing.T) {
	h := newHarness(t)
	f := &fakeUpdater{}
	h.srv.Update = f
	out := h.ok("GET", "/api/update", "", 200)
	if out["enabled"] != true || out["status"].(map[string]any)["available"] != true {
		t.Fatalf("status = %v", out)
	}
	if got := h.ok("POST", "/api/update/check", "", 200); got["status"].(map[string]any)["available"] != false || f.checks != 1 {
		t.Fatalf("check = %v", got)
	}
	if got := h.ok("POST", "/api/update/apply", "", 200); got["restarting"] != true || f.applies != 1 {
		t.Fatalf("apply = %v", got)
	}
	f.applyErr = errors.New("this Shepherd is up to date")
	h.expect("POST", "/api/update/apply", "", 409)
}
