// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"testing"
	"time"

	"shepherd/internal/selftest"
)

type fakeSelftest struct {
	has  bool
	rep  selftest.Report
	runs int
}

func (f *fakeSelftest) Latest() (selftest.Report, bool) { return f.rep, f.has }
func (f *fakeSelftest) RunOnce(context.Context) selftest.Report {
	f.runs++
	f.has = true
	return f.rep
}

func TestSelftestEndpointOffWaitingAndReporting(t *testing.T) {
	h := newHarness(t)
	if m := h.ok("GET", "/api/selftest", "", 200); m["enabled"] != false {
		t.Fatalf("off: %+v", m)
	}
	h.expect("POST", "/api/selftest/run", "", 400)

	fs := &fakeSelftest{rep: selftest.Report{Time: time.Unix(1700000000, 0).UTC(), Status: selftest.StatusFail,
		Problems: []selftest.Problem{{Check: selftest.CheckListener, Subject: "10.0.0.20:53/udp", Severity: selftest.StatusFail, Message: "Nothing answers DNS on 10.0.0.20:53 over UDP"}}}}
	h.srv.Selftest = fs
	m := h.ok("GET", "/api/selftest", "", 200)
	if m["enabled"] != true || m["report"] != nil {
		t.Fatalf("before the first round: %+v", m)
	}
	m = h.ok("POST", "/api/selftest/run", "", 200)
	rep, _ := m["report"].(map[string]any)
	if fs.runs != 1 || rep["status"] != "fail" {
		t.Fatalf("run: %+v", m)
	}
	probs, _ := rep["problems"].([]any)
	if len(probs) != 1 || probs[0].(map[string]any)["check"] != "listener" {
		t.Errorf("problems = %v", rep["problems"])
	}
	m = h.ok("GET", "/api/selftest", "", 200)
	if rep, _ := m["report"].(map[string]any); rep == nil || rep["status"] != "fail" {
		t.Errorf("latest: %+v", m)
	}
}
