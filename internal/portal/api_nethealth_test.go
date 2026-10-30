// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/nethealth"
)

// fakeNethealthConn/fakeNethealthDial mirror fakePortscanConn/fakePortscanDial
// (internal/portal/api_portscan_test.go): no real socket, every address in
// open succeeds, everything else is a simulated connection refusal.
type fakeNethealthConn struct{}

func (fakeNethealthConn) Read([]byte) (int, error)         { return 0, errors.New("no data") }
func (fakeNethealthConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeNethealthConn) Close() error                     { return nil }
func (fakeNethealthConn) LocalAddr() net.Addr              { return nil }
func (fakeNethealthConn) RemoteAddr() net.Addr             { return nil }
func (fakeNethealthConn) SetDeadline(time.Time) error      { return nil }
func (fakeNethealthConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeNethealthConn) SetWriteDeadline(time.Time) error { return nil }

func fakeNethealthDialAll(ctx context.Context, network, address string) (net.Conn, error) {
	return fakeNethealthConn{}, nil
}

func TestNethealthStatusDefaults(t *testing.T) {
	h := newHarness(t)
	m := h.ok("GET", "/api/nethealth", "", 200)
	if m["enabled"] != false || m["bufferbloat_enabled"] != false || m["degraded"] != false {
		t.Fatalf("got %+v", m)
	}
	if _, has := m["current"]; has {
		t.Errorf("current present with no probe ever run: %v", m)
	}
	targets, ok := m["targets"].([]any)
	if !ok || len(targets) != 0 {
		t.Fatalf("targets = %v, want an empty list", m["targets"])
	}
}

func TestNethealthStatusReflectsLatestSampleAndEnabledFlags(t *testing.T) {
	h := newHarness(t)
	h.srv.Nethealth = nethealth.New(nethealth.Options{Dial: fakeNethealthDialAll, Burst: 2, Timeout: time.Second})
	h.srv.Nethealth.ProbeNow(context.Background(), []string{"9.9.9.10", "1.1.1.1"})
	h.srv.NethealthEnabled = true
	h.srv.NethealthBufferbloatEnabled = true

	m := h.ok("GET", "/api/nethealth", "", 200)
	if m["enabled"] != true || m["bufferbloat_enabled"] != true {
		t.Fatalf("got %+v", m)
	}
	cur, ok := m["current"].(map[string]any)
	if !ok {
		t.Fatalf("current missing: %+v", m)
	}
	if cur["reachable_targets"] != float64(2) || cur["total_targets"] != float64(2) {
		t.Fatalf("current = %+v", cur)
	}
	targets, _ := m["targets"].([]any)
	if len(targets) != 2 {
		t.Fatalf("targets = %v, want 2", targets)
	}
}

func TestNethealthDegradedReflectsOpenAlarm(t *testing.T) {
	h := newHarness(t)
	m := h.ok("GET", "/api/nethealth", "", 200)
	if m["degraded"] != false {
		t.Fatalf("degraded = %v, want false with no alarm raised", m["degraded"])
	}

	h.alarms.Raise(alarms.Event{Type: alarms.TypeNetworkDegraded, Source: "test", Title: "t", Key: "network-degraded|"})
	h.alarms.Drain()
	m = h.ok("GET", "/api/nethealth", "", 200)
	if m["degraded"] != true {
		t.Fatalf("degraded = %v, want true with an open alarm", m["degraded"])
	}

	page := h.alarms.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeNetworkDegraded}}})
	if page.Total != 1 {
		t.Fatalf("expected exactly one alarm, got %d", page.Total)
	}
	if _, err := h.alarms.Resolve(alarms.Selector{IDs: []string{page.Alarms[0].ID}}); err != nil {
		t.Fatal(err)
	}
	m = h.ok("GET", "/api/nethealth", "", 200)
	if m["degraded"] != false {
		t.Fatalf("degraded = %v, want false once resolved", m["degraded"])
	}
}

func TestNethealthProbeNowRequiresPriorTargets(t *testing.T) {
	h := newHarness(t)
	h.expect("POST", "/api/nethealth/probe", "{}", 400)
}

func TestNethealthProbeNowRunsAndRecordsHistory(t *testing.T) {
	h := newHarness(t)
	h.srv.Nethealth = nethealth.New(nethealth.Options{Dial: fakeNethealthDialAll, Burst: 2, Timeout: time.Second})
	// Simulate the scheduled probe having already run once, which is what
	// gives a manual probe its target list (docs/NETHEALTH.md).
	h.srv.Nethealth.ProbeNow(context.Background(), []string{"9.9.9.10"})

	m := h.ok("POST", "/api/nethealth/probe", "{}", 200)
	if m["reachable_targets"] != float64(1) || m["total_targets"] != float64(1) {
		t.Fatalf("got %+v", m)
	}

	series := h.ok("GET", "/api/nethealth/series", "", 200)
	points, _ := series["points"].([]any)
	if len(points) != 2 {
		t.Fatalf("expected 2 recorded samples (the seed probe + the manual one), got %d: %+v", len(points), points)
	}
	if series["bucket"] != "raw" {
		t.Errorf("bucket = %v, want raw for a short default range", series["bucket"])
	}
}

func TestNethealthSeriesRejectsBadRange(t *testing.T) {
	h := newHarness(t)
	h.expect("GET", "/api/nethealth/series?from=not-a-time", "", 400)
}

func TestNethealthSeriesBucketSelection(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()

	short := h.ok("GET", "/api/nethealth/series?from="+now.Add(-time.Hour).Format(time.RFC3339)+"&to="+now.Format(time.RFC3339), "", 200)
	if short["bucket"] != "raw" {
		t.Errorf("short range bucket = %v, want raw", short["bucket"])
	}

	medium := h.ok("GET", "/api/nethealth/series?from="+now.Add(-20*24*time.Hour).Format(time.RFC3339)+"&to="+now.Format(time.RFC3339), "", 200)
	if medium["bucket"] != "hour" {
		t.Errorf("medium range bucket = %v, want hour", medium["bucket"])
	}

	long := h.ok("GET", "/api/nethealth/series?from="+now.Add(-200*24*time.Hour).Format(time.RFC3339)+"&to="+now.Format(time.RFC3339), "", 200)
	if long["bucket"] != "day" {
		t.Errorf("long range bucket = %v, want day", long["bucket"])
	}

	explicit := h.ok("GET", "/api/nethealth/series?from="+now.Add(-time.Hour).Format(time.RFC3339)+"&to="+now.Format(time.RFC3339)+"&bucket=day", "", 200)
	if explicit["bucket"] != "day" {
		t.Errorf("explicit bucket = %v, want day (caller's own choice wins)", explicit["bucket"])
	}
}

func TestNethealthBufferbloatHistoryAndManualRun(t *testing.T) {
	h := newHarness(t)
	loaded := make(chan struct{}, 1)
	load := func(ctx context.Context) error {
		loaded <- struct{}{}
		<-ctx.Done()
		return nil
	}
	h.srv.Nethealth = nethealth.New(nethealth.Options{
		Dial: fakeNethealthDialAll, Load: load, Burst: 1, Timeout: time.Second, BufferbloatDuration: 20 * time.Millisecond,
	})
	h.srv.Nethealth.ProbeNow(context.Background(), []string{"9.9.9.10"})

	empty := h.ok("GET", "/api/nethealth/bufferbloat", "", 200)
	if pts, _ := empty["points"].([]any); len(pts) != 0 {
		t.Fatalf("expected no bufferbloat history yet, got %v", pts)
	}

	m := h.ok("POST", "/api/nethealth/bufferbloat/run", "{}", 200)
	if m["grade"] == "" && m["load_error"] == nil {
		t.Fatalf("expected a grade or a load_error, got %+v", m)
	}
	select {
	case <-loaded:
	default:
		t.Error("expected the configured Load to have been invoked")
	}

	hist := h.ok("GET", "/api/nethealth/bufferbloat", "", 200)
	pts, _ := hist["points"].([]any)
	if len(pts) != 1 {
		t.Fatalf("expected 1 bufferbloat record, got %d: %v", len(pts), pts)
	}
}

func TestNethealthBufferbloatRunRequiresPriorTargets(t *testing.T) {
	h := newHarness(t)
	h.expect("POST", "/api/nethealth/bufferbloat/run", "{}", 400)
}
