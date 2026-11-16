// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/backends"
	"shepherd/internal/backends/hub"
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
	"shepherd/internal/secrets"
)

// liveMSP is a Firewalla that answers: one device, one flow that has just
// ended, and it records the writes it receives.
type liveMSP struct {
	mu     sync.Mutex
	writes []string
}

func (l *liveMSP) transport(t *testing.T) http.RoundTripper {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v2/devices":
			fmt.Fprint(w, `[{"id":"02:00:5E:00:00:01","gid":"box-1","name":"TV","online":true}]`)
		case r.Method == "GET" && r.URL.Path == "/v2/flows":
			fmt.Fprintf(w, `{"results":[{"ts":%d,"gid":"box-1","protocol":"tcp","direction":"outbound","download":4000,"upload":100,
			  "device":{"id":"02:00:5E:00:00:01","ip":"192.0.2.5","name":"TV"},"destination":{"ip":"198.51.100.7","name":"example.org"}}]}`, time.Now().Unix()+1)
		case r.Method == "GET":
			fmt.Fprint(w, `{"results":[]}`)
		default:
			l.mu.Lock()
			l.writes = append(l.writes, r.Method+" "+r.URL.Path)
			l.mu.Unlock()
			fmt.Fprint(w, `{"id":"new"}`)
		}
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	return rtFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func connected(t *testing.T, writes bool) (*backendManager, *liveMSP, *dnsengine.QueryLog) {
	t.Helper()
	sec := testSecrets(t)
	if _, err := sec.SetFirewalla(secrets.Firewalla{BaseURL: "https://home.firewalla.net", Token: "tok", Enabled: true, Writes: writes}); err != nil {
		t.Fatal(err)
	}
	msp := &liveMSP{}
	qlog := dnsengine.NewQueryLog(50)
	reg := devices.New(devices.Options{NodeID: "test", Vendor: func(string) string { return "" }})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m := &backendManager{parent: ctx, sec: sec, reg: reg, qlog: qlog, dataDir: t.TempDir(), transport: msp.transport(t)}
	t.Cleanup(m.Stop)
	m.Reload()
	return m, msp, qlog
}

func awaitBackend(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestAConnectedFirewallaFeedsFlowsIntoTheQueryLogAndCounters(t *testing.T) {
	m, _, qlog := connected(t, false)
	awaitBackend(t, "a flow in the query log", func() bool { return len(qlog.All()) > 0 })
	e := qlog.All()[0]
	if e.Name != "example.org" || e.Type != "FLOW" || e.Client != "192.0.2.5" || e.Device != "TV" {
		t.Fatalf("entry = %+v", e)
	}
	awaitBackend(t, "the counters", func() bool { return len(m.samples()) > 0 })
	s := m.samples()[0]
	if s.MAC != "02005e000001" || s.DownBytes != 4000 || s.UpBytes != 100 {
		t.Fatalf("sample = %+v", s)
	}
	awaitBackend(t, "a snapshot with the device", func() bool {
		snap, ok := m.Snapshot()
		return ok && len(snap.Devices) == 1
	})
}

func TestWritesAreRefusedUntilTheyAreSwitchedOnAndSwitchingDoesNotRestart(t *testing.T) {
	m, msp, _ := connected(t, false)
	awaitBackend(t, "the hub", func() bool { _, ok := m.Snapshot(); return ok })
	first := m.hub()
	ctx := context.Background()

	if err := m.DeleteRule(ctx, "r1"); !errors.Is(err, backends.ErrReadOnly) {
		t.Fatalf("err = %v", err)
	}
	if _, err := m.CreateRule(ctx, backends.RuleSpec{Action: "block", TargetType: "domain", Target: "a.example"}); !errors.Is(err, backends.ErrReadOnly) {
		t.Fatalf("err = %v", err)
	}
	if len(msp.writes) != 0 {
		t.Fatalf("a read-only connection sent %v", msp.writes)
	}

	if _, err := m.sec.SetFirewallaWrites(true); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	if m.hub() != first {
		t.Fatal("switching writes on restarted the hub, which would re-ingest recent flows")
	}
	if err := m.DeleteRule(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRulePaused(ctx, "r1", true); err != nil {
		t.Fatal(err)
	}
	if err := m.RenameDevice(ctx, backends.DeviceRef{Box: "box-1", Native: "02:00:5E:00:00:01"}, "Den TV"); err != nil {
		t.Fatal(err)
	}
	if err := m.DismissAlarm(ctx, backends.AlarmRef{Box: "box-1", ID: "7"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateRule(ctx, backends.RuleSpec{Action: "block", TargetType: "domain", Target: "a.example"}); err != nil {
		t.Fatal(err)
	}
	if p, err := m.PreviewRule(backends.RuleSpec{Action: "block", TargetType: "domain", Target: "a.example"}); err != nil || p.Summary == "" {
		t.Fatalf("%+v, %v", p, err)
	}
	msp.mu.Lock()
	n := len(msp.writes)
	msp.mu.Unlock()
	if n != 5 {
		t.Fatalf("writes = %v", msp.writes)
	}

	if _, err := m.sec.SetFirewallaWrites(false); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	if err := m.DeleteRule(ctx, "r1"); !errors.Is(err, backends.ErrReadOnly) {
		t.Fatalf("after switching off: %v", err)
	}
}

func TestChangingTheAccountRestartsAndSwitchingOffStops(t *testing.T) {
	m, _, _ := connected(t, false)
	first := m.hub()
	if first == nil {
		t.Fatal("no hub")
	}
	if _, err := m.sec.SetFirewalla(secrets.Firewalla{BaseURL: "https://other.firewalla.net", Token: "tok2", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	if m.hub() == nil || m.hub() == first {
		t.Fatal("a different account must get a new hub")
	}
	if _, err := m.sec.SetFirewallaEnabled(false); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	if m.hub() != nil || m.samples() != nil {
		t.Fatal("switching off must stop the hub")
	}
	m.Refresh(context.Background()) // harmless with nothing running
}

func TestWithNothingConnectedEveryCallSaysSo(t *testing.T) {
	m := &backendManager{parent: context.Background(), sec: testSecrets(t), qlog: dnsengine.NewQueryLog(1)}
	m.Reload()
	ctx := context.Background()
	if _, err := m.CreateRule(ctx, backends.RuleSpec{}); !errors.Is(err, errNoBackend) {
		t.Fatal(err)
	}
	if _, err := m.PreviewRule(backends.RuleSpec{}); !errors.Is(err, errNoBackend) {
		t.Fatal(err)
	}
	for _, err := range []error{
		m.SetRulePaused(ctx, "r", true), m.DeleteRule(ctx, "r"),
		m.RenameDevice(ctx, backends.DeviceRef{}, "n"), m.DismissAlarm(ctx, backends.AlarmRef{}),
	} {
		if !errors.Is(err, errNoBackend) {
			t.Fatal(err)
		}
	}
	m.Stop()
}

func TestTheBackendResolvesDevicesByMACThenAddress(t *testing.T) {
	reg := devices.New(devices.Options{NodeID: "test", Vendor: func(string) string { return "" }})
	id := reg.Observe(devices.Observation{MAC: "02:00:5e:00:00:09", IP: "192.0.2.9", Source: devices.SourceNeighbor})
	m := &backendManager{reg: reg}
	if got := m.resolve("02005e000009", ""); got != id {
		t.Fatalf("by MAC = %q, want %q", got, id)
	}
	if got := m.resolve("", "192.0.2.9"); got != id {
		t.Fatalf("by address = %q", got)
	}
	if m.resolve("", "") != "" || m.resolve("02005e0000ff", "192.0.2.77") != "" {
		t.Fatal("an unknown device resolved")
	}
	if (&backendManager{}).resolve("02005e000009", "") != "" {
		t.Fatal("no registry, no device")
	}
	if (&backendManager{}).raise(alarmsEvent()) {
		t.Fatal("no alarm engine, nothing raised")
	}
}

func alarmsEvent() alarms.Event { return alarms.Event{Type: alarms.TypeBackendAlarm, Title: "x"} }

// Dashboard mode: Shepherd serves no DNS at all and is only a portal.
func TestDashboardModeServesNoDNSAndStillServesThePortal(t *testing.T) {
	dir := t.TempDir()
	dnsPort, webPort := freePort(t), freePort(t)
	cfg := fmt.Sprintf(`data_dir = %q
[dns]
enabled = false
listen = ["127.0.0.1:%d"]
upstreams = ["192.0.2.53"]
[portal]
listen = "127.0.0.1:%d"
[map]
enabled = false
[devices]
neighbors = false
mdns = false
reverse_dns = false
[arp]
enabled = false
[portscan.wan_exposure]
enabled = false
`, filepath.Join(dir, "data"), dnsPort, webPort)
	path := filepath.Join(dir, "shepherd.toml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, path, false, os.Stdout) }()
	r := &running{t: t, portalBase: fmt.Sprintf("http://127.0.0.1:%d", webPort)}
	awaitBackend(t, "the portal token", func() bool {
		b, err := os.ReadFile(filepath.Join(dir, "data", "portal-token"))
		r.token = strings.TrimSpace(string(b))
		return err == nil && len(r.token) >= 32
	})
	var out map[string]any
	awaitBackend(t, "the portal to answer", func() bool {
		req, _ := http.NewRequest("GET", r.portalBase+"/api/backend", nil)
		req.Header.Set("Authorization", "Bearer "+r.token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200 && json.NewDecoder(resp.Body).Decode(&out) == nil
	})
	if out["available"] != true || out["connected"] != false {
		t.Fatalf("backend view = %v", out)
	}

	// The DNS port was never taken.
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", dnsPort))
	if err != nil {
		t.Fatalf("dashboard mode bound the DNS port: %v", err)
	}
	pc.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop")
	}
}

func TestDNSIsOnUnlessSwitchedOff(t *testing.T) {
	off, on := false, true
	if !(config.DNS{}).On() || !(config.DNS{Enabled: &on}).On() || (config.DNS{Enabled: &off}).On() {
		t.Fatal("dns.enabled defaults to on and only false turns it off")
	}
}

func TestFlowsAndSchedulesGoThroughTheManager(t *testing.T) {
	none := &backendManager{parent: context.Background(), sec: testSecrets(t), qlog: dnsengine.NewQueryLog(1)}
	if _, err := none.QueryFlows(context.Background(), backends.FlowQuery{}); !errors.Is(err, errNoBackend) {
		t.Fatal(err)
	}
	if _, err := none.AddSchedule(context.Background(), hub.Schedule{}); !errors.Is(err, errNoBackend) {
		t.Fatal(err)
	}
	if err := none.DeleteSchedule("x"); !errors.Is(err, errNoBackend) {
		t.Fatal(err)
	}

	m, _, _ := connected(t, true)
	awaitBackend(t, "the rules", func() bool { s, ok := m.Snapshot(); return ok && s.Status.LastPoll != nil })
	page, err := m.QueryFlows(context.Background(), backends.FlowQuery{DeviceMAC: "02005e000001"})
	if err != nil || len(page.Flows) != 1 {
		t.Fatalf("%+v, %v", page, err)
	}
	if _, err := m.AddSchedule(context.Background(), hub.Schedule{RuleID: "nope", Days: []int{1}, Start: "09:00", End: "10:00", TZ: "UTC"}); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("a schedule for a rule that is not there: %v", err)
	}
	if err := m.DeleteSchedule("nope"); !errors.Is(err, backends.ErrNotFound) {
		t.Fatal(err)
	}
	m.Refresh(context.Background())
	if m.raise(alarms.Event{Type: alarms.TypeBackendAlarm, Title: "x"}) {
		t.Fatal("there is no alarm engine in this test")
	}
}
