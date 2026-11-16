// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"path/filepath"
	"sync"

	"shepherd/internal/alarms"
	"shepherd/internal/backends"
	"shepherd/internal/backends/firewalla"
	"shepherd/internal/backends/hub"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
	"shepherd/internal/routerusage"
	"shepherd/internal/secrets"
)

var errNoBackend = errors.New("no router or firewall is connected")

// backendManager runs the dashboard hub for the owner's connected router
// (docs/BACKENDS.md) and restarts it when the connection changes. Nothing
// starts until a Firewalla account is connected and switched on, so a
// Shepherd whose owner never connected one does no work and holds no
// credentials.
type backendManager struct {
	parent  context.Context
	sec     *secrets.Store
	reg     *devices.Registry
	qlog    *dnsengine.QueryLog
	alarms  *alarms.Engine
	dataDir string
	// transport replaces the HTTP transport, for tests.
	transport http.RoundTripper

	mu     sync.Mutex
	cur    *hub.Hub
	client *firewalla.Client
	key    secrets.Firewalla // what cur was built from, minus the write switch
	cancel context.CancelFunc
	done   chan struct{}
	err    string
}

func startBackend(ctx context.Context, sec *secrets.Store, reg *devices.Registry, qlog *dnsengine.QueryLog, al *alarms.Engine, dataDir string) *backendManager {
	m := &backendManager{parent: ctx, sec: sec, reg: reg, qlog: qlog, alarms: al, dataDir: dataDir}
	m.Reload()
	return m
}

// Reload makes what is running match the stored connection. A change to
// only the write switch is applied in place, so toggling it never makes the
// hub forget what it has already ingested.
func (m *backendManager) Reload() {
	w, ok := m.sec.Firewalla()
	want := ok && w.Enabled
	same := func(a, b secrets.Firewalla) bool {
		return a.BaseURL == b.BaseURL && a.Token == b.Token && a.Box == b.Box
	}

	m.mu.Lock()
	if m.cur != nil && want && same(m.key, w) {
		m.client.SetReadOnly(!w.Writes)
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	m.stop()
	if !want {
		m.setErr("")
		return
	}
	c, err := firewalla.New(firewalla.Config{BaseURL: w.BaseURL, Token: w.Token, Box: w.Box, ReadOnly: !w.Writes, Transport: m.transport})
	if err != nil {
		m.setErr(err.Error())
		log.Printf("backend: not starting: %v", err)
		return
	}
	h := hub.New(hub.Options{
		Backend: c, FlowSink: m.qlog.Add, AlarmSink: m.raise,
		Resolve:      m.resolve,
		StatePath:    filepath.Join(m.dataDir, "backend-firewalla.json"),
		SchedulePath: filepath.Join(m.dataDir, "backend-schedules.json"),
		Logf:         log.Printf,
	})
	ctx, cancel := context.WithCancel(m.parent)
	done := make(chan struct{})
	m.mu.Lock()
	m.cur, m.client, m.key, m.cancel, m.done, m.err = h, c, w, cancel, done, ""
	m.mu.Unlock()
	go func() { defer close(done); h.Run(ctx) }()
	log.Printf("backend: reading %s every %s (writes %s)", c.Name(), hub.DefaultInterval, map[bool]string{true: "on", false: "off"}[w.Writes])
}

func (m *backendManager) raise(e alarms.Event) bool {
	if m.alarms == nil {
		return false
	}
	return m.alarms.Raise(e)
}

func (m *backendManager) resolve(mac, ip string) string {
	if m.reg == nil {
		return ""
	}
	if mac != "" {
		if d, ok := m.reg.FindByMAC(mac); ok {
			return d.ID
		}
	}
	if ip != "" {
		if d, ok := m.reg.FindByIP(ip); ok {
			return d.ID
		}
	}
	return ""
}

func (m *backendManager) setErr(s string) {
	m.mu.Lock()
	m.err = s
	m.mu.Unlock()
}

func (m *backendManager) stop() {
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	m.cur, m.client, m.cancel, m.done = nil, nil, nil, nil
	m.key = secrets.Firewalla{}
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// Stop ends the hub, if one is running.
func (m *backendManager) Stop() { m.stop() }

func (m *backendManager) hub() *hub.Hub {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// Totals is the running per-device byte counts as bandwidth samples, for
// the bandwidth reader. It is nil when no hub is running.
func (m *backendManager) samples() []routerusage.Sample {
	h := m.hub()
	if h == nil {
		return nil
	}
	totals := h.Totals()
	out := make([]routerusage.Sample, 0, len(totals))
	for mac, t := range totals {
		out = append(out, routerusage.Sample{MAC: mac, DownBytes: t.Down, UpBytes: t.Up})
	}
	return out
}

// ---- what the portal calls ---------------------------------------------------

// LastError is why the hub could not start, "" when it could or none is
// configured.
func (m *backendManager) LastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

// Snapshot is the hub's latest view; ok is false when none is running.
func (m *backendManager) Snapshot() (hub.Snapshot, bool) {
	h := m.hub()
	if h == nil {
		return hub.Snapshot{}, false
	}
	return h.Snapshot(), true
}

func (m *backendManager) PreviewRule(spec backends.RuleSpec) (hub.RulePreview, error) {
	h := m.hub()
	if h == nil {
		return hub.RulePreview{}, errNoBackend
	}
	return h.PreviewRule(spec)
}

func (m *backendManager) CreateRule(ctx context.Context, spec backends.RuleSpec) (backends.Rule, error) {
	h := m.hub()
	if h == nil {
		return backends.Rule{}, errNoBackend
	}
	return h.CreateRule(ctx, spec)
}

func (m *backendManager) SetRulePaused(ctx context.Context, id string, paused bool) error {
	h := m.hub()
	if h == nil {
		return errNoBackend
	}
	return h.SetRulePaused(ctx, id, paused)
}

func (m *backendManager) DeleteRule(ctx context.Context, id string) error {
	h := m.hub()
	if h == nil {
		return errNoBackend
	}
	return h.DeleteRule(ctx, id)
}

func (m *backendManager) RenameDevice(ctx context.Context, ref backends.DeviceRef, name string) error {
	h := m.hub()
	if h == nil {
		return errNoBackend
	}
	return h.RenameDevice(ctx, ref, name)
}

func (m *backendManager) DismissAlarm(ctx context.Context, ref backends.AlarmRef) error {
	h := m.hub()
	if h == nil {
		return errNoBackend
	}
	return h.DismissAlarm(ctx, ref)
}

func (m *backendManager) QueryFlows(ctx context.Context, q backends.FlowQuery) (backends.FlowPage, error) {
	h := m.hub()
	if h == nil {
		return backends.FlowPage{}, errNoBackend
	}
	return h.QueryFlows(ctx, q)
}

func (m *backendManager) AddSchedule(ctx context.Context, s hub.Schedule) (hub.Schedule, error) {
	h := m.hub()
	if h == nil {
		return hub.Schedule{}, errNoBackend
	}
	return h.AddSchedule(ctx, s)
}

func (m *backendManager) DeleteSchedule(id string) error {
	h := m.hub()
	if h == nil {
		return errNoBackend
	}
	return h.DeleteSchedule(id)
}

// Refresh reads everything now, for the portal's refresh button.
func (m *backendManager) Refresh(ctx context.Context) {
	if h := m.hub(); h != nil {
		h.Refresh(ctx)
	}
}
