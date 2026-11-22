// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"sync"

	"shepherd/internal/alarms"
	"shepherd/internal/backends"
	"shepherd/internal/backends/firewalla"
	"shepherd/internal/backends/fwlocal"
	"shepherd/internal/backends/hub"
	"shepherd/internal/backends/unifi"
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
	// geo places a flow's remote address on the map; it returns nil when
	// the map is switched off.
	geo func() dnsengine.Geo
	// transport replaces the HTTP transport, for tests.
	transport http.RoundTripper

	mu     sync.Mutex
	cur    *hub.Hub
	name   string // which backend cur runs
	rename bool   // cur's product can rename a device at all
	limit  int    // the longest device name cur's product takes, 0 for none
	setRO  func(bool)
	key    string // what cur was built from, minus the write switch
	cancel context.CancelFunc
	done   chan struct{}
	err    string
}

func startBackend(ctx context.Context, sec *secrets.Store, reg *devices.Registry, engine *dnsengine.Engine, al *alarms.Engine, dataDir string) *backendManager {
	m := &backendManager{parent: ctx, sec: sec, reg: reg, qlog: engine.Log, alarms: al, dataDir: dataDir,
		geo: func() dnsengine.Geo { return engine.Geo }}
	m.Reload()
	return m
}

// connection is the backend the stored settings ask for.
type connection struct {
	name    string
	key     string
	writes  bool
	backend backends.Backend
	// nameLimit is the longest device name the product accepts.
	nameLimit int
	setRO     func(bool)
}

// wanted builds the backend the owner has connected and switched on, or
// nil when there is none. One backend runs at a time: a Firewalla wins over
// a UniFi console when both are connected, since it also reports requests.
func (m *backendManager) wanted() (*connection, error) {
	// Shepherd on the Firewalla box itself: the box's own API, no account.
	if w, ok := m.sec.Firewalla(); ok && w.Enabled && w.Local {
		c, err := fwlocal.New(fwlocal.Config{BaseURL: w.BaseURL, ReadOnly: !w.Writes, Transport: m.transport})
		if err != nil {
			return nil, err
		}
		return &connection{name: "firewalla", key: "firewalla-local|" + w.BaseURL, writes: w.Writes, backend: c, setRO: c.SetReadOnly, nameLimit: fwlocal.MaxNameLen}, nil
	}
	if w, ok := m.sec.Firewalla(); ok && w.Enabled {
		c, err := firewalla.New(firewalla.Config{BaseURL: w.BaseURL, Token: w.Token, Box: w.Box, ReadOnly: !w.Writes, Transport: m.transport})
		if err != nil {
			return nil, err
		}
		return &connection{name: "firewalla", key: "firewalla|" + w.BaseURL + "|" + w.Token + "|" + w.Box, writes: w.Writes, backend: c, setRO: c.SetReadOnly, nameLimit: 32}, nil
	}
	if u, ok := m.sec.UniFiAPI(); ok && u.Enabled {
		c, err := unifi.New(unifi.Config{BaseURL: u.BaseURL, APIKey: u.APIKey, Site: u.Site, AllowSelfSigned: u.AllowSelfSigned, ReadOnly: !u.Writes, Transport: m.transport})
		if err != nil {
			return nil, err
		}
		return &connection{name: "unifi", key: fmt.Sprintf("unifi|%s|%s|%s|%t", u.BaseURL, u.APIKey, u.Site, u.AllowSelfSigned), writes: u.Writes, backend: c, setRO: c.SetReadOnly}, nil
	}
	return nil, nil
}

// Reload makes what is running match the stored connection. A change to
// only the write switch is applied in place, so toggling it never makes the
// hub forget what it has already ingested.
func (m *backendManager) Reload() {
	conn, err := m.wanted()
	if err != nil {
		m.stop()
		m.setErr(err.Error())
		log.Printf("backend: not starting: %v", err)
		return
	}

	m.mu.Lock()
	if m.cur != nil && conn != nil && conn.key == m.key {
		m.setRO(!conn.writes)
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	m.stop()
	m.setErr("")
	if conn == nil {
		return
	}
	h := hub.New(hub.Options{
		Backend: conn.backend, FlowSink: m.qlog.Add, AlarmSink: m.raise,
		Resolve:      m.resolve,
		Locate:       m.locate,
		StatePath:    filepath.Join(m.dataDir, "backend-"+conn.name+".json"),
		SchedulePath: filepath.Join(m.dataDir, "backend-"+conn.name+"-schedules.json"),
		BlockedPath:  filepath.Join(m.dataDir, "backend-"+conn.name+"-blocked.json"),
		Logf:         log.Printf,
	})
	ctx, cancel := context.WithCancel(m.parent)
	done := make(chan struct{})
	m.mu.Lock()
	m.cur, m.name, m.setRO, m.key, m.cancel, m.done = h, conn.name, conn.setRO, conn.key, cancel, done
	_, m.rename = conn.backend.(backends.DeviceRenamer)
	m.limit = conn.nameLimit
	m.mu.Unlock()
	go func() { defer close(done); h.Run(ctx) }()
	log.Printf("backend: reading %s every %s (writes %s)", conn.name, hub.DefaultInterval, map[bool]string{true: "on", false: "off"}[conn.writes])
}

// active reports the name of the backend that is running, "" for none.
func (m *backendManager) active() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == nil {
		return ""
	}
	return m.name
}

// nameLimit is the longest device name the running backend accepts.
func (m *backendManager) nameLimit() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.limit
}

// canRename reports whether the running backend's product can rename a
// device, whether or not writes are switched on.
func (m *backendManager) canRename() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur != nil && m.rename
}

// locate places an address on the map, when the map is on and knows it.
func (m *backendManager) locate(ip string) (dnsengine.Dest, bool) {
	if m.geo == nil {
		return dnsengine.Dest{}, false
	}
	g := m.geo()
	parsed := net.ParseIP(ip)
	if g == nil || parsed == nil {
		return dnsengine.Dest{}, false
	}
	return g.Locate(parsed)
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
	m.cur, m.name, m.setRO, m.cancel, m.done = nil, "", nil, nil, nil
	m.key = ""
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

func (m *backendManager) SetDeviceGroup(ctx context.Context, ref backends.DeviceRef, name string) error {
	h := m.hub()
	if h == nil {
		return errNoBackend
	}
	return h.SetDeviceGroup(ctx, ref, name)
}

func (m *backendManager) BlockClient(ctx context.Context, ref backends.DeviceRef, block bool) error {
	h := m.hub()
	if h == nil {
		return errNoBackend
	}
	return h.BlockClient(ctx, ref, block)
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
