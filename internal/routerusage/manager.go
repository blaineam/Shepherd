// SPDX-License-Identifier: AGPL-3.0-or-later

package routerusage

import (
	"context"
	"sync"
)

// Build returns the Collector to run right now. ok is false when the owner
// has not connected a router, or has turned the collector off, which is a
// state rather than a failure. An error means a connection exists but
// could not be opened -- an unreadable stored session, say -- and is shown
// in the Status.
type Build func() (c *Collector, ok bool, err error)

// Manager runs at most one Collector and restarts it whenever the owner
// changes the connection in the portal. Nothing starts until Reload is
// called, so a Shepherd whose owner never connected a router does no work
// and holds no credentials.
type Manager struct {
	parent context.Context
	build  Build
	logf   func(string, ...any)

	mu      sync.Mutex
	cur     *Collector
	stop    context.CancelFunc
	done    chan struct{}
	lastErr string
}

// NewManager returns a Manager whose collectors live as long as parent.
func NewManager(parent context.Context, build Build, logf func(string, ...any)) *Manager {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Manager{parent: parent, build: build, logf: logf}
}

// Reload stops whatever is running and starts what the configuration now
// asks for. It is what the portal calls after the owner signs in, picks a
// network, flips the switch or disconnects. Safe to call repeatedly.
func (m *Manager) Reload() {
	m.stopCurrent()

	c, ok, err := m.build()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastErr = ""
	if err != nil {
		m.lastErr = err.Error()
		m.logf("routerusage: not starting: %v", err)
		return
	}
	if !ok {
		return
	}
	ctx, cancel := context.WithCancel(m.parent)
	done := make(chan struct{})
	m.cur, m.stop, m.done = c, cancel, done
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	st := c.Status()
	m.logf("routerusage: reading per-device bandwidth from %s every %ds", st.Source, st.IntervalSeconds)
}

// Stop ends the running collector, if any, and waits for it to finish.
func (m *Manager) Stop() { m.stopCurrent() }

func (m *Manager) stopCurrent() {
	m.mu.Lock()
	stop, done := m.stop, m.done
	m.cur, m.stop, m.done = nil, nil, nil
	m.mu.Unlock()
	if stop == nil {
		return
	}
	stop()
	<-done
}

// Live is the running collector's last poll, or nothing when none is
// running.
func (m *Manager) Live() []LiveDevice {
	m.mu.Lock()
	c := m.cur
	m.mu.Unlock()
	if c == nil {
		return nil
	}
	return c.Live()
}

// Status reports the running collector's state, or an empty Status with
// Enabled false when nothing is running.
func (m *Manager) Status() Status {
	m.mu.Lock()
	c, lastErr := m.cur, m.lastErr
	m.mu.Unlock()
	if c == nil {
		return Status{LastError: lastErr}
	}
	return c.Status()
}
