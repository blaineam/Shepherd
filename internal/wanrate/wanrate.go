// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wanrate measures how fast a network interface is moving bytes
// right now, from the kernel's own counters. Where Shepherd runs on the
// router itself, the WAN interface's counters are the whole network's
// traffic, read to the second, with nothing in the path and no router API
// to ask (docs/TRAFFIC.md).
package wanrate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultEvery is how often the counters are read.
const DefaultEvery = time.Second

// staleAfter is how old a reading can be before Rate stops offering it.
const staleAfter = 5 * time.Second

// Reader returns an interface's received and sent byte counts.
type Reader func() (rx, tx uint64, err error)

// SysReader reads iface's counters from sysfs, as Linux keeps them.
func SysReader(iface string) Reader {
	dir := filepath.Join("/sys/class/net", iface, "statistics")
	return fileReader(dir)
}

func fileReader(dir string) Reader {
	one := func(name string) (uint64, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	return func() (uint64, uint64, error) {
		rx, err := one("rx_bytes")
		if err != nil {
			return 0, 0, fmt.Errorf("wanrate: %w", err)
		}
		tx, err := one("tx_bytes")
		if err != nil {
			return 0, 0, fmt.Errorf("wanrate: %w", err)
		}
		return rx, tx, nil
	}
}

// Meter turns successive counter readings into a rate.
type Meter struct {
	read Reader
	now  func() time.Time

	mu       sync.Mutex
	rx, tx   uint64
	at       time.Time
	down, up float64
	rateAt   time.Time
}

// New returns a Meter over read. now is the clock; nil uses the real one.
func New(read Reader, now func() time.Time) *Meter {
	if now == nil {
		now = time.Now
	}
	return &Meter{read: read, now: now}
}

// Sample reads the counters once. Two readings make a rate. A counter that
// went backwards (the interface was reset) starts the measurement again
// rather than reporting a rate that never happened.
func (m *Meter) Sample() error {
	rx, tx, err := m.read()
	if err != nil {
		return err
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.at.IsZero() && rx >= m.rx && tx >= m.tx {
		if secs := now.Sub(m.at).Seconds(); secs > 0 {
			// Received on the WAN side is what the network downloaded.
			m.down, m.up, m.rateAt = float64(rx-m.rx)/secs, float64(tx-m.tx)/secs, now
		}
	}
	m.rx, m.tx, m.at = rx, tx, now
	return nil
}

// Rate is the latest rate in bytes per second. ok is false until two
// readings have been taken, and again once the latest is stale.
func (m *Meter) Rate() (down, up float64, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rateAt.IsZero() || m.now().Sub(m.rateAt) > staleAfter {
		return 0, 0, false
	}
	return m.down, m.up, true
}

// Run samples every interval until ctx ends. A reading that fails is
// skipped: the rate goes stale and Rate says so.
func (m *Meter) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = DefaultEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	_ = m.Sample()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = m.Sample()
		}
	}
}
