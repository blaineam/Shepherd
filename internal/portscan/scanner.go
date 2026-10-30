// SPDX-License-Identifier: AGPL-3.0-or-later

package portscan

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// DialFunc opens a bare TCP connection for one connect-scan probe: nothing
// more than net.Dialer.DialContext does. Tests inject a fake that never
// touches a real socket; production uses the default, which does.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func defaultDial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// Target is one device to probe: its registry ID (for recording results
// against) and the address to dial. See TargetsFromDevices.
type Target struct {
	DeviceID string
	IP       string
}

// PortRecord is what Shepherd remembers about one port on one device: its
// current state and when it was first and most recently found open. A port
// that has never been found open has no record at all.
type PortRecord struct {
	Port      int       `json:"port"`
	Open      bool      `json:"open"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// NewlyOpened marks a port that was closed (or never seen) on the
	// previous scan and is open now. It is never set on a device's very
	// first scan: with no earlier scan to compare to, nothing is "new".
	NewlyOpened bool `json:"newly_opened,omitempty"`
	// Risky and RiskNote are set whenever an open port is on the built-in
	// risky list (RiskyPorts), every time it is found open, not only when
	// it is newly opened.
	Risky    bool   `json:"risky,omitempty"`
	RiskNote string `json:"risk_note,omitempty"`
}

// DeviceScan is one device's scan history: its address as of the last scan,
// when that scan ran, and every port ever found open on it (open now, or
// closed again since).
type DeviceScan struct {
	DeviceID    string       `json:"device_id"`
	IP          string       `json:"ip"`
	LastScanned time.Time    `json:"last_scanned"`
	Ports       []PortRecord `json:"ports"`
}

func cloneDeviceScan(ds DeviceScan) DeviceScan {
	ds.Ports = append([]PortRecord(nil), ds.Ports...)
	return ds
}

// Options configures a Scanner. The zero value is usable: it dials for real
// TCP connections, scans DefaultPorts, and keeps both concurrency and the
// per-connection timeout gentle (see docs/PORTSCAN.md).
type Options struct {
	// Dial opens one probe connection. Default: a real net.Dialer.
	Dial DialFunc
	// Ports is the list of ports every scan checks. Default: DefaultPorts.
	Ports []int
	// Concurrency bounds how many connection attempts are in flight at once,
	// across the whole scan (every device, every port), not per device.
	// Default: 10.
	Concurrency int
	// Timeout bounds one connection attempt. Default: 750ms.
	Timeout time.Duration
}

// Scanner runs gentle TCP connect scans and keeps the resulting history. It
// is safe for concurrent use.
type Scanner struct {
	dial        DialFunc
	ports       []int
	concurrency int
	timeout     time.Duration

	// OnScan, when set, is called with the result after every completed
	// Scan, whether triggered by Run's schedule or a manual call. Set it
	// once, before the scanner is used concurrently (cmd/shepherd uses it to
	// persist history after each scan). Left nil, nothing extra happens.
	OnScan func([]DeviceScan)

	scanMu sync.Mutex // serializes whole scans: manual and scheduled runs never overlap

	mu      sync.Mutex
	history map[string]*DeviceScan
}

const (
	defaultConcurrency = 10
	defaultTimeout     = 750 * time.Millisecond
)

func dedupeSortedInts(in []int) []int {
	out := append([]int(nil), in...)
	sort.Ints(out)
	n := 0
	for i, v := range out {
		if i == 0 || v != out[i-1] {
			out[n] = v
			n++
		}
	}
	return out[:n]
}

// New creates a Scanner from opts.
func New(opts Options) *Scanner {
	ports := opts.Ports
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	s := &Scanner{
		dial:        opts.Dial,
		ports:       dedupeSortedInts(ports),
		concurrency: opts.Concurrency,
		timeout:     opts.Timeout,
		history:     map[string]*DeviceScan{},
	}
	if s.dial == nil {
		s.dial = defaultDial
	}
	if s.concurrency <= 0 {
		s.concurrency = defaultConcurrency
	}
	if s.timeout <= 0 {
		s.timeout = defaultTimeout
	}
	return s
}

// Ports is the configured port list (sorted, deduplicated). Fixed at
// construction, so it is safe to read without a lock.
func (s *Scanner) Ports() []int { return append([]int(nil), s.ports...) }

// probe dials one address and reports whether it accepted the connection.
func (s *Scanner) probe(ctx context.Context, ip string, port int) bool {
	cctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	conn, err := s.dial(cctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Scan probes every port in the configured list against every target,
// bounding the number of connection attempts in flight to Concurrency at
// once, records the results into history, and returns the updated
// DeviceScan for each target that had an address. Targets with no IP are
// skipped. Scan respects ctx: a canceled context stops new probes quickly
// and in-flight ones fail fast.
//
// Only one Scan runs at a time per Scanner; a call that arrives while
// another is still running waits for it, so a manual "scan now" never piles
// on top of the scheduled one.
func (s *Scanner) Scan(ctx context.Context, targets []Target) []DeviceScan {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()

	now := time.Now()
	open := make([][]int, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.concurrency)
	var mu sync.Mutex

	for i, t := range targets {
		if t.IP == "" || ctx.Err() != nil {
			continue
		}
		for _, port := range s.ports {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(i, port int, ip string) {
				defer wg.Done()
				defer func() { <-sem }()
				if s.probe(ctx, ip, port) {
					mu.Lock()
					open[i] = append(open[i], port)
					mu.Unlock()
				}
			}(i, port, t.IP)
		}
	}
	wg.Wait()

	out := make([]DeviceScan, 0, len(targets))
	for i, t := range targets {
		if t.IP == "" {
			continue
		}
		ports := open[i]
		sort.Ints(ports)
		out = append(out, s.recordDevice(t.DeviceID, t.IP, ports, now))
	}
	sort.Slice(out, func(a, b int) bool { return out[a].DeviceID < out[b].DeviceID })

	if s.OnScan != nil {
		s.OnScan(out)
	}
	return out
}

// recordDevice folds one device's freshly observed open ports into its
// stored history and returns the updated, caller-owned copy.
func (s *Scanner) recordDevice(id, ip string, open []int, now time.Time) DeviceScan {
	s.mu.Lock()
	defer s.mu.Unlock()

	ds := s.history[id]
	firstScan := ds == nil
	if ds == nil {
		ds = &DeviceScan{DeviceID: id}
		s.history[id] = ds
	}
	ds.IP = ip
	ds.LastScanned = now

	openSet := make(map[int]bool, len(open))
	for _, p := range open {
		openSet[p] = true
	}
	existing := make(map[int]PortRecord, len(ds.Ports))
	for _, r := range ds.Ports {
		existing[r.Port] = r
	}
	allPorts := make(map[int]bool, len(existing)+len(s.ports))
	for p := range existing {
		allPorts[p] = true
	}
	for _, p := range s.ports {
		allPorts[p] = true
	}
	sorted := make([]int, 0, len(allPorts))
	for p := range allPorts {
		sorted = append(sorted, p)
	}
	sort.Ints(sorted)

	next := make([]PortRecord, 0, len(sorted))
	for _, p := range sorted {
		rec, had := existing[p]
		isOpen := openSet[p]
		if !isOpen && !had {
			continue // never seen open, not open now: nothing worth keeping
		}
		wasOpen := had && rec.Open
		rec.Port = p
		rec.Open = isOpen
		if isOpen {
			if rec.FirstSeen.IsZero() {
				rec.FirstSeen = now
			}
			rec.LastSeen = now
		}
		rec.NewlyOpened = isOpen && !wasOpen && !firstScan
		rec.Risky, rec.RiskNote = false, ""
		if isOpen {
			if note, risky := IsRisky(p); risky {
				rec.Risky, rec.RiskNote = true, note
			}
		}
		next = append(next, rec)
	}
	ds.Ports = next
	return cloneDeviceScan(*ds)
}

// Results returns every device's current scan state, sorted by device ID.
func (s *Scanner) Results() []DeviceScan {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DeviceScan, 0, len(s.history))
	for _, ds := range s.history {
		out = append(out, cloneDeviceScan(*ds))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

// Result returns one device's current scan state.
func (s *Scanner) Result(deviceID string) (DeviceScan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ds, ok := s.history[deviceID]
	if !ok {
		return DeviceScan{}, false
	}
	return cloneDeviceScan(*ds), true
}

// Run scans immediately, then again every `every` on a ticker, until ctx
// ends. lister is called fresh before every scan, so a device added or
// removed between runs is picked up without restarting. every <= 0 scans
// once and returns (used by tests; production always configures a real
// interval).
func (s *Scanner) Run(ctx context.Context, lister func() []Target, every time.Duration) {
	s.Scan(ctx, lister())
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ctx.Err() != nil {
				return
			}
			s.Scan(ctx, lister())
		}
	}
}
