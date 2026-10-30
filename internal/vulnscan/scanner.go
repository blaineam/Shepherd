// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Target is one device to probe: its registry ID, its address, and exactly
// the ports internal/portscan found open on it this scan. TargetsFromPortscan
// builds these from portscan.Scanner.Results().
type Target struct {
	DeviceID string
	IP       string
	Ports    []int
}

// Finding is one signature match on one device's one port, with its own
// little history, in the same spirit as internal/portscan.PortRecord: a
// finding that stops matching is kept (Active: false, ResolvedAt set)
// rather than discarded, so "this was exposed for a while and is now fixed"
// stays visible.
type Finding struct {
	SignatureID string    `json:"signature_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
	Port        int       `json:"port"`
	Evidence    string    `json:"evidence,omitempty"`
	Active      bool      `json:"active"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ResolvedAt  time.Time `json:"resolved_at,omitzero"`
	// NewlyFound marks a finding that was inactive (or unseen) on the
	// previous scan and active now. Never set on a device's very first
	// scan, the same rule PortRecord.NewlyOpened follows.
	NewlyFound bool `json:"newly_found,omitempty"`
}

// DeviceFindings is one device's full finding history: active findings and
// resolved ones, kept side by side.
type DeviceFindings struct {
	DeviceID    string    `json:"device_id"`
	IP          string    `json:"ip"`
	LastScanned time.Time `json:"last_scanned"`
	Findings    []Finding `json:"findings"`
}

func cloneDeviceFindings(ds DeviceFindings) DeviceFindings {
	ds.Findings = append([]Finding(nil), ds.Findings...)
	return ds
}

// ResolvedFinding names one finding that just transitioned from active to
// resolved on a device, for a caller (cmd/shepherd/vulnscan.go) that wants
// to close out whatever it did when the finding first appeared.
type ResolvedFinding struct {
	DeviceID string
	Finding  Finding
}

// Options configures a Scanner. The zero value is usable: it dials for real
// TCP connections and keeps concurrency and the per-probe timeout gentle —
// gentler than internal/portscan's own defaults, since each probe here does
// real protocol work (a read, sometimes a short write/read exchange), not
// just a connect-and-close. See docs/VULNSCAN.md.
type Options struct {
	Dial        DialFunc
	Concurrency int
	Timeout     time.Duration
}

const (
	defaultConcurrency = 5
	defaultTimeout     = 2 * time.Second
)

// Scanner runs the gentle banner/protocol probes and keeps the resulting
// finding history. Safe for concurrent use.
type Scanner struct {
	dial        DialFunc
	concurrency int
	timeout     time.Duration

	// OnScan, when set, is called after every completed Scan (scheduled or
	// manual) with every device's fresh findings and, separately, every
	// finding that just resolved. cmd/shepherd's wiring
	// (cmd/shepherd/vulnscan.go) uses a NewlyFound finding to raise an alarm
	// once and a resolved one to close it; nothing in this package imports
	// internal/alarms.
	OnScan func(devices []DeviceFindings, resolved []ResolvedFinding)

	scanMu sync.Mutex // serializes whole scans: manual and scheduled runs never overlap

	mu      sync.Mutex
	history map[string]*DeviceFindings
}

// New creates a Scanner from opts.
func New(opts Options) *Scanner {
	s := &Scanner{
		dial:        opts.Dial,
		concurrency: opts.Concurrency,
		timeout:     opts.Timeout,
		history:     map[string]*DeviceFindings{},
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

type portProbe struct {
	port    int
	matches []Match
}

// Scan probes every interesting port of every target, bounding the number
// of connections in flight to Concurrency at once, records the results into
// history, and returns the updated DeviceFindings for each target that had
// an address. Only one Scan runs at a time; a call that arrives while
// another is still running waits for it.
func (s *Scanner) Scan(ctx context.Context, targets []Target) []DeviceFindings {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()

	now := time.Now()
	probed := make([][]portProbe, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.concurrency)
	var mu sync.Mutex

	for i, t := range targets {
		if t.IP == "" || ctx.Err() != nil {
			continue
		}
		for _, port := range t.Ports {
			if !interestingPorts[port] {
				continue
			}
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(i, port int, ip string) {
				defer wg.Done()
				defer func() { <-sem }()
				p := probePort(ctx, s.dial, s.timeout, ip, port)
				matches := Evaluate(p)
				mu.Lock()
				probed[i] = append(probed[i], portProbe{port: port, matches: matches})
				mu.Unlock()
			}(i, port, t.IP)
		}
	}
	wg.Wait()

	out := make([]DeviceFindings, 0, len(targets))
	var resolved []ResolvedFinding
	for i, t := range targets {
		if t.IP == "" {
			continue
		}
		ds, res := s.recordDevice(t.DeviceID, t.IP, probed[i], now)
		out = append(out, ds)
		resolved = append(resolved, res...)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].DeviceID < out[b].DeviceID })

	if s.OnScan != nil {
		s.OnScan(out, resolved)
	}
	return out
}

type findingKey struct {
	signature string
	port      int
}

// recordDevice folds one device's freshly probed ports into its stored
// history and returns the updated, caller-owned copy, plus every finding
// that just transitioned from active to resolved.
func (s *Scanner) recordDevice(id, ip string, probed []portProbe, now time.Time) (DeviceFindings, []ResolvedFinding) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ds := s.history[id]
	firstScan := ds == nil
	if ds == nil {
		ds = &DeviceFindings{DeviceID: id}
		s.history[id] = ds
	}
	ds.IP = ip
	ds.LastScanned = now

	fresh := map[findingKey]Match{}
	for _, pp := range probed {
		for _, m := range pp.matches {
			fresh[findingKey{m.Signature.ID, pp.port}] = m
		}
	}

	existing := map[findingKey]Finding{}
	for _, f := range ds.Findings {
		existing[findingKey{f.SignatureID, f.Port}] = f
	}

	var resolved []ResolvedFinding
	next := make([]Finding, 0, len(existing)+len(fresh))

	for k, f := range existing {
		if m, ok := fresh[k]; ok {
			wasActive := f.Active
			f.Active = true
			f.LastSeen = now
			f.NewlyFound = !wasActive // reopened findings are "new" again, same rule PortRecord.NewlyOpened follows
			f.Evidence = m.Evidence
			f.Name, f.Description, f.Severity = m.Signature.Name, m.Signature.Description, m.Signature.Severity
			f.ResolvedAt = time.Time{}
			next = append(next, f)
			delete(fresh, k)
			continue
		}
		if f.Active {
			f.Active = false
			f.NewlyFound = false
			f.ResolvedAt = now
			resolved = append(resolved, ResolvedFinding{DeviceID: id, Finding: f})
		}
		next = append(next, f)
	}
	for k, m := range fresh {
		next = append(next, Finding{
			SignatureID: m.Signature.ID, Name: m.Signature.Name, Description: m.Signature.Description,
			Severity: m.Signature.Severity, Port: k.port, Evidence: m.Evidence,
			Active: true, FirstSeen: now, LastSeen: now, NewlyFound: !firstScan,
		})
	}
	sort.Slice(next, func(a, b int) bool {
		if next[a].Port != next[b].Port {
			return next[a].Port < next[b].Port
		}
		return next[a].SignatureID < next[b].SignatureID
	})
	ds.Findings = next
	return cloneDeviceFindings(*ds), resolved
}

// Results returns every device's current finding state, sorted by device ID.
func (s *Scanner) Results() []DeviceFindings {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DeviceFindings, 0, len(s.history))
	for _, ds := range s.history {
		out = append(out, cloneDeviceFindings(*ds))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

// Result returns one device's current finding state.
func (s *Scanner) Result(deviceID string) (DeviceFindings, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ds, ok := s.history[deviceID]
	if !ok {
		return DeviceFindings{}, false
	}
	return cloneDeviceFindings(*ds), true
}

// Run scans immediately, then again every `every` on a ticker, until ctx
// ends. lister is called fresh before every scan. every <= 0 scans once and
// returns (used by tests; production always configures a real interval).
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
