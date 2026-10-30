// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// connScript lets a test control exactly what byte sequence probePort reads
// back for one dialed address, without touching a real socket.
type connScript map[string][][]byte

func dialByAddress(scripts connScript) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		script, ok := scripts[address]
		if !ok {
			return nil, errors.New("connection refused")
		}
		return &scriptedConn{script: append([][]byte(nil), script...)}, nil
	}
}

func addr(ip string, port int) string { return net.JoinHostPort(ip, strconv.Itoa(port)) }

func TestNewDefaults(t *testing.T) {
	s := New(Options{})
	if s.dial == nil {
		t.Fatal("New must set a default Dial")
	}
	if s.concurrency != defaultConcurrency {
		t.Fatalf("concurrency = %d, want %d", s.concurrency, defaultConcurrency)
	}
	if s.timeout != defaultTimeout {
		t.Fatalf("timeout = %v, want %v", s.timeout, defaultTimeout)
	}
}

func TestScanSkipsTargetsWithNoAddress(t *testing.T) {
	s := New(Options{Dial: dialByAddress(nil)})
	results := s.Scan(context.Background(), []Target{{DeviceID: "no-ip", IP: "", Ports: []int{21}}})
	if len(results) != 0 {
		t.Fatalf("Scan() = %v, want no results for a target with no address", results)
	}
}

func TestScanSkipsPortsItDoesNotUnderstand(t *testing.T) {
	var calls int32
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("should never be dialed")
	}
	s := New(Options{Dial: dial})
	// 3306 (MySQL) has no probe: Scan must not even connect to it.
	s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.10", Ports: []int{3306}}})
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("dial called %d times for an uninteresting port, want 0", calls)
	}
}

func TestScanFindsTelnetExposed(t *testing.T) {
	s := New(Options{Dial: dialByAddress(connScript{addr("192.0.2.10", 23): nil}), Concurrency: 2, Timeout: time.Second})
	r := s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.10", Ports: []int{23}}})
	if len(r) != 1 || len(r[0].Findings) != 1 {
		t.Fatalf("Scan() = %+v, want one finding", r)
	}
	f := r[0].Findings[0]
	if f.SignatureID != "telnet-exposed" || !f.Active || !f.NewlyFound {
		t.Fatalf("finding = %+v, want active telnet-exposed, NewlyFound even on the first scan", f)
	}
}

func TestScanHistoryTracksNewAndResolvedFindings(t *testing.T) {
	scripts := connScript{}
	s := New(Options{Dial: dialByAddress(scripts), Concurrency: 2, Timeout: time.Second})
	target := Target{DeviceID: "d1", IP: "192.0.2.20", Ports: []int{23}}

	// Scan 1: telnet not even reachable yet (no script entry -> refused).
	r := s.Scan(context.Background(), []Target{target})[0]
	if len(r.Findings) != 0 {
		t.Fatalf("scan 1 findings = %+v, want none", r.Findings)
	}

	// Scan 2: telnet opens. Second scan for this device, so NewlyFound must be set.
	scripts[addr("192.0.2.20", 23)] = nil
	var resolved []ResolvedFinding
	s.OnScan = func(_ []DeviceFindings, res []ResolvedFinding) { resolved = res }
	r = s.Scan(context.Background(), []Target{target})[0]
	f := findFinding(t, r.Findings, "telnet-exposed")
	if !f.Active || !f.NewlyFound {
		t.Fatalf("finding = %+v, want active and newly found", f)
	}
	if len(resolved) != 0 {
		t.Fatalf("resolved = %+v, want none yet", resolved)
	}
	firstSeen := f.FirstSeen

	// Scan 3: stays open: no longer "newly" found, FirstSeen unchanged.
	r = s.Scan(context.Background(), []Target{target})[0]
	f = findFinding(t, r.Findings, "telnet-exposed")
	if !f.Active || f.NewlyFound {
		t.Fatalf("finding = %+v, want active and NOT newly found on the third scan", f)
	}
	if !f.FirstSeen.Equal(firstSeen) {
		t.Fatalf("FirstSeen changed from %v to %v", firstSeen, f.FirstSeen)
	}

	// Scan 4: telnet closes again (port no longer open, so portscan would
	// not even hand vulnscan this port; simulate that by scanning with no
	// ports at all). The finding is kept, marked resolved, and reported via
	// OnScan's resolved list.
	r = s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.20", Ports: []int{}}})[0]
	f = findFinding(t, r.Findings, "telnet-exposed")
	if f.Active {
		t.Fatalf("finding = %+v, want resolved (inactive)", f)
	}
	if f.ResolvedAt.IsZero() {
		t.Fatal("ResolvedAt must be set once a finding resolves")
	}
	if !f.FirstSeen.Equal(firstSeen) {
		t.Fatal("FirstSeen must survive resolution")
	}
	if len(resolved) != 1 || resolved[0].Finding.SignatureID != "telnet-exposed" || resolved[0].DeviceID != "d1" {
		t.Fatalf("resolved = %+v, want exactly the telnet-exposed finding for d1", resolved)
	}

	// Scan 5: reopens: active and newly found again, FirstSeen preserved.
	r = s.Scan(context.Background(), []Target{target})[0]
	f = findFinding(t, r.Findings, "telnet-exposed")
	if !f.Active || !f.NewlyFound {
		t.Fatalf("finding = %+v, want active and newly found again", f)
	}
	if !f.FirstSeen.Equal(firstSeen) {
		t.Fatalf("FirstSeen changed on reopening: got %v, want %v", f.FirstSeen, firstSeen)
	}
	if f.ResolvedAt.IsZero() == false {
		t.Fatalf("ResolvedAt must be cleared once the finding is active again, got %v", f.ResolvedAt)
	}
}

func findFinding(t *testing.T, findings []Finding, id string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.SignatureID == id {
			return f
		}
	}
	t.Fatalf("no finding %q in %+v", id, findings)
	return Finding{}
}

func TestScanConcurrencyIsBounded(t *testing.T) {
	const limit = 2
	var cur, max int32
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		n := atomic.AddInt32(&cur, 1)
		for {
			m := atomic.LoadInt32(&max)
			if n <= m {
				break
			}
			if atomic.CompareAndSwapInt32(&max, m, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&cur, -1)
		return nil, errors.New("closed")
	}
	s := New(Options{Dial: dial, Concurrency: limit, Timeout: time.Second})
	ports := []int{21, 22, 23, 25, 80, 110, 143, 445, 2375}
	s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.50", Ports: ports}})

	if got := atomic.LoadInt32(&max); got == 0 {
		t.Fatal("no dials were observed")
	} else if got > int32(limit) {
		t.Fatalf("max concurrent dials = %d, want <= %d", got, limit)
	}
}

func TestScanRespectsAlreadyCanceledContext(t *testing.T) {
	var calls int32
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("should not be called")
	}
	s := New(Options{Dial: dial, Concurrency: 2, Timeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Scan(ctx, []Target{{DeviceID: "d1", IP: "192.0.2.60", Ports: []int{22, 23}}})
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("dial called %d times on an already-canceled context, want 0", calls)
	}
}

func TestScanOnlyOneAtATime(t *testing.T) {
	var running int32
	var sawOverlap int32
	release := make(chan struct{})
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if atomic.AddInt32(&running, 1) > 1 {
			atomic.StoreInt32(&sawOverlap, 1)
		}
		<-release
		atomic.AddInt32(&running, -1)
		return nil, errors.New("closed")
	}
	s := New(Options{Dial: dial, Concurrency: 4, Timeout: time.Minute})

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.80", Ports: []int{23}}})
		}()
	}
	time.Sleep(30 * time.Millisecond)
	close(release)
	wg.Wait()

	if atomic.LoadInt32(&sawOverlap) != 0 {
		t.Fatal("two Scan calls ran their probes concurrently; Scan must serialize whole scans")
	}
}

func TestOnScanCalledAfterEachScan(t *testing.T) {
	s := New(Options{Dial: dialByAddress(nil)})
	var got []DeviceFindings
	s.OnScan = func(r []DeviceFindings, _ []ResolvedFinding) { got = r }
	s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.90", Ports: []int{23}}})
	if len(got) != 1 || got[0].DeviceID != "d1" {
		t.Fatalf("OnScan received %+v, want the scan's own result", got)
	}
}

func TestResultsAndResult(t *testing.T) {
	s := New(Options{Dial: dialByAddress(connScript{addr("192.0.2.100", 23): nil}), Concurrency: 2, Timeout: time.Second})
	s.Scan(context.Background(), []Target{
		{DeviceID: "b", IP: "192.0.2.100", Ports: []int{23}},
		{DeviceID: "a", IP: "192.0.2.101", Ports: []int{23}},
	})

	all := s.Results()
	if len(all) != 2 || all[0].DeviceID != "a" || all[1].DeviceID != "b" {
		t.Fatalf("Results() = %+v, want sorted by device ID", all)
	}
	one, ok := s.Result("b")
	if !ok || len(one.Findings) != 1 {
		t.Fatalf("Result(\"b\") = %+v, %v", one, ok)
	}
	if _, ok := s.Result("missing"); ok {
		t.Fatal("Result() reported a device that was never scanned")
	}

	// Mutating what the caller got back must not affect the scanner's state.
	one.Findings[0].Active = false
	again, _ := s.Result("b")
	if !again.Findings[0].Active {
		t.Fatal("Result() leaked internal state: a caller's edit changed the scanner's own record")
	}
}

func TestRunScansOnScheduleAndOnDemand(t *testing.T) {
	calls := make(chan struct{}, 8)
	s := New(Options{Dial: dialByAddress(nil)})
	s.OnScan = func([]DeviceFindings, []ResolvedFinding) { calls <- struct{}{} }
	lister := func() []Target { return []Target{{DeviceID: "d1", IP: "192.0.2.110", Ports: []int{23}}} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx, lister, 10*time.Millisecond); close(done) }()

	deadline := time.After(2 * time.Second)
	seen := 0
	for seen < 3 {
		select {
		case <-calls:
			seen++
		case <-deadline:
			t.Fatalf("Run only triggered %d scans in time, want at least 3", seen)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was canceled")
	}
}

func TestRunWithoutIntervalScansOnceAndReturns(t *testing.T) {
	s := New(Options{Dial: dialByAddress(nil)})
	var n int32
	s.OnScan = func([]DeviceFindings, []ResolvedFinding) { atomic.AddInt32(&n, 1) }
	done := make(chan struct{})
	go func() {
		s.Run(context.Background(), func() []Target { return nil }, 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run with every<=0 must scan once and return")
	}
	if atomic.LoadInt32(&n) != 1 {
		t.Fatalf("OnScan called %d times, want 1", n)
	}
}
