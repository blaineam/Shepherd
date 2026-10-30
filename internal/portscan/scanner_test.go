// SPDX-License-Identifier: AGPL-3.0-or-later

package portscan

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

// fakeConn is a net.Conn that touches no real socket at all: just enough to
// satisfy the interface so Scanner can Close() it.
type fakeConn struct{ closed bool }

func (c *fakeConn) Read([]byte) (int, error)         { return 0, errFakeEOF }
func (c *fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *fakeConn) Close() error                     { c.closed = true; return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return nil }
func (c *fakeConn) RemoteAddr() net.Addr             { return nil }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

var errFakeEOF = errors.New("fakeConn: no data")

// fakeDial answers "open" for every address in open, "closed" (connection
// refused) for everything else. It never opens a real socket.
func fakeDial(open map[string]bool) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if open[address] {
			return &fakeConn{}, nil
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
}

func addr(ip string, port int) string { return net.JoinHostPort(ip, strconv.Itoa(port)) }

func TestNewDefaults(t *testing.T) {
	s := New(Options{})
	if s.dial == nil {
		t.Fatal("New must set a default Dial")
	}
	if len(s.ports) == 0 {
		t.Fatal("New must default to a non-empty port list")
	}
	if s.concurrency != defaultConcurrency {
		t.Fatalf("concurrency = %d, want default %d", s.concurrency, defaultConcurrency)
	}
	if s.timeout != defaultTimeout {
		t.Fatalf("timeout = %v, want default %v", s.timeout, defaultTimeout)
	}
}

func TestNewDedupesAndSortsPorts(t *testing.T) {
	s := New(Options{Ports: []int{80, 22, 80, 443, 22}})
	got := s.Ports()
	want := []int{22, 80, 443}
	if len(got) != len(want) {
		t.Fatalf("Ports() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Ports() = %v, want %v", got, want)
		}
	}
}

func TestScanFindsOpenAndClosedPorts(t *testing.T) {
	dial := fakeDial(map[string]bool{addr("192.0.2.10", 22): true})
	s := New(Options{Dial: dial, Ports: []int{22, 80}, Concurrency: 4, Timeout: time.Second})

	results := s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.10"}})
	if len(results) != 1 {
		t.Fatalf("Scan() returned %d results, want 1", len(results))
	}
	ds := results[0]
	if ds.DeviceID != "d1" || ds.IP != "192.0.2.10" {
		t.Fatalf("Scan() result = %+v", ds)
	}
	if len(ds.Ports) != 1 || ds.Ports[0].Port != 22 || !ds.Ports[0].Open {
		t.Fatalf("Ports = %+v, want only port 22 open", ds.Ports)
	}
	if ds.Ports[0].NewlyOpened {
		t.Fatalf("a device's first scan must never flag NewlyOpened")
	}
}

func TestScanSkipsTargetsWithNoAddress(t *testing.T) {
	s := New(Options{Dial: fakeDial(nil), Ports: []int{22}})
	results := s.Scan(context.Background(), []Target{{DeviceID: "no-ip", IP: ""}})
	if len(results) != 0 {
		t.Fatalf("Scan() = %v, want no results for a target with no address", results)
	}
}

func TestScanHistoryTracksChangesOverTime(t *testing.T) {
	open := map[string]bool{}
	dial := fakeDial(open)
	s := New(Options{Dial: dial, Ports: []int{22, 23, 3389}, Concurrency: 4, Timeout: time.Second})
	target := Target{DeviceID: "d1", IP: "192.0.2.20"}

	// Scan 1: nothing open yet.
	r := s.Scan(context.Background(), []Target{target})[0]
	if len(r.Ports) != 0 {
		t.Fatalf("scan 1 ports = %+v, want none (nothing open, nothing ever seen open)", r.Ports)
	}

	// Scan 2: port 22 opens. This is the device's second scan (scan 1 found
	// nothing), so the new port must be flagged.
	open[addr("192.0.2.20", 22)] = true
	r = s.Scan(context.Background(), []Target{target})[0]
	p22 := findPort(t, r.Ports, 22)
	if !p22.Open || !p22.NewlyOpened {
		t.Fatalf("port 22 = %+v, want open and newly opened", p22)
	}
	firstSeen := p22.FirstSeen
	if firstSeen.IsZero() {
		t.Fatal("FirstSeen must be set once a port is seen open")
	}

	// Scan 3: port 22 stays open: no longer "newly" opened, FirstSeen unchanged.
	r = s.Scan(context.Background(), []Target{target})[0]
	p22 = findPort(t, r.Ports, 22)
	if !p22.Open || p22.NewlyOpened {
		t.Fatalf("port 22 = %+v, want open and NOT newly opened on the third scan", p22)
	}
	if !p22.FirstSeen.Equal(firstSeen) {
		t.Fatalf("FirstSeen changed from %v to %v on an unchanged port", firstSeen, p22.FirstSeen)
	}

	// Scan 4: port 22 closes again. The record is kept (closed) with its
	// history, not discarded.
	open[addr("192.0.2.20", 22)] = false
	r = s.Scan(context.Background(), []Target{target})[0]
	p22 = findPort(t, r.Ports, 22)
	if p22.Open {
		t.Fatalf("port 22 = %+v, want closed", p22)
	}
	if !p22.FirstSeen.Equal(firstSeen) {
		t.Fatalf("FirstSeen must survive the port closing")
	}

	// Scan 5: port 22 reopens: newly opened again, FirstSeen still the
	// original time it was first ever seen.
	open[addr("192.0.2.20", 22)] = true
	r = s.Scan(context.Background(), []Target{target})[0]
	p22 = findPort(t, r.Ports, 22)
	if !p22.Open || !p22.NewlyOpened {
		t.Fatalf("port 22 = %+v, want open and newly opened again", p22)
	}
	if !p22.FirstSeen.Equal(firstSeen) {
		t.Fatalf("FirstSeen changed on reopening: got %v, want %v", p22.FirstSeen, firstSeen)
	}
}

func findPort(t *testing.T, ports []PortRecord, port int) PortRecord {
	t.Helper()
	for _, p := range ports {
		if p.Port == port {
			return p
		}
	}
	t.Fatalf("no record for port %d in %+v", port, ports)
	return PortRecord{}
}

func TestScanFlagsRiskyPortsEveryTime(t *testing.T) {
	dial := fakeDial(map[string]bool{addr("192.0.2.30", 23): true})
	s := New(Options{Dial: dial, Ports: []int{23}, Concurrency: 2, Timeout: time.Second})
	target := Target{DeviceID: "d1", IP: "192.0.2.30"}

	for i := 0; i < 3; i++ {
		r := s.Scan(context.Background(), []Target{target})[0]
		p := findPort(t, r.Ports, 23)
		if !p.Risky || p.RiskNote == "" {
			t.Fatalf("scan %d: port 23 = %+v, want Risky with a note every time", i, p)
		}
	}
}

func TestScanNonRiskyOpenPortIsNotFlaggedRisky(t *testing.T) {
	dial := fakeDial(map[string]bool{addr("192.0.2.40", 80): true})
	s := New(Options{Dial: dial, Ports: []int{80}, Concurrency: 2, Timeout: time.Second})
	r := s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.40"}})[0]
	p := findPort(t, r.Ports, 80)
	if p.Risky {
		t.Fatalf("port 80 flagged risky: %+v", p)
	}
}

func TestScanConcurrencyIsBounded(t *testing.T) {
	const limit = 3
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
	s := New(Options{Dial: dial, Ports: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, Concurrency: limit, Timeout: time.Second})
	s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.50"}})

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
	s := New(Options{Dial: dial, Ports: []int{22, 80}, Concurrency: 2, Timeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Scan(ctx, []Target{{DeviceID: "d1", IP: "192.0.2.60"}})
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("dial called %d times on an already-canceled context, want 0", calls)
	}
}

func TestScanStopsPromptlyWhenContextIsCanceledMidScan(t *testing.T) {
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		<-ctx.Done() // block until the per-probe timeout or cancellation fires
		return nil, ctx.Err()
	}
	s := New(Options{Dial: dial, Ports: make([]int, 50), Concurrency: 5, Timeout: time.Minute})
	for i := range s.ports {
		s.ports[i] = i + 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.Scan(ctx, []Target{{DeviceID: "d1", IP: "192.0.2.70"}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Scan did not return promptly after its context was canceled")
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
	s := New(Options{Dial: dial, Ports: []int{1}, Concurrency: 4, Timeout: time.Minute})

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.80"}})
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
	s := New(Options{Dial: fakeDial(nil), Ports: []int{22}})
	var got []DeviceScan
	s.OnScan = func(r []DeviceScan) { got = r }
	s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.90"}})
	if len(got) != 1 || got[0].DeviceID != "d1" {
		t.Fatalf("OnScan received %+v, want the scan's own result", got)
	}
}

func TestResultsAndResult(t *testing.T) {
	dial := fakeDial(map[string]bool{addr("192.0.2.100", 22): true})
	s := New(Options{Dial: dial, Ports: []int{22}, Concurrency: 2, Timeout: time.Second})
	s.Scan(context.Background(), []Target{{DeviceID: "b", IP: "192.0.2.100"}, {DeviceID: "a", IP: "192.0.2.101"}})

	all := s.Results()
	if len(all) != 2 || all[0].DeviceID != "a" || all[1].DeviceID != "b" {
		t.Fatalf("Results() = %+v, want sorted by device ID", all)
	}
	one, ok := s.Result("b")
	if !ok || len(one.Ports) != 1 || !one.Ports[0].Open {
		t.Fatalf("Result(\"b\") = %+v, %v", one, ok)
	}
	if _, ok := s.Result("missing"); ok {
		t.Fatal("Result() reported a device that was never scanned")
	}

	// Mutating what the caller got back must not affect the scanner's state.
	one.Ports[0].Open = false
	again, _ := s.Result("b")
	if !again.Ports[0].Open {
		t.Fatal("Result() leaked internal state: a caller's edit changed the scanner's own record")
	}
}

func TestRunScansOnScheduleAndOnDemand(t *testing.T) {
	calls := make(chan struct{}, 8)
	s := New(Options{Dial: fakeDial(nil), Ports: []int{22}})
	s.OnScan = func([]DeviceScan) { calls <- struct{}{} }
	lister := func() []Target { return []Target{{DeviceID: "d1", IP: "192.0.2.110"}} }

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
	s := New(Options{Dial: fakeDial(nil), Ports: []int{22}})
	var n int32
	s.OnScan = func([]DeviceScan) { atomic.AddInt32(&n, 1) }
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
