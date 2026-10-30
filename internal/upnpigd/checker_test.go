// SPDX-License-Identifier: AGPL-3.0-or-later

package upnpigd

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// fakeFetcher is a MappingsFetcher that never touches a real network: it
// returns a canned result (or error) and counts calls, so tests can tell
// exactly how often Checker actually refreshed.
type fakeFetcher struct {
	calls   int32
	mapping []Mapping
	err     error
}

func (f *fakeFetcher) Mappings(ctx context.Context) ([]Mapping, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.err != nil {
		return nil, f.err
	}
	return f.mapping, nil
}

func TestCheckerExposureWANForwarded(t *testing.T) {
	f := &fakeFetcher{mapping: []Mapping{{Protocol: "TCP", InternalClient: "192.168.1.50", InternalPort: 8080, Enabled: true}}}
	c := NewChecker(f, time.Hour)
	wan, ok := c.Exposure(context.Background(), "192.168.1.50", 8080)
	if !ok || !wan {
		t.Fatalf("Exposure() = %v, %v, want true, true", wan, ok)
	}
}

func TestCheckerExposureLANOnly(t *testing.T) {
	f := &fakeFetcher{mapping: []Mapping{{Protocol: "TCP", InternalClient: "192.168.1.50", InternalPort: 8080, Enabled: true}}}
	c := NewChecker(f, time.Hour)
	wan, ok := c.Exposure(context.Background(), "192.168.1.51", 8080) // different device
	if !ok || wan {
		t.Fatalf("Exposure() = %v, %v, want false, true", wan, ok)
	}
}

func TestCheckerExposureIgnoresDisabledMappings(t *testing.T) {
	f := &fakeFetcher{mapping: []Mapping{{Protocol: "TCP", InternalClient: "192.168.1.50", InternalPort: 8080, Enabled: false}}}
	c := NewChecker(f, time.Hour)
	wan, ok := c.Exposure(context.Background(), "192.168.1.50", 8080)
	if !ok || wan {
		t.Fatalf("Exposure() = %v, %v, want false, true for a disabled mapping", wan, ok)
	}
}

func TestCheckerExposureIgnoresUDPMappings(t *testing.T) {
	f := &fakeFetcher{mapping: []Mapping{{Protocol: "UDP", InternalClient: "192.168.1.50", InternalPort: 8080, Enabled: true}}}
	c := NewChecker(f, time.Hour)
	wan, ok := c.Exposure(context.Background(), "192.168.1.50", 8080)
	if !ok || wan {
		t.Fatalf("Exposure() = %v, %v, want false, true: a UDP mapping must not mark a TCP port forwarded", wan, ok)
	}
}

func TestCheckerExposureUnknownWhenFetchFails(t *testing.T) {
	f := &fakeFetcher{err: errors.New("no IGD answered")}
	c := NewChecker(f, time.Hour)
	_, ok := c.Exposure(context.Background(), "192.168.1.50", 8080)
	if ok {
		t.Fatal("Exposure() must report unknown (ok=false) when the fetch fails")
	}
}

func TestCheckerDoesNotRefreshMoreOftenThanEvery(t *testing.T) {
	f := &fakeFetcher{mapping: []Mapping{}}
	c := NewChecker(f, time.Hour)
	for i := 0; i < 5; i++ {
		c.Exposure(context.Background(), "192.168.1.50", 80)
	}
	if atomic.LoadInt32(&f.calls) != 1 {
		t.Fatalf("fetcher called %d times for 5 lookups within one interval, want 1", f.calls)
	}
}

func TestCheckerRefreshesAgainAfterInterval(t *testing.T) {
	f := &fakeFetcher{mapping: []Mapping{}}
	c := NewChecker(f, 10*time.Millisecond)
	c.Exposure(context.Background(), "192.168.1.50", 80)
	time.Sleep(20 * time.Millisecond)
	c.Exposure(context.Background(), "192.168.1.50", 80)
	if atomic.LoadInt32(&f.calls) != 2 {
		t.Fatalf("fetcher called %d times across two intervals, want 2", f.calls)
	}
}

func TestCheckerDoesNotRetryImmediatelyAfterAFailure(t *testing.T) {
	f := &fakeFetcher{err: errors.New("no IGD answered")}
	c := NewChecker(f, time.Hour)
	c.Exposure(context.Background(), "192.168.1.50", 80)
	c.Exposure(context.Background(), "192.168.1.50", 80)
	if atomic.LoadInt32(&f.calls) != 1 {
		t.Fatalf("fetcher called %d times for 2 lookups right after a failure, want 1 (back off until the interval passes)", f.calls)
	}
}

func TestCheckerDiscardsStaleMappingsAfterAFailedRefresh(t *testing.T) {
	f := &fakeFetcher{mapping: []Mapping{{Protocol: "TCP", InternalClient: "192.168.1.50", InternalPort: 8080, Enabled: true}}}
	c := NewChecker(f, 10*time.Millisecond)
	wan, ok := c.Exposure(context.Background(), "192.168.1.50", 8080)
	if !ok || !wan {
		t.Fatalf("first lookup = %v, %v, want true, true", wan, ok)
	}
	time.Sleep(20 * time.Millisecond)
	f.err = errors.New("router stopped answering")
	_, ok = c.Exposure(context.Background(), "192.168.1.50", 8080)
	if ok {
		t.Fatal("Exposure() must not serve a stale cached mapping once a refresh fails: that would be a guess")
	}
}

func TestNewCheckerDefaultsIntervalWhenNonPositive(t *testing.T) {
	c := NewChecker(&fakeFetcher{}, 0)
	if c.every != DefaultRefreshInterval {
		t.Errorf("every = %v, want DefaultRefreshInterval", c.every)
	}
	c2 := NewChecker(&fakeFetcher{}, -time.Second)
	if c2.every != DefaultRefreshInterval {
		t.Errorf("every = %v, want DefaultRefreshInterval for a negative input", c2.every)
	}
}
