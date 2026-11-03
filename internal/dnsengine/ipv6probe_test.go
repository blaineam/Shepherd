package dnsengine

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestIPv6ProbeFiltersOnlyAfterTwoFailedRoundsAndRecoversAtOnce(t *testing.T) {
	up := false
	var changes []bool
	p := &IPv6Probe{
		Targets: []string{"[::1]:1"},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if up {
				c, _ := net.Pipe()
				return c, nil
			}
			return nil, errors.New("no route to host")
		},
		OnChange: func(usable bool) { changes = append(changes, usable) },
	}
	ctx := context.Background()
	p.Check(ctx)
	if p.Filtering() {
		t.Fatal("one failed round must not start filtering")
	}
	p.Check(ctx)
	if !p.Filtering() {
		t.Fatal("two failed rounds in a row should start filtering")
	}
	up = true
	p.Check(ctx)
	if p.Filtering() {
		t.Fatal("one success should stop filtering at once")
	}
	if len(changes) != 2 || changes[0] || !changes[1] {
		t.Errorf("changes = %v, want [false true]", changes)
	}
}

func TestIPv6ProbeOneReachableTargetIsEnough(t *testing.T) {
	p := &IPv6Probe{
		Targets: []string{"[::1]:1", "[::2]:1"},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == "[::2]:1" {
				c, _ := net.Pipe()
				return c, nil
			}
			return nil, errors.New("no route to host")
		},
	}
	p.Check(context.Background())
	p.Check(context.Background())
	if p.Filtering() {
		t.Fatal("a reachable target means IPv6 works")
	}
}

func TestIPv6ProbeRunChecksRepeatedlyUntilCancelled(t *testing.T) {
	rounds := make(chan struct{}, 8)
	p := &IPv6Probe{
		Timeout: time.Second,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp6" {
				t.Errorf("network = %s, want tcp6", network)
			}
			rounds <- struct{}{}
			return nil, errors.New("no route to host")
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx, 5*time.Millisecond); close(done) }()
	// the default targets are tried, three at a time, every round
	for i := 0; i < 6; i++ {
		<-rounds
	}
	cancel()
	<-done
	if !p.Filtering() {
		t.Error("rounds that all fail should leave the probe filtering")
	}
}
