package dnsengine

import (
	"context"
	"errors"
	"net"
	"testing"
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
