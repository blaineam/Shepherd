// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import (
	"errors"
	"net/netip"
	"testing"
)

const routeTable = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth1	00000000	0100000A	0003	0	0	600	00000000	0	0	0
eth0	00000000	010200C0	0003	0	0	100	00000000	0	0	0
eth0	000200C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
bad	zz	zz
eth2	00000000	00000000	0001	0	0	50	00000000	0	0	0
eth3	00000000	030200C0	0001	0	0	10	00000000	0	0	0
`

func TestParseDefaultRoute(t *testing.T) {
	r, err := ParseDefaultRoute([]byte(routeTable))
	if err != nil {
		t.Fatal(err)
	}
	if r.Iface != "eth0" || r.Gateway != netip.MustParseAddr("192.0.2.1") || r.Metric != 100 {
		t.Fatalf("got %+v", r)
	}
}

func TestParseDefaultRouteNone(t *testing.T) {
	for _, in := range []string{"", "Iface\tDestination\n", "eth0 00000000 zz 0003 0 0 1 00000000\n"} {
		if _, err := ParseDefaultRoute([]byte(in)); !errors.Is(err, ErrNoDefaultRoute) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestDefaultRouteAndGatewayFunc(t *testing.T) {
	read := func(p string) ([]byte, error) {
		if p != ProcNetRoute {
			t.Errorf("read %s", p)
		}
		return []byte(routeTable), nil
	}
	if r, err := DefaultRoute(read); err != nil || r.Iface != "eth0" {
		t.Fatalf("%+v %v", r, err)
	}
	if gw, err := DefaultGatewayFunc(read)(); err != nil || gw != ip(1) {
		t.Fatalf("%v %v", gw, err)
	}
	fail := func(string) ([]byte, error) { return nil, errors.New("denied") }
	if _, err := DefaultRoute(fail); err == nil {
		t.Fatal("read error swallowed")
	}
	if _, err := DefaultGatewayFunc(fail)(); err == nil {
		t.Fatal("gateway func swallowed error")
	}
}
