// SPDX-License-Identifier: AGPL-3.0-or-later

package watch

import (
	"context"
	"errors"
	"net/netip"

	"shepherd/internal/arp"
	"shepherd/internal/intercept"
)

// ErrUnsupported is what the real Platform reports on any operating system
// but Linux: raw frame injection, AF_PACKET capture and XDP are all Linux
// facilities.
var ErrUnsupported = errors.New("watch: Watch mode is only supported on Linux")

// Link is what the engine needs to know about the interface it steers on.
type Link struct {
	Name  string
	Index int
	MAC   arp.MAC
	// IPv4s are Shepherd's own IPv4 addresses on the interface: a steered
	// device's traffic to one of these (a DNS query, a portal connection)
	// is for Shepherd itself and must be passed, never relayed. They go to
	// intercept.ControllerConfig.ShepherdIPs.
	IPv4s []netip.Addr
	// IPv6s are Shepherd's own IPv6 addresses on the interface, the
	// counterpart of IPv4s for IPv6 steering
	// (intercept.ControllerConfig.ShepherdIPs6).
	IPv6s []netip.Addr
}

// Neighbor is one (IPv4, MAC) entry of the host's neighbour table on the
// steered interface.
type Neighbor struct {
	IP  netip.Addr
	MAC arp.MAC
}

// Platform is everything the engine asks of the operating system, behind
// one interface so the engine's own logic runs in tests with no interface,
// socket or capability. platform_linux.go is the real one.
type Platform interface {
	// DefaultRoute names the interface the default route leaves through and
	// the gateway it points at.
	DefaultRoute() (iface string, gateway netip.Addr, err error)
	// DefaultRoute6 is the IPv6 default route: the interface and the next
	// hop, which on any ordinary LAN is the router's link-local address.
	// ErrNoDefaultRoute6 means the network has no IPv6 router, which is
	// not a failure — IPv6 steering simply has nothing to do.
	DefaultRoute6() (Route6, error)
	// Link describes the named interface.
	Link(name string) (Link, error)
	// GatewayMAC finds the gateway's MAC in the host's neighbour table,
	// prompting the kernel to resolve it when the entry is missing, and
	// gives up when ctx ends.
	GatewayMAC(ctx context.Context, iface string, gateway netip.Addr) (arp.MAC, error)
	// Neighbors reads the host's IPv4 neighbour table for iface.
	Neighbors(iface string) ([]Neighbor, error)
	// OpenSender opens the raw send-only socket the Spoofer's ARP replies
	// go out through (needs CAP_NET_RAW). close releases it.
	OpenSender(iface string) (sender intercept.Sender, close func() error, err error)
	// AttachXDP runs the in-kernel relay until ctx ends (Controller.AttachXDP).
	AttachXDP(ctx context.Context, c *intercept.Controller, iface string, opts intercept.XDPOptions) error
	// ParallelRelay runs the userspace relay until ctx ends (Controller.ParallelRelay).
	ParallelRelay(ctx context.Context, c *intercept.Controller, iface string, workers int) error
	// GRO reports whether generic receive offload is on for iface; SetGRO
	// changes it (needs CAP_NET_ADMIN). The userspace relay cannot run
	// with it on: see the GRO discussion in docs/INTERCEPT.md.
	GRO(iface string) (on bool, err error)
	SetGRO(iface string, on bool) error
}
