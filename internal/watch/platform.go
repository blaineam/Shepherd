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
	// IPv4Nets are the IPv4 prefixes configured on the interface, which is
	// what says whether a device could be on this L2 segment at all. A
	// device with an address outside every one of them cannot be reached
	// by an ARP reply here, so steering it is meaningless -- and this
	// host's own Docker containers arrive in the registry looking exactly
	// like that.
	IPv4Nets []netip.Prefix
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
	// Driver names the kernel driver bound to iface ("atlantic", "igc",
	// "e1000e"), which is what decides whether a native XDP attach is
	// safe: see driversThatFlapOnNativeAttach. An empty name with no
	// error means the interface has no driver to report (a veth or a
	// virtual device), which is not a failure.
	Driver(iface string) (string, error)
	// CarrierChanges is the kernel's count of link up/down transitions on
	// iface. Sampling it either side of a native XDP attach is how
	// Shepherd learns that this driver drops the link when its rings are
	// rebuilt, without having to know the driver in advance.
	CarrierChanges(iface string) (uint64, error)
	// IPForwarding reports whether this host forwards IPv4. A host that
	// both forwards and has a second interface on the relay's own subnet
	// is routing the segment Shepherd is doing Layer 2 steering on, and
	// the two roles conflict: see the forwarding guard in engine.go.
	IPForwarding() (bool, error)
	// InterfaceCounters reads the kernel's own byte and packet counters
	// for iface. The loop brake compares the relay's reported throughput
	// against these: a relay carrying almost everything the interface
	// receives, while the interface transmits the same amount it receives,
	// is relaying its own output back to itself.
	InterfaceCounters(iface string) (Counters, error)
	// LocalAddrs is every MAC and every IP address on this host, across
	// all of its interfaces, for the Own set the policy refuses to steer.
	// It must cover interfaces the relay is not attached to: those are
	// the dangerous ones, because on a host whose interfaces share a
	// subnet they look exactly like LAN devices and steering one relays
	// Shepherd's traffic to itself at line rate (see watch.Own).
	LocalAddrs() (macs []arp.MAC, ips []netip.Addr, err error)
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

// Counters is one reading of an interface's kernel counters.
type Counters struct {
	RxBytes, RxPackets, TxBytes, TxPackets uint64
}
