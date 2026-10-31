// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package watch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"shepherd/internal/arp"
	"shepherd/internal/devices"
	"shepherd/internal/intercept"
)

// RealPlatform is the Linux host: the routing and neighbour tables under
// /proc, the interface's own addresses, internal/intercept's raw sockets
// and relays, and the ethtool ioctl for GRO. Nothing here is reachable
// from an unprivileged test, which is why the engine is tested against a
// fake Platform instead; this file stays thin on purpose.
type RealPlatform struct {
	// ReadFile is a seam for the /proc reads; nil means os.ReadFile.
	ReadFile func(string) ([]byte, error)
}

func (p RealPlatform) readFile() func(string) ([]byte, error) {
	if p.ReadFile != nil {
		return p.ReadFile
	}
	return os.ReadFile
}

// procNetARP is the kernel's IPv4 neighbour table.
const procNetARP = "/proc/net/arp"

func (p RealPlatform) DefaultRoute() (string, netip.Addr, error) {
	r, err := arp.DefaultRoute(p.readFile())
	if err != nil {
		return "", netip.Addr{}, err
	}
	return r.Iface, r.Gateway, nil
}

func (p RealPlatform) DefaultRoute6() (Route6, error) {
	data, err := p.readFile()(ProcNetIPv6Route)
	if err != nil {
		return Route6{}, fmt.Errorf("watch: read IPv6 routing table: %w", err)
	}
	return ParseDefaultRoute6(data)
}

func (RealPlatform) Link(name string) (Link, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return Link{}, fmt.Errorf("watch: interface %q: %w", name, err)
	}
	l := Link{Name: ifc.Name, Index: ifc.Index}
	copy(l.MAC[:], ifc.HardwareAddr)
	if l.MAC.IsZero() {
		return Link{}, fmt.Errorf("watch: interface %q has no usable MAC address", name)
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return Link{}, fmt.Errorf("watch: addresses of %q: %w", name, err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		if ip = ip.Unmap(); ip.Is4() {
			l.IPv4s = append(l.IPv4s, ip)
		} else if ip.Is6() {
			l.IPv6s = append(l.IPv6s, ip)
		}
	}
	return l, nil
}

func (p RealPlatform) Neighbors(iface string) ([]Neighbor, error) {
	data, err := p.readFile()(procNetARP)
	if err != nil {
		return nil, fmt.Errorf("watch: read neighbour table: %w", err)
	}
	var out []Neighbor
	for _, n := range devices.ParseProcNetARP(data) {
		if n.Iface != iface {
			continue
		}
		ip, err := netip.ParseAddr(n.IP)
		if err != nil || !ip.Is4() {
			continue
		}
		mac, err := arp.ParseMAC(n.MAC)
		if err != nil || mac.IsZero() {
			continue
		}
		out = append(out, Neighbor{IP: ip, MAC: mac})
	}
	return out, nil
}

// GatewayMAC reads the gateway's MAC from the neighbour table. When the
// entry is missing or incomplete (a freshly booted host has not spoken to
// its gateway yet), it sends one empty UDP datagram to the gateway's
// discard port, which makes the kernel resolve the address the ordinary
// way, then reads again. The kernel's own table is the only source: the
// ARP monitor's events are a prompt to re-read it, never a value to take.
func (p RealPlatform) GatewayMAC(ctx context.Context, iface string, gateway netip.Addr) (arp.MAC, error) {
	lookup := func() (arp.MAC, bool) {
		ns, err := p.Neighbors(iface)
		if err != nil {
			return arp.MAC{}, false
		}
		for _, n := range ns {
			if n.IP == gateway {
				return n.MAC, true
			}
		}
		return arp.MAC{}, false
	}
	if mac, ok := lookup(); ok {
		return mac, nil
	}
	for attempt := 0; attempt < 10; attempt++ {
		poke(gateway)
		select {
		case <-ctx.Done():
			return arp.MAC{}, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
		if mac, ok := lookup(); ok {
			return mac, nil
		}
	}
	return arp.MAC{}, fmt.Errorf("watch: the gateway %s is not in the neighbour table on %s", gateway, iface)
}

// poke makes the kernel resolve gateway's MAC by addressing one empty UDP
// datagram to its discard port. Errors are irrelevant: the ARP request the
// kernel sends on the way out is the whole point.
func poke(gateway netip.Addr) {
	c, err := net.DialTimeout("udp", netip.AddrPortFrom(gateway, 9).String(), time.Second)
	if err != nil {
		return
	}
	_, _ = c.Write([]byte{})
	_ = c.Close()
}

func (RealPlatform) OpenSender(iface string) (intercept.Sender, func() error, error) {
	s, err := intercept.Open(iface)
	if err != nil {
		return nil, nil, err
	}
	closer := func() error { return nil }
	if c, ok := s.(interface{ Close() error }); ok {
		closer = c.Close
	}
	return s, closer, nil
}

func (RealPlatform) AttachXDP(ctx context.Context, c *intercept.Controller, iface string, opts intercept.XDPOptions) error {
	return c.AttachXDP(ctx, iface, opts)
}

func (RealPlatform) ParallelRelay(ctx context.Context, c *intercept.Controller, iface string, workers int) error {
	return c.ParallelRelay(ctx, iface, workers)
}

func (RealPlatform) GRO(iface string) (bool, error) {
	on, err := ethtoolGRO(iface, nil)
	if errors.Is(err, errGROFixed) {
		return on, err
	}
	return on, err
}

func (RealPlatform) SetGRO(iface string, on bool) error {
	_, err := ethtoolGRO(iface, &on)
	return err
}

var _ Platform = RealPlatform{}

// LocalAddrs enumerates every interface on the host, not just the one the
// relay runs on. Loopback is included for completeness; what matters are
// the other real interfaces, which on a host whose interfaces share a
// subnet are indistinguishable from LAN devices to everything upstream of
// the policy. An interface that cannot be read is skipped rather than
// failing the whole set: a partial answer still excludes more than none,
// and the caller treats an error as "refuse to steer anything new".
func (RealPlatform) LocalAddrs() ([]arp.MAC, []netip.Addr, error) {
	ifcs, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("watch: listing interfaces: %w", err)
	}
	var macs []arp.MAC
	var ips []netip.Addr
	for _, ifc := range ifcs {
		var mac arp.MAC
		copy(mac[:], ifc.HardwareAddr)
		if !mac.IsZero() {
			macs = append(macs, mac)
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				ips = append(ips, ip.Unmap())
			}
		}
	}
	return macs, ips, nil
}

// Driver reads the driver bound to iface from sysfs. The symlink at
// device/driver points at the module's directory, so its base name is the
// driver. An interface with no device/driver at all -- a veth, a bridge --
// reports an empty name and no error: there is no driver whose behaviour
// needs allowing for.
func (RealPlatform) Driver(iface string) (string, error) {
	if err := validIfaceName(iface); err != nil {
		return "", err
	}
	dst, err := os.Readlink(filepath.Join("/sys/class/net", iface, "device", "driver"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("watch: driver of %s: %w", iface, err)
	}
	return filepath.Base(dst), nil
}

// CarrierChanges reads the kernel's link-transition counter for iface.
func (RealPlatform) CarrierChanges(iface string) (uint64, error) {
	if err := validIfaceName(iface); err != nil {
		return 0, err
	}
	b, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "carrier_changes"))
	if err != nil {
		return 0, fmt.Errorf("watch: carrier changes of %s: %w", iface, err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("watch: carrier changes of %s: %w", iface, err)
	}
	return n, nil
}

// validIfaceName refuses anything that could escape /sys/class/net, since
// the interface name reaches here from the configuration.
func validIfaceName(iface string) error {
	if iface == "" || iface == "." || iface == ".." || strings.ContainsAny(iface, "/\\\x00") {
		return fmt.Errorf("watch: invalid interface name %q", iface)
	}
	return nil
}
