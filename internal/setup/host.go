// SPDX-License-Identifier: AGPL-3.0-or-later

package setup

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
)

// Addr is one address this host has, with the interface it belongs to so the
// owner can tell the wired one from the Wi-Fi one when both are offered on
// the setup page.
type Addr struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"` // a bare address, no port: "192.0.2.10", "2001:db8::10"
	V6        bool   `json:"v6"`
}

// HostAddrs lists the addresses this host could serve DNS or the portal on:
// every address of every interface that is up, minus the ones nothing can
// usefully be pointed at.
//
// What is left out, and why:
//
//   - Loopback. Shepherd adds 127.0.0.1 and [::1] by itself
//     (config.DNS.ListenAddrs), and the portal offers loopback as its own
//     first choice, so listing it among the LAN addresses would only invite
//     picking it twice.
//   - Link-local (169.254.0.0/16, fe80::/10). A device can only reach these // leakcheck:allow the ranges themselves, not an address
//     with a zone it has to know, so no router hands one out as a resolver.
//
// Unique-local IPv6 (fd00::/8) is kept: on a LAN with no global IPv6 that is // leakcheck:allow the range itself, not an address
// the address devices actually have, and a device asking DNS over IPv6 is
// asking that address.
func HostAddrs() ([]Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]iface, 0, len(ifaces))
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			// One unreadable interface must not cost the owner the
			// others: an address they cannot see here is an address
			// they will not point a device at.
			continue
		}
		out = append(out, iface{Name: i.Name, Flags: i.Flags, Addrs: addrs})
	}
	return collect(out), nil
}

// iface is one interface as collect sees it, which is all HostAddrs reads
// from the operating system. Keeping the decisions in collect is what lets
// them be tested against shapes this host does not happen to have.
type iface struct {
	Name  string
	Flags net.Flags
	Addrs []net.Addr
}

func collect(ifaces []iface) []Addr {
	var out []Addr
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		for _, a := range i.Addrs {
			prefix, ok := a.(*net.IPNet)
			if !ok {
				// A point-to-point interface can report a
				// *net.IPAddr instead; nothing is pointed at
				// one as a resolver, so skipping it is right.
				continue
			}
			ip, ok := netip.AddrFromSlice(prefix.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, Addr{Interface: i.Name, IP: ip.String(), V6: ip.Is6()})
		}
	}
	// IPv4 first, then by interface name: the address a router is most
	// likely configured with should be the first one offered, and a stable
	// order keeps the numbers in the prompt from moving between runs.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].V6 != out[j].V6 {
			return !out[i].V6
		}
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// PortFree reports whether host:port can be bound right now over both UDP
// and TCP, which is what a DNS listener needs. It is best-effort by nature —
// the answer can change the moment it is given — so the wizard treats a
// false as something to explain, never as a refusal.
func PortFree(host string, port int) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = l.Close()
	p, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	_ = p.Close()
	return true
}
