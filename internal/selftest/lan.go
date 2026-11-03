// SPDX-License-Identifier: AGPL-3.0-or-later

package selftest

import (
	"net"
	"sort"
	"strings"
)

// virtualPrefixes are interface names that are not a LAN devices use:
// container bridges, VM and VPN tunnels.
var virtualPrefixes = []string{"docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "tun", "tap", "wg", "tailscale", "utun", "zt", "vmnet", "vboxnet"}

// hostAddrs lists the private IPv4 addresses of this host's up, non-virtual
// interfaces: the addresses a device on the LAN could be told to use as its
// resolver.
func hostAddrs() ([]HostAddr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []HostAddr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || virtualName(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				out = append(out, HostAddr{Interface: ifc.Name, IP: ipn.IP})
			}
		}
	}
	return out, nil
}

func virtualName(n string) bool {
	n = strings.ToLower(n)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// lanAddrs filters the host's addresses down to private, non-loopback,
// non-link-local IPv4 ones, sorted and de-duplicated.
func (t *Tester) lanAddrs() ([]HostAddr, error) {
	all, err := t.o.Interfaces()
	seen := map[string]bool{}
	var out []HostAddr
	for _, h := range all {
		v4 := h.IP.To4()
		if v4 == nil || !v4.IsPrivate() || seen[v4.String()] {
			continue
		}
		seen[v4.String()] = true
		out = append(out, HostAddr{h.Interface, v4})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.String() < out[j].IP.String() })
	return out, err
}

// checkLAN decides, for every LAN address of this host, whether Shepherd
// serves it (a listen entry names it, or a wildcard listener covers it) or
// the owner said it should not.
func (t *Tester) checkLAN(listen []string, lan []HostAddr) []LANResult {
	served := map[string]bool{}
	wildcard := false
	for _, a := range listen {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			continue
		}
		switch host {
		case "", "0.0.0.0", "::":
			wildcard = true
		default:
			if ip := net.ParseIP(host); ip != nil {
				served[ip.String()] = true
			}
		}
	}
	notServed := map[string]bool{}
	for _, s := range t.o.NotServed {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			notServed[ip.String()] = true
		}
	}
	out := []LANResult{}
	for _, h := range lan {
		ip := h.IP.String()
		r := LANResult{IP: ip, Interface: h.Interface}
		switch {
		case served[ip] || wildcard:
			r.State = "served"
		case notServed[ip]:
			r.State, r.Detail = "not-served", "listed in selftest.not_served"
		default:
			r.State, r.Detail = "unserved", "no dns.listen entry covers this address"
		}
		out = append(out, r)
	}
	return out
}
