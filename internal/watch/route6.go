// SPDX-License-Identifier: AGPL-3.0-or-later

package watch

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// ProcNetIPv6Route is the kernel's IPv6 routing table, which is where the
// gateway's link-local address comes from. There is no /proc/net/route
// equivalent for IPv6 with the same columns, so this file parses the one
// the kernel does publish.
const ProcNetIPv6Route = "/proc/net/ipv6_route"

// ErrNoDefaultRoute6 means the table has no usable IPv6 default route, so
// the network has no IPv6 router and there is nothing to steer.
var ErrNoDefaultRoute6 = errors.New("watch: no IPv6 default route")

// Route6 is the IPv6 default route: which interface it leaves through and
// the next hop it points at, which on any ordinary LAN is the router's
// link-local address. That address, not its ULA or global one, is what a
// device's IPv6 default route actually resolves, so it is the address
// IPv6 steering has to claim (docs/IPV6-WATCH.md).
type Route6 struct {
	Iface   string
	NextHop netip.Addr
	Metric  int
}

const (
	rtf6Up      = 0x1
	rtf6Gateway = 0x2
)

// ParseDefaultRoute6 picks the IPv6 default route (destination ::/0, up,
// via a gateway) with the lowest metric from the text of
// /proc/net/ipv6_route. Its columns are: destination, destination prefix
// length, source, source prefix length, next hop, metric, refcount, use,
// flags, interface — with every address as 32 hex characters and the
// numbers in hex. Malformed lines are skipped.
func ParseDefaultRoute6(data []byte) (Route6, error) {
	var best Route6
	found := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		dest, destOK := parseHexAddr16(f[0])
		plen, e1 := strconv.ParseUint(f[1], 16, 32)
		nextHop, hopOK := parseHexAddr16(f[4])
		metric, e2 := strconv.ParseUint(f[5], 16, 64)
		flags, e3 := strconv.ParseUint(f[8], 16, 64)
		if !destOK || !hopOK || e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		// A default route: ::/0, up, and through a gateway with a real
		// next hop. Anything else is an on-link prefix or a host route.
		if !dest.IsUnspecified() || plen != 0 || flags&rtf6Up == 0 || flags&rtf6Gateway == 0 || nextHop.IsUnspecified() {
			continue
		}
		r := Route6{Iface: f[9], NextHop: nextHop, Metric: int(metric)}
		if !found || r.Metric < best.Metric {
			best, found = r, true
		}
	}
	if !found {
		return Route6{}, ErrNoDefaultRoute6
	}
	return best, nil
}

// parseHexAddr16 reads one of the table's 32-hex-character addresses.
func parseHexAddr16(s string) (netip.Addr, bool) {
	if len(s) != 32 {
		return netip.Addr{}, false
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom16([16]byte(raw)), true
}

// isGlobalV6 reports whether a is a global unicast IPv6 address: the
// 2000::/3 range the internet actually routes. A unique local address
// and a link-local one are both global-unicast as far as
// netip is concerned but neither is reachable off the LAN, which is
// exactly the distinction IPv6 steering turns on — see the "no global
// route" case in docs/WATCH.md.
func isGlobalV6(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is6() || a.Is4In6() {
		return false
	}
	return a.As16()[0]&0xe0 == 0x20
}

// usableDeviceV6 reports whether a is an address a Neighbor Advertisement
// can be sent to: a concrete unicast IPv6 address, which a device's
// link-local always is.
func usableDeviceV6(a netip.Addr) bool {
	a = a.Unmap()
	return a.Is6() && !a.Is4In6() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback()
}
