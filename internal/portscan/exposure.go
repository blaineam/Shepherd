// SPDX-License-Identifier: AGPL-3.0-or-later

package portscan

import "context"

// Exposure is what a scan concluded about whether an open port is also
// reachable from the WAN, not just the LAN: the far more dangerous case
// for the same open port (an exposed Telnet or Docker API on the LAN is
// bad; the same thing reachable from the internet is much worse). It is
// derived, at most, from the router's own UPnP IGD port-mapping table
// (internal/upnpigd) — never guessed. See docs/PORTSCAN.md's "WAN
// exposure" section for exactly what each value means in practice.
type Exposure string

const (
	// ExposureLANOnly means the IGD was queried successfully and this port
	// is not in its forwarding table: as far as Shepherd can tell, nothing
	// forwards it from the WAN through UPnP. This is not a guarantee a
	// port is safe — see ExposureUnknown's doc comment for the ways a port
	// can still be reachable from the WAN without UPnP IGD knowing about it.
	ExposureLANOnly Exposure = "lan_only"
	// ExposureWANForwarded means the router's own NAT table has an
	// enabled mapping forwarding this exact LAN IP:port from the WAN.
	ExposureWANForwarded Exposure = "wan_forwarded"
	// ExposureUnknown means the WAN-exposure check could not be made this
	// scan: no IGD answered SSDP discovery, the IGD has no
	// WANIPConnection/WANPPPConnection service, a SOAP call failed, or no
	// ExposureChecker is configured at all (the field is then left empty
	// rather than set to this value — see PortRecord.Exposure).
	//
	// Unknown is never a signal of safety. A port forwarded by some means
	// other than UPnP IGD — a manual NAT rule made outside UPnP, a DMZ
	// host, a device with its own direct WAN address — is indistinguishable
	// here from a port that genuinely is not exposed at all, because UPnP
	// IGD can only ever report what was forwarded through it. Likewise,
	// some routers (and some consumer mesh systems in particular) simply
	// do not answer UPnP IGD discovery at all, by default or by design; for
	// those, every port will show unknown, always. That is the honest
	// answer, not a bug.
	ExposureUnknown Exposure = "unknown"
)

// ExposureChecker answers whether one TCP ip:port is currently forwarded
// from the WAN. internal/upnpigd.Checker implements it; Scanner depends
// only on this interface, so its own tests need no IGD client at all — the
// same way they need no real net.Dialer.
type ExposureChecker interface {
	// Exposure reports the router's own NAT-table state for ip:port. ok is
	// false whenever that state could not be determined this round
	// (unreachable IGD, failed query, ...): the caller must then record
	// ExposureUnknown, never guess ExposureLANOnly or ExposureWANForwarded.
	Exposure(ctx context.Context, ip string, port int) (wanForwarded bool, ok bool)
}
