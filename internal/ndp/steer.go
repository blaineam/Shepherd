// SPDX-License-Identifier: AGPL-3.0-or-later

package ndp

import (
	"net/netip"

	"shepherd/internal/arp"
)

// steerFlags is what every steering advertisement sets: Router (the
// advertised address is the real router — never clear this, see Flags),
// Override (overwrite the device's existing cache entry). Solicited is set
// only by SolicitedReply.
var steerFlags = Flags{Router: true, Override: true}

// Claim builds the periodic unsolicited Neighbor Advertisement that tells
// one steered device the gateway's link-local address lives at Shepherd's
// MAC. It is the NDP mirror of arp.NewReply(shepherdMAC, gatewayIP,
// deviceMAC, deviceIP): same one device, same unicast delivery, same
// "Shepherd is now the gateway" claim.
func Claim(shepherdMAC, deviceMAC arp.MAC, gatewayLinkLocal, deviceIP netip.Addr) ([]byte, error) {
	return Advertisement{
		EthSrc: shepherdMAC, EthDst: deviceMAC,
		SrcIP: gatewayLinkLocal, DstIP: deviceIP,
		Target: gatewayLinkLocal, TargetLLA: shepherdMAC,
		Flags: steerFlags,
	}.Marshal()
}

// Corrective builds the Neighbor Advertisement that restores the truth
// when a device is unsteered (or on panic-stop): the gateway's link-local
// address lives at the gateway's real MAC again. Sent best-effort so the
// device recovers at once instead of waiting out its neighbor cache. The
// NDP mirror of arp.NewReply(gatewayMAC, gatewayIP, deviceMAC, deviceIP).
func Corrective(gatewayMAC, deviceMAC arp.MAC, gatewayLinkLocal, deviceIP netip.Addr) ([]byte, error) {
	return Advertisement{
		EthSrc: gatewayMAC, EthDst: deviceMAC,
		SrcIP: gatewayLinkLocal, DstIP: deviceIP,
		Target: gatewayLinkLocal, TargetLLA: gatewayMAC,
		Flags: steerFlags,
	}.Marshal()
}

// SolicitedReply builds the direct answer to a steered device's unicast
// Neighbor Solicitation probe for the gateway's address: same claim as
// Claim, but with the Solicited flag set, so a device revalidating its
// (STALE) cache entry keeps Shepherd's MAC instead of falling back to the
// real gateway. Used by the steering layer's NS responder.
func SolicitedReply(shepherdMAC, deviceMAC arp.MAC, gatewayLinkLocal, deviceIP netip.Addr) ([]byte, error) {
	f := steerFlags
	f.Solicited = true
	return Advertisement{
		EthSrc: shepherdMAC, EthDst: deviceMAC,
		SrcIP: gatewayLinkLocal, DstIP: deviceIP,
		Target: gatewayLinkLocal, TargetLLA: shepherdMAC,
		Flags: f,
	}.Marshal()
}
