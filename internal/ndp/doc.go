// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ndp builds the IPv6 Neighbor Discovery frames Watch mode's IPv6
// steering needs, and parses the one kind it has to react to. It is the
// IPv6 counterpart of internal/arp's frame codec, and deliberately as
// small and as safety-constrained: see docs/IPV6-WATCH.md for the design
// and docs/IPV6.md for the hard rules it is written to respect.
//
// What it can build: a unicast Neighbor Advertisement (ICMPv6 type 136)
// addressed to one device, claiming some target address lives at some
// link-layer address. That is the exact NDP mirror of internal/arp's
// unicast NewReply, and it is all one-sided IPv6 steering ever transmits.
//
// What it deliberately cannot build: a Router Advertisement (there is no
// function for one, type 134 is never emitted), and anything addressed to
// a multicast group (Marshal rejects a multicast Ethernet or IPv6
// destination). Those two refusals are the machine-checked form of
// docs/IPV6.md's rule 1 ("never run a Router Advertisement") and of the
// unicast-only safety story in docs/IPV6-WATCH.md: a Thread border router
// or Matter device that is not the one explicitly steered can never
// receive a frame this package produces.
//
// What it parses: a Neighbor Solicitation (ICMPv6 type 135), so the
// steering layer can answer a steered device's unicast "are you still
// there?" probe for the gateway's address with a solicited advertisement,
// keeping the device's neighbor cache pointed at Shepherd without relying
// on the periodic unsolicited refresh winning a race. It parses nothing
// else; every other frame is reported as not-an-NS and ignored.
package ndp
