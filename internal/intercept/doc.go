// SPDX-License-Identifier: AGPL-3.0-or-later

// Package intercept is the ARP interception engine behind Shepherd's Watch
// mode: one-sided ARP spoofing of a chosen device, so its outbound traffic
// flows through Shepherd on its way to the real gateway.
//
// The design (see docs/DESIGN.md, "Watch interception methods") is: tell
// one device, by periodic ARP replies, that Shepherd's own MAC owns the
// gateway's IP. The device then sends its outbound frames to Shepherd,
// which rewrites the destination MAC to the gateway's real MAC and
// retransmits them unchanged. The gateway's own ARP table is never
// touched, so inbound (gateway-to-device) traffic goes straight to the
// device, bypassing Shepherd entirely. That is a known, accepted scope
// boundary — outbound-direction visibility and control only — not a bug.
// See docs/INTERCEPT.md for the full picture, including the safety model.
//
// IPv4 only, always. IPv6 and NDP are never touched anywhere in this
// package: docs/IPV6.md's hard rules apply in full, and the Relay and the
// Spoofer's frame builder are both fuzz-tested to prove it.
//
// This package builds on internal/arp, reusing its Frame/MAC codec
// (ParseFrame, NewReply, Marshal, ...) rather than duplicating it.
// internal/arp stays strictly read-only; every byte this package puts on
// the wire flows through the Sender interface defined here, which
// internal/arp deliberately has no equivalent of.
//
// This package is a library only. Nothing in it is wired into
// cmd/shepherd, internal/portal, or any startup path, and nothing here
// calls Open or constructs a real Sender outside this package's own
// Linux-only, capability-gated file. A Controller never steers a device
// unless something outside this package calls Steer — and the Controller
// itself refuses to steer the gateway or an excluded device even then.
// Wiring a trial UI or API, and running this against a real network,
// happens later, only with the maintainer's explicit go-ahead.
package intercept
