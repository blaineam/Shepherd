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
// This package is the engine, not the policy. internal/watch wires it
// into cmd/shepherd and the portal (Watch mode is on by default; see
// docs/WATCH.md), decides which devices to steer, and keeps one Controller
// for the life of the process. What stays true regardless of the caller:
// this package is the only thing here that transmits, and a Controller
// never steers a device unless something calls Steer — and then still
// refuses the gateway, Shepherd's own MAC, and anything its Excluder
// rejects. IPv6 steering additionally needs its own master switch and its
// own stricter excluder (docs/IPV6-WATCH.md).
package intercept
