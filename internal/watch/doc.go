// SPDX-License-Identifier: AGPL-3.0-or-later

// Package watch is Shepherd's Watch mode: the always-on engine that decides
// which devices internal/intercept steers, keeps one Controller and one
// relay data plane alive for the life of the process, and reports what it
// is doing to the portal. docs/WATCH.md is the operator's view of it;
// docs/INTERCEPT.md documents the steering engine underneath.
//
// The split of responsibilities is deliberate. internal/intercept is the
// safety-governed authority: it alone sends frames, verifies health, fails
// open and panic-stops, and it refuses to steer the gateway, Shepherd's own
// MAC or anything its Excluder rejects. This package never bypasses any of
// that. What it adds is policy and lifecycle:
//
//   - Policy (policy.go): which registry devices are eligible. Excluded
//     devices, the gateway, Shepherd's own interfaces, network
//     infrastructure and Thread/Matter advertisers are never steered; a
//     per-device switch in the registry (devices.Device.Watch) opts one
//     out, or in. Wandering and quarantined devices are steered like any
//     other: Watch mode is visibility, it blocks nothing.
//   - Lifecycle (engine.go): discover the interface, Shepherd's and the
//     gateway's addresses, build the Controller, attach the relay once
//     (XDP in the NIC driver, else XDP generic, else the userspace
//     ParallelRelay with GRO turned off for its duration) and from then
//     on only toggle the steered set, re-steering a device whose address
//     changed and backing off one the health loop keeps failing open.
//   - Safety surface: a kill switch (Kill/Rearm) that calls PanicStop and
//     stays off across restarts until re-armed, the Controller's own
//     unsteer history with device names attached, and a Snapshot for the
//     portal with the relay in effect, live relayed rates and every
//     device's state and the reason for it.
//
// Everything that touches the kernel lives behind the Platform interface so
// the engine is tested end to end with intercept.FakeSender and
// intercept.FakeClock and a fake platform, with no interface, socket or
// capability anywhere. Linux is the only platform with a real
// implementation; elsewhere the engine reports itself unavailable and
// Shepherd runs without it. IPv4 only, by the hard rule in docs/IPV6.md.
package watch
