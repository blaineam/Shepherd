// SPDX-License-Identifier: AGPL-3.0-or-later

// Package routerusage reads per-device bandwidth from the router the owner
// already has, instead of putting Shepherd in the path of their traffic.
//
// Watch mode (internal/watch) measures bandwidth by steering each device's
// traffic through Shepherd. That is exact, but it is also an intervention:
// it needs Linux, raw sockets and a router whose switching tolerates
// one-sided ARP steering, and on some routers it cannot be made to work at
// all. This package is the passive alternative. Nothing here touches a
// packet; a Source asks the router what it already knows and the Collector
// turns that into the same per-device byte counts internal/traffic stores,
// so the Bandwidth screen, the per-device chart and the history work the
// same whichever measurement is in effect.
//
// Routers differ in what they will tell you, so a Source declares which of
// two shapes it reports and the Collector normalizes both:
//
//   - KindCounters: bytes since the router last booted, which is what
//     UniFi, OpenWrt and the business-grade controllers keep. Differencing
//     consecutive reads is exact apart from what is lost to a reset.
//   - KindRates: the instantaneous rate right now, which is all eero's
//     cloud API exposes. Integrating samples over time is an estimate and
//     is documented as one everywhere it reaches the owner: traffic between
//     two polls is interpolated, and a burst shorter than the interval is
//     under-counted.
//
// A Source is only ever asked for data. Nothing in this package changes a
// setting on anyone's router.
package routerusage
