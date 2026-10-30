// SPDX-License-Identifier: AGPL-3.0-or-later

// Package classify guesses what kind of device each machine on the network is
// (camera, TV, phone, printer...) and says why, from three families of
// evidence: the manufacturer and whether the MAC address is randomized, the
// DNS names the device looks up, and the networks (ASNs) those lookups
// resolve to. mDNS service types and device names feed in too.
//
// The package is self-contained. The DNS engine calls Observe for every
// answered query; the registry supplies manufacturer, services and names
// through ObserveDevice and ObserveNames (Apply does that for you); Classify
// scores one device and Apply writes the guesses into the registry, never
// over a type the user set. The rules are embedded, versioned JSON files in
// rules/, each with its evidence, so they can be reviewed and corrected like
// code. docs/CLASSIFY.md is the reference.
//
// Privacy: per device the classifier keeps class scores, a few counters and a
// small capped set of registrable domains. It never keeps a query history,
// timestamps of individual lookups, full host names or answer addresses, and
// everything is in memory only and decays away.
package classify
