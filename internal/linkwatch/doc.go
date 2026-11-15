// SPDX-License-Identifier: AGPL-3.0-or-later

// Package linkwatch notices when the machine Shepherd runs on loses the
// network address it serves DNS on, and reports how long it was gone.
//
// Why this exists: when a NAS's network interface drops (a cable or switch
// hiccup, a DHCP renewal that briefly removes the address, a second NIC
// stealing the route), every DNS lookup in the house fails at once and every
// upstream looks dead, because Shepherd cannot reach anything. The probes that
// watch for that run every couple of minutes and need several bad samples in a
// row, so a ten-second drop is invisible to them. linkwatch looks at the
// interface itself once a second, so a drop of any length is caught and
// reported with its cause and duration the moment the link returns.
package linkwatch
