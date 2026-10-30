// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package arp

// Open is only implemented on Linux. Elsewhere it returns ErrUnsupported so
// callers can report that passive ARP monitoring is unavailable.
func Open(iface string) (Source, string, error) { return nil, "", ErrUnsupported }
