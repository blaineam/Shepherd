// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix && !linux

package dhcp

// bindToDevice is a no-op away from Linux: SO_BINDTODEVICE is a Linux
// socket option. DHCP mode is only supported on Linux (docs/DHCP.md); this
// exists so the package builds and its tests run on a developer's Mac.
func bindToDevice(int, string) error { return nil }
