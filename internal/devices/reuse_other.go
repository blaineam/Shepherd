// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package devices

import "syscall"

// reuseControl is a no-op where socket reuse options are not wired up; the
// listener then only works if nothing else holds the mDNS port.
func reuseControl(network, address string, c syscall.RawConn) error { return nil }
