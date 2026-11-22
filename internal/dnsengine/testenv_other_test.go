// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package dnsengine

import "testing"

// refusePort cannot reserve a port without listening here, so the port is
// left as it is, as these tests always had it.
func refusePort(*testing.T, int) bool { return true }
