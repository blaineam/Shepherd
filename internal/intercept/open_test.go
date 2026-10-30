// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import "testing"

// TestOpenReportsAnError mirrors internal/arp's TestOpenReportsAnError:
// unprivileged and without a real interface, Open must fail cleanly on
// every platform (ErrUnsupported off Linux, a lookup or permission error
// on Linux), never panic, and never return a usable Sender.
func TestOpenReportsAnError(t *testing.T) {
	s, err := Open("shepherd-no-such-iface0")
	if err == nil {
		t.Fatal("Open succeeded")
	}
	if s != nil {
		t.Fatal("Open returned a non-nil Sender alongside an error")
	}
}
