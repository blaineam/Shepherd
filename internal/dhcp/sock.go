// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"errors"
	"strconv"
)

// errNotUDP cannot happen with a "udp4" network, and is here so the type
// assertion that proves it has somewhere to go.
var errNotUDP = errors.New("dhcp: the listener is not a UDP socket")

func itoa(n int) string { return strconv.Itoa(n) }
