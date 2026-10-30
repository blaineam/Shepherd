// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"strconv"
	"strings"
)

// NormalizeMAC canonicalizes a MAC address to lower-case colon form. It
// accepts colon, dash, Cisco-dotted and bare forms, and the macOS style that
// drops leading zeros ("2:0:5e:0:0:1"). Zero, broadcast and multicast
// addresses are not device identities and are rejected.
func NormalizeMAC(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	var parts []string
	switch {
	case strings.ContainsAny(s, ":-"):
		parts = strings.FieldsFunc(s, func(r rune) bool { return r == ':' || r == '-' })
		if len(parts) != 6 {
			return "", false
		}
	default:
		s = strings.ReplaceAll(s, ".", "")
		if len(s) != 12 {
			return "", false
		}
		for i := 0; i < 12; i += 2 {
			parts = append(parts, s[i:i+2])
		}
	}
	out := make([]string, 6)
	var first uint64
	allZero := true
	for i, p := range parts {
		if len(p) == 0 || len(p) > 2 {
			return "", false
		}
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return "", false
		}
		if i == 0 {
			first = v
		}
		if v != 0 {
			allZero = false
		}
		out[i] = string("0123456789abcdef"[v>>4]) + string("0123456789abcdef"[v&15])
	}
	if allZero || first&1 == 1 {
		return "", false
	}
	return strings.Join(out, ":"), true
}

// IsLocallyAdministered reports whether a normalized MAC has the
// locally-administered bit set: the signature of a randomized "private"
// Wi-Fi address (phones and laptops rotate these).
func IsLocallyAdministered(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	v, err := strconv.ParseUint(mac[:2], 16, 8)
	return err == nil && v&2 != 0
}
