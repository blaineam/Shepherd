// SPDX-License-Identifier: AGPL-3.0-or-later

package namesync

import (
	"net/netip"
	"strings"
	"unicode"
)

// How readable a device name is to a person. Higher is better; the gaps
// leave room for the bonus a name gets for having been typed by someone.
const (
	// Useless tells a person nothing: empty, a MAC or IP address, or a
	// placeholder such as "Unknown". It never replaces anything.
	Useless = 0
	// Generic is only the maker's name ("ExampleCo Networks").
	Generic = 5
	// Machine is a model or serial a device reports ("XP200M", "PS5-1B3C5D").
	Machine = 10
	// Plain is one ordinary word, or words with a serial among them
	// ("iPhone", "Hue Bridge 41D7").
	Plain = 20
	// Hostname is ordinary words joined the way a hostname is
	// ("Kitchen-Speaker").
	Hostname = 25
	// Human is words a person would say ("Kitchen speaker").
	Human = 30

	// typedBonus is added when the source knows a person typed the name.
	typedBonus = 15
)

// placeholders are names that stand for "no name".
var placeholders = map[string]bool{
	"unknown": true, "unknown device": true, "(unknown)": true, "private": true,
	"n/a": true, "none": true, "null": true, "device": true, "new device": true,
	"unnamed": true, "generic": true, "localhost": true, "*": true, "?": true, "-": true,
}

// Quality scores name for a device made by vendor, which may be empty.
func Quality(name, vendor string) int {
	n := strings.TrimSpace(name)
	if n == "" {
		return Useless
	}
	lower := strings.ToLower(n)
	if placeholders[lower] {
		return Useless
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return Useless
	}
	if hex := stripSeparators(lower); len(hex) == 12 && isHex(hex) {
		return Useless
	}
	if vendorOnly(lower, strings.ToLower(vendor)) {
		return Generic
	}

	words := strings.Fields(n)
	serial, parts := false, 0
	for _, w := range words {
		for _, p := range strings.FieldsFunc(w, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
			parts++
			if serialish(p) {
				serial = true
			}
		}
	}
	switch {
	case len(words) > 1 && !serial:
		return Human
	case len(words) > 1:
		return Plain
	case serial:
		return Machine
	case parts > 1:
		return Hostname
	}
	return Plain
}

// score is the quality with the typed bonus, which is what names are
// compared by. A useless name stays useless whoever typed it.
func score(e Entry) int {
	q := Quality(e.Name, e.Vendor)
	if q > Useless && e.Typed {
		q += typedBonus
	}
	return q
}

func stripSeparators(s string) string {
	return strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(s)
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// vendorOnly reports whether every word of name is a word of the maker's
// name, so "Acme" for "Shenzhen Acme Technology Co., Ltd.".
func vendorOnly(name, vendor string) bool {
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	}
	vw := map[string]bool{}
	for _, w := range split(vendor) {
		vw[w] = true
	}
	nw := split(name)
	if len(vw) == 0 || len(nw) == 0 {
		return false
	}
	for _, w := range nw {
		if !vw[w] {
			return false
		}
	}
	return true
}

// serialish reports whether a piece of a name reads as a model or serial
// number rather than a word: a long run of digits, or letters and digits
// mixed ("XP200M", "1B3C5D", "K7QZ4T9XWB"). Short pieces such as "4K" or
// "PS5" are words.
func serialish(p string) bool {
	digits, letters := 0, 0
	for _, r := range p {
		switch {
		case unicode.IsDigit(r):
			digits++
		case unicode.IsLetter(r):
			letters++
		}
	}
	n := digits + letters
	switch {
	case letters == 0:
		return digits >= 5
	case digits == 0:
		return false
	case n >= 6:
		return true
	}
	return n >= 4 && digits >= 2
}
