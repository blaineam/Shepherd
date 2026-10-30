// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import (
	"regexp"
	"strconv"
	"strings"
)

// parsedVersion is a dotted numeric version ("7.4.1" -> [7 4 1]), compared
// component by component. A missing trailing component reads as zero, so
// "7.4" is less than "7.4.1" but equal to "7.4.0".
type parsedVersion []int

// parseVersion parses a dotted numeric version, stripping one trailing
// non-numeric suffix from the last component (OpenSSH's "7.4p1" is "7.4"
// plus a patch letter Shepherd does not need to compare).
func parseVersion(s string) (parsedVersion, bool) {
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	out := make(parsedVersion, 0, len(parts))
	for i, p := range parts {
		if i == len(parts)-1 {
			p = leadingDigits(p)
		}
		if p == "" {
			return nil, false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// leadingDigits returns the longest leading run of ASCII digits in s.
func leadingDigits(s string) string {
	for i, r := range s {
		if r < '0' || r > '9' {
			return s[:i]
		}
	}
	return s
}

// less reports whether a < b.
func (a parsedVersion) less(b parsedVersion) bool {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// equal reports whether a and b compare equal (missing trailing components
// counted as zero, the same rule less uses).
func (a parsedVersion) equal(b parsedVersion) bool { return !a.less(b) && !b.less(a) }

// serverVersionRE matches well-known "Product/x.y.z" tokens anywhere in an
// HTTP Server header, case-insensitively.
var serverVersionRE = regexp.MustCompile(`(?i)(apache|nginx|lighttpd)/([0-9]+(?:\.[0-9]+){0,3})`)

// parseServerVersion extracts the product name (lower-cased) and version
// string from an HTTP "Server:" header, for the products Shepherd's
// signature list knows about. Anything else, or a header with no version at
// all, reports ok=false.
func parseServerVersion(header string) (product, version string, ok bool) {
	m := serverVersionRE.FindStringSubmatch(header)
	if m == nil {
		return "", "", false
	}
	return strings.ToLower(m[1]), m[2], true
}

// sshBannerRE matches an SSH identification string's protocol version
// ("SSH-2.0-...", "SSH-1.99-...", "SSH-1.5-...") per RFC 4253 section 4.2.
var sshBannerRE = regexp.MustCompile(`^SSH-(\d+)\.(\d+)-(.*)$`)

// parseSSHProtocolMajor returns the protocol major version an SSH banner
// advertises (1 or 2), ok=false when banner is not an SSH identification
// string at all.
func parseSSHProtocolMajor(banner string) (major int, ok bool) {
	m := sshBannerRE.FindStringSubmatch(banner)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// openSSHSoftwareRE matches the OpenSSH software-version token within an
// SSH banner's software-version field ("OpenSSH_9.6", "OpenSSH_7.4p1").
var openSSHSoftwareRE = regexp.MustCompile(`(?i)OpenSSH_([0-9]+(?:\.[0-9]+)*)`)

// parseOpenSSHVersion returns ("openssh", version, true) when banner is an
// SSH identification string whose software field names OpenSSH. Other SSH
// servers (Dropbear, libssh, ...) report ok=false: Shepherd's signature list
// only knows OpenSSH's own version history so far (docs/VULNSCAN.md).
func parseOpenSSHVersion(banner string) (software, version string, ok bool) {
	full := sshBannerRE.FindStringSubmatch(banner)
	if full == nil {
		return "", "", false
	}
	m := openSSHSoftwareRE.FindStringSubmatch(full[3])
	if m == nil {
		return "", "", false
	}
	return "openssh", m[1], true
}
