// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import "strings"

// Mode is how much of DHCP mode is switched on. See the package comment for
// why this is three states rather than a boolean.
type Mode string

// The three modes.
const (
	// ModeOff opens no socket. The default, and what every existing install
	// keeps.
	ModeOff Mode = "off"
	// ModeObserve listens and decides but has no send path.
	ModeObserve Mode = "observe"
	// ModeServe answers, subject to the gates in Server.
	ModeServe Mode = "serve"
)

// ParseMode reads "off", "observe" or "serve". The empty string is ModeOff,
// so an absent configuration key means off rather than an error.
func ParseMode(s string) (Mode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "false", "no":
		return ModeOff, true
	case "observe", "watch", "listen":
		return ModeObserve, true
	case "serve", "server", "on", "true", "yes":
		return ModeServe, true
	}
	return "", false
}

// Listens reports whether this mode opens a socket at all.
func (m Mode) Listens() bool { return m == ModeObserve || m == ModeServe }

// String returns the mode's configuration spelling.
func (m Mode) String() string {
	if m == "" {
		return string(ModeOff)
	}
	return string(m)
}
