// SPDX-License-Identifier: AGPL-3.0-or-later

// Package accountability implements accountability-partner email alerts: an
// opt-in feature that lets someone invite a trusted contact to be emailed
// when a device they chose, in a group they chose, accesses a category they
// chose.
//
// This is a recovery and awareness tool, not a surveillance or enforcement
// feature. See docs/ACCOUNTABILITY.md for the full design and the numbered
// privacy and tone rules that shape every default in this package. In short:
//
//   - Nothing is watched unless a contact is explicitly subscribed to a
//     scope (a group or a device) and a set of catalog items. There is no
//     "watch everything" mode.
//   - A subscription's TriggerOn decides whether it cares about every
//     matching access ("any", the default — monitor-and-disclose, the way
//     Covenant Eyes and similar tools work) or only attempts the policy
//     engine actually blocked ("blocked_only").
//   - A subscription's Detail decides how much the email says: "summary"
//     (what category, roughly when, roughly which device or group — never a
//     domain name) by default, or "detailed" (also the specific domain).
//   - A subscription's Mode decides when the email goes out: "digest" (a
//     periodic rollup, daily by default) unless the person setting it up
//     chooses "immediate". Even immediate mode coalesces a burst within a
//     short window into one email, never one email per attempt.
//
// This package has no dependency on internal/dnsengine or internal/devices.
// It is fed by a small event type (AccessEvent) that a caller — the
// maintainer's wiring, not built here — constructs from whatever the policy
// engine actually decided. Likewise it holds no portal authentication of its
// own: the accountability partner receives email only, never a login.
package accountability
