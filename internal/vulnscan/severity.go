// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

// Severity ranks a finding on the same five-step scale internal/alarms uses
// (info < low < medium < high < critical). It is its own type, not
// alarms.Severity, so this package never has to import internal/alarms just
// to describe how bad a finding is: cmd/shepherd's alarm wiring
// (cmd/shepherd/vulnscan.go) converts one to the other by name, the same way
// it converts everything else about a finding into an alarms.Event.
type Severity string

// Severities, lowest first.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// valid reports whether s is one of the five known severities.
func (s Severity) valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}
