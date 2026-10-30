// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"strings"
	"time"
)

// itemAgg accumulates one watched item's occurrences within a pending
// window.
type itemAgg struct {
	Count   int       `json:"count"`
	Blocked int       `json:"blocked"`
	Allowed int       `json:"allowed"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	// Domains counts occurrences per exact domain. It is populated for
	// every subscription regardless of Detail, because the domain is
	// cheap to keep and restart recovery should not depend on which
	// detail level was configured when the window opened; only the
	// renderer (driven by the subscription's current Detail) decides
	// whether any of this ever reaches an email.
	Domains map[string]int `json:"domains,omitempty"`
}

// pendingDigest is one subscription's in-progress accumulation window: the
// state that must survive a restart (design deliverable 3) so a burst that
// started before Shepherd stopped is still one email, not a double count or
// a silently dropped one.
type pendingDigest struct {
	SubscriptionID string              `json:"subscription_id"`
	Opened         time.Time           `json:"opened"`
	FlushAt        time.Time           `json:"flush_at"`
	Items          map[string]*itemAgg `json:"items"`
	// Devices counts occurrences per client ID, for a rough "which
	// device" line when a subscription watches a group.
	Devices map[string]int `json:"devices,omitempty"`
	Total   int            `json:"total"`
}

func newPendingDigest(subID string, now, flushAt time.Time) *pendingDigest {
	return &pendingDigest{
		SubscriptionID: subID,
		Opened:         now,
		FlushAt:        flushAt,
		Items:          map[string]*itemAgg{},
		Devices:        map[string]int{},
	}
}

// add folds ev into the window.
func (p *pendingDigest) add(ev AccessEvent) {
	it := p.Items[ev.Item]
	if it == nil {
		it = &itemAgg{First: ev.Time}
		p.Items[ev.Item] = it
	}
	it.Count++
	it.Last = ev.Time
	if isBlocked(ev.Action) {
		it.Blocked++
	} else {
		it.Allowed++
	}
	if ev.Domain != "" {
		if it.Domains == nil {
			it.Domains = map[string]int{}
		}
		it.Domains[ev.Domain]++
	}
	if ev.ClientID != "" {
		p.Devices[ev.ClientID]++
	}
	p.Total++
}

func isBlocked(action string) bool { return strings.EqualFold(action, "blocked") }

// windowFor returns the accumulation window for mode: DigestInterval for
// digest mode (default dayWindow), or immediateWindow for immediate mode.
func windowFor(sub Subscription, immediateWindow time.Duration) time.Duration {
	if sub.Mode == ModeImmediate {
		return immediateWindow
	}
	if sub.DigestInterval > 0 {
		return sub.DigestInterval
	}
	return defaultDigestInterval
}

// defaultDigestInterval is "daily" (design rule 2's default).
const defaultDigestInterval = 24 * time.Hour

// defaultImmediateWindow is the dedupe window applied to immediate-mode
// subscriptions (design rule 2: even an opt-in to "immediate" still
// coalesces a burst into one email).
const defaultImmediateWindow = 5 * time.Minute
