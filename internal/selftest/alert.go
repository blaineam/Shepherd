// SPDX-License-Identifier: AGPL-3.0-or-later

package selftest

import (
	"sync"
	"time"
)

// Alerter turns reports into alarm-worthy problems without spamming: a
// problem must fail Confirm rounds in a row before it is raised (one lost
// packet is not an outage), and once raised it is not raised again for
// Cooldown, however long it keeps failing or however often it flaps.
type Alerter struct {
	// Raise is called for each problem that crosses the line.
	Raise func(Problem)
	// Confirm is how many consecutive failing rounds raise a problem
	// (default 2).
	Confirm int
	// Cooldown is the minimum time between two raises of the same problem
	// (default 30 minutes).
	Cooldown time.Duration
	// Now is the clock; default time.Now.
	Now func() time.Time

	mu     sync.Mutex
	streak map[string]int
	last   map[string]time.Time
}

// Observe feeds one report in.
func (a *Alerter) Observe(r Report) {
	confirm, cooldown, now := a.Confirm, a.Cooldown, time.Now()
	if confirm <= 0 {
		confirm = 2
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Minute
	}
	if a.Now != nil {
		now = a.Now()
	}
	var fire []Problem
	a.mu.Lock()
	if a.streak == nil {
		a.streak, a.last = map[string]int{}, map[string]time.Time{}
	}
	failing := map[string]bool{}
	for _, p := range r.Problems {
		k := p.Key()
		failing[k] = true
		a.streak[k]++
		if a.streak[k] >= confirm {
			if at, ok := a.last[k]; !ok || now.Sub(at) >= cooldown {
				a.last[k] = now
				fire = append(fire, p)
			}
		}
	}
	for k := range a.streak {
		if !failing[k] {
			delete(a.streak, k) // a clean round resets the streak, not the cooldown
		}
	}
	a.mu.Unlock()
	for _, p := range fire {
		a.Raise(p)
	}
}
