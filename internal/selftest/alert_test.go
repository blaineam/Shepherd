// SPDX-License-Identifier: AGPL-3.0-or-later

package selftest

import (
	"testing"
	"time"
)

func rep(keys ...string) Report {
	var r Report
	for _, k := range keys {
		r.Problems = append(r.Problems, Problem{Check: CheckListener, Subject: k, Severity: StatusFail, Message: k})
	}
	return r
}

func TestAlerterConfirmsThenCoolsDown(t *testing.T) {
	now := time.Unix(1000, 0)
	var raised []string
	a := &Alerter{Raise: func(p Problem) { raised = append(raised, p.Subject) }, Now: func() time.Time { return now }}

	a.Observe(rep("a")) // first failure: not yet
	if len(raised) != 0 {
		t.Fatalf("raised on the first failure: %v", raised)
	}
	a.Observe(rep("a", "b")) // a confirmed; b first time
	if len(raised) != 1 || raised[0] != "a" {
		t.Fatalf("raised = %v", raised)
	}
	for i := 0; i < 10; i++ { // still failing: cooldown holds
		now = now.Add(time.Minute)
		a.Observe(rep("a", "b"))
	}
	if len(raised) != 2 || raised[1] != "b" {
		t.Fatalf("raised = %v", raised)
	}
	// A flap resets the streak but not the cooldown: no new alarm for a.
	a.Observe(rep())
	a.Observe(rep("a"))
	a.Observe(rep("a"))
	if len(raised) != 2 {
		t.Fatalf("a flapping check raised again inside the cooldown: %v", raised)
	}
	now = now.Add(31 * time.Minute)
	a.Observe(rep("a"))
	if len(raised) != 3 || raised[2] != "a" {
		t.Fatalf("raised = %v", raised)
	}
}

func TestAlerterDefaultsAndCustomSettings(t *testing.T) {
	var n int
	a := &Alerter{Raise: func(Problem) { n++ }, Confirm: 1, Cooldown: time.Millisecond}
	a.Observe(rep("x"))
	time.Sleep(5 * time.Millisecond)
	a.Observe(rep("x"))
	if n != 2 {
		t.Fatalf("raised %d times", n)
	}
}
