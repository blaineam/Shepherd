// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"strings"
	"testing"
	"time"
)

// These two cases are the canonical examples reproduced in full in
// docs/ACCOUNTABILITY.md. They are golden/snapshot tests on purpose: a
// future wording change must show up here as a visible diff, never
// silently (see docs/ACCOUNTABILITY.md design rule 3). Every name, address
// and domain here is synthetic.

const wantDigestSubject = "A check-in about the Family Devices group"

const wantDigestBody = `Hi Jordan,

You're set up as an accountability contact for the Family Devices group, so here's the check-in for Oct 19 to Oct 25.

There were 4 accesses in a category you're both keeping an eye on:

  - Adult Content: 4 times (blocked)

That's everything for this check-in — nothing else to see, no log to review. This is meant as a starting
point for a conversation, not a verdict, so however it comes up, it might be worth asking how things are
going.

No reply is needed. You're getting this because someone chose you as an accountability partner for
the Family Devices group; if that ever changes, these emails stop.

— Shepherd
`

const wantImmediateSubject = "A heads-up about a console in the Family Devices group"

const wantImmediateBody = `Hi Avery,

A quick heads-up from a console in the Family Devices group, around Oct 25 at 4:12 PM UTC:

  - Roblox: 1 time
      play.example.com

This is just what happened, not an accusation — plenty of browsing crosses categories without meaning
anything. If it's useful, it might be worth checking in.

No reply is needed. You're getting this because someone chose you as an accountability partner for
a console in the Family Devices group; if that ever changes, these emails stop.

— Shepherd
`

func TestRenderEmailSummaryDigestSnapshot(t *testing.T) {
	data := emailData{
		ContactName: "Jordan",
		ScopeLabel:  "the Family Devices group",
		Mode:        ModeDigest,
		Detail:      DetailSummary,
		WindowStart: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC),
		WindowEnd:   time.Date(2026, 10, 25, 20, 14, 0, 0, time.UTC),
		Total:       4,
		Items:       []itemLine{{Label: "Adult Content", Count: 4, AllBlocked: true}},
	}
	subj, body, err := renderEmail(data)
	if err != nil {
		t.Fatal(err)
	}
	if subj != wantDigestSubject {
		t.Errorf("subject = %q, want %q", subj, wantDigestSubject)
	}
	if body != wantDigestBody {
		t.Errorf("body mismatch:\ngot:\n%s\nwant:\n%s", body, wantDigestBody)
	}
	// Design rule 1: a summary email never names a domain.
	if strings.Contains(body, ".com") || strings.Contains(body, ".example") {
		t.Errorf("summary email must not contain a domain name:\n%s", body)
	}
}

func TestRenderEmailDetailedImmediateSnapshot(t *testing.T) {
	// The maintainer's own worked example: a device in a watched group
	// accesses a "Roblox" category resource, allowed or blocked, and an
	// external accountability partner is told about it. Not blocked here,
	// which is exactly the point of design rule 2: this is disclosure, not
	// enforcement, so the item is not marked "(blocked)".
	data := emailData{
		ContactName: "Avery",
		ScopeLabel:  "a console in the Family Devices group",
		Mode:        ModeImmediate,
		Detail:      DetailDetailed,
		WindowStart: time.Date(2026, 10, 25, 16, 12, 0, 0, time.UTC),
		WindowEnd:   time.Date(2026, 10, 25, 16, 12, 0, 0, time.UTC),
		Total:       1,
		Items:       []itemLine{{Label: "Roblox", Count: 1, AllBlocked: false, Domains: []string{"play.example.com"}}},
	}
	subj, body, err := renderEmail(data)
	if err != nil {
		t.Fatal(err)
	}
	if subj != wantImmediateSubject {
		t.Errorf("subject = %q, want %q", subj, wantImmediateSubject)
	}
	if body != wantImmediateBody {
		t.Errorf("body mismatch:\ngot:\n%s\nwant:\n%s", body, wantImmediateBody)
	}
	// Design rule 1, the other half: a detailed email does name the domain.
	if !strings.Contains(body, "play.example.com") {
		t.Errorf("detailed email must contain the domain:\n%s", body)
	}
	// Design rule 3: no clinical or accusatory language anywhere.
	for _, bad := range []string{"VIOLATION", "DETECTED", "WARNING", "flagged", "caught"} {
		if strings.Contains(strings.ToUpper(body), strings.ToUpper(bad)) {
			t.Errorf("body contains shaming language %q:\n%s", bad, body)
		}
	}
}

func TestRenderEmailPluralAndSingular(t *testing.T) {
	one := emailData{ContactName: "Jordan", ScopeLabel: "the group", Mode: ModeDigest, Detail: DetailSummary,
		WindowStart: time.Now(), WindowEnd: time.Now(), Total: 1,
		Items: []itemLine{{Label: "Gaming", Count: 1}}}
	_, body, err := renderEmail(one)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "There was one access") {
		t.Errorf("singular phrasing missing:\n%s", body)
	}
	if !strings.Contains(body, "1 time") || strings.Contains(body, "1 times") {
		t.Errorf("item count should say %q not %q:\n%s", "1 time", "1 times", body)
	}
}

func TestRenderEmailMultipleItemsAndDomainsAreSorted(t *testing.T) {
	data := emailData{
		ContactName: "Jordan", ScopeLabel: "the group", Mode: ModeImmediate, Detail: DetailDetailed,
		WindowStart: time.Now(), WindowEnd: time.Now(), Total: 5,
		Items: []itemLine{
			{Label: "Gambling", Count: 3, Domains: []string{"bet.example.com", "wager.example.net"}},
			{Label: "Social", Count: 2, Domains: []string{"social.example.org"}},
		},
	}
	_, body, err := renderEmail(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(body, "Gambling") > strings.Index(body, "Social") {
		t.Errorf("items should be ordered as given (caller sorts):\n%s", body)
	}
}

func TestDefaultLabel(t *testing.T) {
	cases := map[string]string{
		"roblox":         "Roblox",
		"adult-content":  "Adult Content",
		"gaming_console": "Gaming Console",
		Wildcard:         "anything watched",
		"":               "",
	}
	for in, want := range cases {
		if got := defaultLabel(in); got != want {
			t.Errorf("defaultLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDefaultScopeLabel(t *testing.T) {
	if got := defaultScopeLabel(GroupScope("g1")); !strings.Contains(got, "group") {
		t.Errorf("defaultScopeLabel(group) = %q", got)
	}
	if got := defaultScopeLabel(DeviceScope("d1")); !strings.Contains(got, "device") {
		t.Errorf("defaultScopeLabel(device) = %q", got)
	}
	if got := defaultScopeLabel(Scope{}); got == "" {
		t.Errorf("defaultScopeLabel(zero value) returned empty string")
	}
	// Neither form leaks the raw scope ID.
	if got := defaultScopeLabel(GroupScope("super-secret-group-id")); strings.Contains(got, "super-secret-group-id") {
		t.Errorf("defaultScopeLabel leaked the scope ID: %q", got)
	}
}

func TestTopDomainsCapsAndOrders(t *testing.T) {
	counts := map[string]int{
		"a.example.com": 1, "b.example.com": 5, "c.example.com": 3, "d.example.com": 5,
	}
	got := topDomains(counts, 3)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	// highest counts first; ties break by name.
	want := []string{"b.example.com", "d.example.com", "c.example.com"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("topDomains()[%d] = %q, want %q (got %v)", i, got[i], want[i], got)
		}
	}
}

func TestTopDomainsNoLimit(t *testing.T) {
	counts := map[string]int{"a.example.com": 1, "b.example.com": 2}
	got := topDomains(counts, 0)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (0 means no limit)", len(got))
	}
}

func TestSortedItemLinesSummaryOmitsDomains(t *testing.T) {
	agg := newPendingDigest("s1", time.Now(), time.Now())
	agg.add(AccessEvent{Item: "adult-content", Domain: "x.example.com", Action: "blocked"})
	agg.add(AccessEvent{Item: "adult-content", Domain: "y.example.com", Action: "blocked"})
	lines := sortedItemLines(agg, defaultLabel, false, 5)
	if len(lines) != 1 {
		t.Fatalf("len = %d, want 1", len(lines))
	}
	if lines[0].Domains != nil {
		t.Errorf("summary item line carries domains: %v", lines[0].Domains)
	}
	if !lines[0].AllBlocked {
		t.Errorf("expected AllBlocked true when every occurrence was blocked")
	}
}

func TestSortedItemLinesDetailedIncludesDomains(t *testing.T) {
	agg := newPendingDigest("s1", time.Now(), time.Now())
	agg.add(AccessEvent{Item: "gaming", Domain: "play.example.com", Action: "allowed"})
	agg.add(AccessEvent{Item: "gaming", Domain: "play.example.com", Action: "blocked"})
	lines := sortedItemLines(agg, defaultLabel, true, 5)
	if len(lines) != 1 || len(lines[0].Domains) != 1 || lines[0].Domains[0] != "play.example.com" {
		t.Fatalf("lines = %+v", lines)
	}
	if lines[0].AllBlocked {
		t.Errorf("mixed blocked/allowed must not be marked AllBlocked")
	}
}

func TestSortedItemLinesOrdering(t *testing.T) {
	agg := newPendingDigest("s1", time.Now(), time.Now())
	agg.add(AccessEvent{Item: "b-item", Action: "allowed"})
	agg.add(AccessEvent{Item: "a-item", Action: "allowed"})
	agg.add(AccessEvent{Item: "a-item", Action: "allowed"})
	lines := sortedItemLines(agg, defaultLabel, false, 5)
	if len(lines) != 2 || lines[0].Label != "A Item" || lines[1].Label != "B Item" {
		t.Fatalf("lines = %+v, want A Item (count 2) first", lines)
	}
}
