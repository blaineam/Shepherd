// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/template"
	"time"
)

// This file is the one place the actual email wording lives, deliberately
// kept separate from the matching and digest logic in engine.go and
// digest.go, so a reviewer can read and improve the copy without following
// any control flow. See docs/ACCOUNTABILITY.md design rule 3: no clinical
// surveillance language, no "VIOLATION DETECTED" — a supportive nudge
// toward a conversation, nothing more, nothing less than what actually
// happened.
//
// Design rule 2 (from the maintainer's own worked example, a device
// accessing a "Roblox" category resource that was never blocked at all):
// "accessed" is the neutral word used throughout. An item is only ever
// marked "(blocked)" when every occurrence counted here really was blocked;
// otherwise the copy says what happened and nothing more, because an access
// that was never blocked is not evidence of anything on its own.

// itemLine is one row of the "what happened" list in an email.
type itemLine struct {
	Label      string
	Count      int
	AllBlocked bool
	// Domains is only populated for Detail: detailed subscriptions; a
	// summary email never receives domain names at all, so there is
	// nothing for the template to accidentally print.
	Domains []string
}

// emailData is everything a template needs. Nothing here is attacker- or
// device-controlled free text beyond catalog item labels and domain names,
// both of which text/template escapes like any other field (this is plain
// text, not HTML, so there is no injection surface, but the discipline is
// kept anyway).
type emailData struct {
	ContactName string
	ScopeLabel  string
	Mode        Mode
	Detail      Detail
	WindowStart time.Time
	WindowEnd   time.Time
	Total       int
	Items       []itemLine
}

var funcs = template.FuncMap{
	"dateRange": func(start, end time.Time) string {
		s, e := start.UTC(), end.UTC()
		if s.Format("2006-01-02") == e.Format("2006-01-02") {
			return s.Format("Jan 2")
		}
		return s.Format("Jan 2") + " to " + e.Format("Jan 2")
	},
	"timeOfDay": func(t time.Time) string { return t.UTC().Format("Jan 2 at 3:04 PM") + " UTC" },
	"plural": func(n int, word string) string {
		if n == 1 {
			return word
		}
		return word + "s"
	},
}

// digestTemplate is the periodic rollup: the default for every subscription
// (design rule 2). It reads as a check-in, not a report card.
const digestTemplateText = `Hi {{.ContactName}},

You're set up as an accountability contact for {{.ScopeLabel}}, so here's the check-in for {{dateRange .WindowStart .WindowEnd}}.

{{if eq .Total 1}}There was one access{{else}}There were {{.Total}} accesses{{end}} in a category you're both keeping an eye on:

{{range .Items}}  - {{.Label}}: {{.Count}} {{plural .Count "time"}}{{if .AllBlocked}} (blocked){{end}}{{range .Domains}}
      {{.}}{{end}}
{{end}}
That's everything for this check-in — nothing else to see, no log to review. This is meant as a starting
point for a conversation, not a verdict, so however it comes up, it might be worth asking how things are
going.

No reply is needed. You're getting this because someone chose you as an accountability partner for
{{.ScopeLabel}}; if that ever changes, these emails stop.

— Shepherd
`

// immediateTemplateText is sent sooner (within the dedupe window described
// in docs/ACCOUNTABILITY.md), but still as one email per burst, never one
// per attempt.
const immediateTemplateText = `Hi {{.ContactName}},

A quick heads-up from {{.ScopeLabel}}, around {{timeOfDay .WindowStart}}{{if .WindowEnd.After .WindowStart}} (through {{timeOfDay .WindowEnd}}){{end}}:

{{range .Items}}  - {{.Label}}: {{.Count}} {{plural .Count "time"}}{{if .AllBlocked}} (blocked){{end}}{{range .Domains}}
      {{.}}{{end}}
{{end}}
This is just what happened, not an accusation — plenty of browsing crosses categories without meaning
anything. If it's useful, it might be worth checking in.

No reply is needed. You're getting this because someone chose you as an accountability partner for
{{.ScopeLabel}}; if that ever changes, these emails stop.

— Shepherd
`

var (
	digestTemplate    = template.Must(template.New("digest").Funcs(funcs).Parse(digestTemplateText))
	immediateTemplate = template.Must(template.New("immediate").Funcs(funcs).Parse(immediateTemplateText))
)

// subject renders the one-line subject for a check-in email.
func subjectFor(mode Mode, scopeLabel string) string {
	if mode == ModeImmediate {
		return "A heads-up about " + scopeLabel
	}
	return "A check-in about " + scopeLabel
}

// renderEmail renders the subject and plain-text body for data. mode picks
// the digest or immediate template; data.Mode should agree (callers set both
// from the same subscription).
func renderEmail(data emailData) (subject, body string, err error) {
	t := digestTemplate
	if data.Mode == ModeImmediate {
		t = immediateTemplate
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("accountability: render email: %w", err)
	}
	return subjectFor(data.Mode, data.ScopeLabel), buf.String(), nil
}

// defaultLabel turns a catalog ID such as "adult-content" into "Adult
// Content" when no ItemLabel function is configured. It is a display
// fallback only; the ID itself is what matching and persistence use.
func defaultLabel(id string) string {
	if id == Wildcard {
		return "anything watched"
	}
	parts := strings.FieldsFunc(id, func(r rune) bool { return r == '-' || r == '_' || r == ' ' })
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
	}
	if len(parts) == 0 {
		return id
	}
	return strings.Join(parts, " ")
}

// defaultScopeLabel is used when no ScopeLabel function is configured.
func defaultScopeLabel(s Scope) string {
	switch s.Kind {
	case ScopeGroup:
		return "a device in the group being watched"
	case ScopeDevice:
		return "the device being watched"
	default:
		return "the scope being watched"
	}
}

// sortedItemLines returns agg's items as template rows, sorted by count
// (highest first) then label, each capped to maxDomains example domains.
func sortedItemLines(agg *pendingDigest, label func(string) string, detailed bool, maxDomains int) []itemLine {
	lines := make([]itemLine, 0, len(agg.Items))
	for id, it := range agg.Items {
		line := itemLine{Label: label(id), Count: it.Count, AllBlocked: it.Blocked > 0 && it.Allowed == 0}
		if detailed {
			line.Domains = topDomains(it.Domains, maxDomains)
		}
		lines = append(lines, line)
	}
	sort.Slice(lines, func(i, j int) bool {
		if lines[i].Count != lines[j].Count {
			return lines[i].Count > lines[j].Count
		}
		return lines[i].Label < lines[j].Label
	})
	return lines
}

// topDomains returns up to max domain names from counts, highest count
// first, name as the tie-break, so output is deterministic.
func topDomains(counts map[string]int, max int) []string {
	type kv struct {
		domain string
		n      int
	}
	kvs := make([]kv, 0, len(counts))
	for d, n := range counts {
		kvs = append(kvs, kv{d, n})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].n != kvs[j].n {
			return kvs[i].n > kvs[j].n
		}
		return kvs[i].domain < kvs[j].domain
	})
	if max > 0 && len(kvs) > max {
		kvs = kvs[:max]
	}
	out := make([]string, len(kvs))
	for i, kv := range kvs {
		out[i] = kv.domain
	}
	return out
}
