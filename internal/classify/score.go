// SPDX-License-Identifier: AGPL-3.0-or-later

package classify

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"shepherd/internal/devices"
)

// The scoring model. Every family of evidence turns into a strength between
// 0 and 1 per class; a class's total is the noisy-or of its families,
// 1 - (1-a)(1-b)..., so independent clues add up without ever passing 1 and
// no single weak clue can reach the threshold on its own.
//
//	domains    1 - exp(-h/2.5), h = recognised lookups weighted by rule weight,
//	           at most 5 counted per registrable domain
//	ASNs       0.4 * (1 - exp(-h/2)), the same counting on weak network hints
//	mDNS       the rule weight, once per kind of service
//	names      0.75 when the device's name or model names a class
//	vendor     the manufacturer rule's weight (ignored for private addresses)
//	private    a small prior toward phone-like classes for randomized MACs
//
// Confidence is the winner's total minus a share of the runner-up's, so
// conflicting evidence lowers it: half of the runner-up, a fifth when the two
// classes are close relatives (TV and streaming box).
const (
	domainK     = 2.5
	asnK        = 2.0
	asnCap      = 0.4
	nameWeight  = 0.75
	conflictRho = 0.5
	relatedRho  = 0.2
	minReason   = 0.08
	minAlt      = 0.15
	maxReasons  = 3
)

// randomizedPrior is what a private (randomized) address alone suggests:
// modern phones, tablets and laptops randomize, most other devices do not.
var randomizedPrior = map[devices.DeviceType]float32{
	devices.TypePhone: 0.22, devices.TypeTablet: 0.08, devices.TypeLaptop: 0.10,
}

// Alternative is a runner-up class.
type Alternative struct {
	Type       devices.DeviceType `json:"type"`
	Confidence float64            `json:"confidence"`
}

// Result is the classifier's answer for one device.
type Result struct {
	// Type is the class, or devices.TypeUnknown when the evidence is below
	// the threshold: never a wild guess.
	Type devices.DeviceType `json:"type"`
	// Confidence is 0 to 1. For a named class it is at least the threshold.
	// For unknown it is the confidence of the best candidate, below the
	// threshold, so a screen can say "weak hint".
	Confidence float64 `json:"confidence"`
	// Reasons are short plain sentences a person can read.
	Reasons []string `json:"reasons"`
	// Alternatives are the other classes with meaningful evidence.
	Alternatives []Alternative `json:"alternatives,omitempty"`

	scores map[devices.DeviceType]float64
	stable []string
	// evidence summarises how much there was to go on (decayed lookups).
	lookups float64
}

// Score is the raw (not conflict-adjusted) strength of evidence for a class.
func (r Result) Score(t devices.DeviceType) float64 { return r.scores[t] }

// Summary is the stored form of the reasons: the same sentences without
// counts, so the text only changes when the story does. It is what Apply
// writes to the registry.
func (r Result) Summary() string { return strings.Join(r.stable, "; ") }

func noisyOr(a, b float32) float32 { return 1 - (1-a)*(1-b) }

// classify scores one device. The caller holds the shard lock.
func (c *Classifier) classify(e *devEvidence, now time.Time) Result {
	e.decay(now, c.cfg.halfLife)
	rs := c.rs
	n := len(rs.classes)

	var fam [6]vec // name, service, domain, asn, vendor, private
	const (
		fName = iota
		fService
		fDomain
		fASN
		fVendor
		fPrivate
	)
	if t, ok := rs.classIdx[e.info.nameType]; ok && e.info.nameType != devices.TypeUnknown {
		fam[fName][t] = nameWeight
	}
	// mDNS: strongest weight per kind of service, then noisy-or across kinds.
	var perLabel [maxLabels]vec
	var usedLabel [maxLabels]bool
	for _, s := range e.info.services {
		if r := rs.services[s]; r != nil {
			usedLabel[r.LabelIdx] = true
			for i, w := range r.W {
				perLabel[r.LabelIdx][i] = max(perLabel[r.LabelIdx][i], w)
			}
		}
	}
	for l := range perLabel {
		if usedLabel[l] {
			for i := 0; i < n; i++ {
				fam[fService][i] = noisyOr(fam[fService][i], perLabel[l][i])
			}
		}
	}
	for i := 0; i < n; i++ {
		fam[fDomain][i] = float32(1 - math.Exp(-float64(e.dom[i])/domainK))
		fam[fASN][i] = float32(asnCap * (1 - math.Exp(-float64(e.asn[i])/asnK)))
	}
	if e.info.randomized {
		for t, w := range randomizedPrior {
			if i, ok := rs.classIdx[t]; ok {
				fam[fPrivate][i] = w
			}
		}
	} else if e.info.vrule != nil && !e.info.vrule.Neutral {
		fam[fVendor] = e.info.vrule.W
	}

	type cand struct {
		idx   int
		score float32
	}
	var cands []cand
	scores := make(map[devices.DeviceType]float64, n)
	for i := 0; i < n; i++ {
		var t float32
		for f := range fam {
			t = noisyOr(t, fam[f][i])
		}
		if t > 0 {
			cands = append(cands, cand{i, t})
			scores[rs.classes[i].ID] = float64(t)
		}
	}
	sort.Slice(cands, func(a, b int) bool {
		if cands[a].score != cands[b].score {
			return cands[a].score > cands[b].score
		}
		return cands[a].idx < cands[b].idx
	})

	res := Result{Type: devices.TypeUnknown, scores: scores, lookups: float64(e.lookups)}
	if len(cands) == 0 {
		res.Reasons = []string{"Not enough evidence yet to tell what this is"}
		res.stable = res.Reasons
		c.addPrivateNote(&res, e)
		return res
	}
	top := cands[0]
	var second float32
	related := false
	if len(cands) > 1 {
		second = cands[1].score
		related = rs.related[top.idx][cands[1].idx]
	}
	rho := float32(conflictRho)
	if related {
		rho = relatedRho
	}
	conf := math.Max(0, float64(top.score-rho*second))
	conf = math.Min(conf, 0.99)
	res.Confidence = round2(conf)
	for _, a := range cands[1:] {
		if a.score < minAlt || len(res.Alternatives) == 3 {
			break
		}
		res.Alternatives = append(res.Alternatives, Alternative{rs.classes[a.idx].ID, round2(float64(a.score))})
	}
	named := conf >= c.threshold
	if named {
		res.Type = rs.classes[top.idx].ID
	}

	// Reasons are explained for the best candidate even when it falls short,
	// so a weak hint still says what it rests on.
	counted, stable := c.reasons(e, fam[:], top.idx)
	if !named {
		counted = append([]string{"Not enough evidence yet to be sure"}, counted...)
		stable = append([]string{"Not enough evidence yet to be sure"}, stable...)
	}
	if second >= 0.3 {
		why := fmt.Sprintf("Some evidence also points to a %s, so confidence is lower", rs.classes[cands[1].idx].ID)
		counted = append(counted, why)
		stable = append(stable, why)
	}
	res.Reasons, res.stable = counted, stable
	c.addPrivateNote(&res, e)
	return res
}

func (c *Classifier) addPrivateNote(res *Result, e *devEvidence) {
	if e.info.randomized {
		const note = "Uses a private (randomized) address, so the manufacturer is hidden"
		res.Reasons = append(res.Reasons, note)
		res.stable = append(res.stable, note)
	}
}

// reasons explains the top class: the strongest families first, at most three
// sentences. The first slice has the counts people like to read, the second
// is the count-free stored form.
func (c *Classifier) reasons(e *devEvidence, fam []vec, top int) (counted, stable []string) {
	const (
		fName = iota
		fService
		fDomain
		fASN
		fVendor
	)
	type item struct {
		strength float32
		a, b     string
	}
	var items []item
	add := func(s float32, a, b string) {
		if s >= minReason {
			items = append(items, item{s, a, b})
		}
	}
	if fam[fName][top] > 0 && e.info.nameReason != "" {
		why := strings.Replace(e.info.nameReason, "name or model contains", "Its name or model contains", 1)
		add(fam[fName][top], why, why)
	}
	if fam[fService][top] >= minReason {
		best, bw := -1, float32(0)
		for _, s := range e.info.services {
			if r := c.rs.services[s]; r != nil && r.W[top] > bw {
				best, bw = r.LabelIdx, r.W[top]
			}
		}
		if best >= 0 {
			why := "Advertises " + c.rs.labels[best] + " on the network"
			add(fam[fService][top], why, why)
		}
	}
	if fam[fDomain][top] >= minReason {
		type lab struct {
			idx  int
			hits float32
		}
		var labs []lab
		for l := range c.rs.labels {
			if e.labelHits[l] >= 1 && c.rs.labelW[l][top] > 0 {
				labs = append(labs, lab{l, e.labelHits[l] * c.rs.labelW[l][top]})
			}
		}
		sort.Slice(labs, func(a, b int) bool { return labs[a].hits > labs[b].hits })
		for i, l := range labs {
			if i == 2 {
				break
			}
			n := int(e.labelHits[l.idx] + 0.5)
			name := c.rs.labels[l.idx]
			var counted string
			if i == 0 && e.matched > 0 && e.labelHits[l.idx]/e.matched >= 0.6 && n >= 3 {
				counted = "Most of its recognised lookups go to " + name
			} else {
				counted = fmt.Sprintf("%d %s to %s", n, plural(n, "lookup", "lookups"), name)
			}
			add(fam[fDomain][top]/float32(i+1), counted, "Lookups go to "+name)
		}
	}
	if fam[fASN][top] >= minReason {
		best, bh := -1, float32(0)
		for l := range c.rs.labels {
			if e.asnLabelHits[l] > bh && c.rs.labelW[l][top] > 0 {
				best, bh = l, e.asnLabelHits[l]
			}
		}
		if best >= 0 {
			n := int(bh + 0.5)
			add(fam[fASN][top], fmt.Sprintf("%d %s resolve to %s", n, plural(n, "lookup", "lookups"), c.rs.labels[best]),
				"Connections go to "+c.rs.labels[best])
		}
	}
	if fam[fVendor][top] >= minReason && e.info.vrule != nil {
		why := fmt.Sprintf("Manufacturer (%s) is known for %s", e.info.vendor, e.info.vrule.KnownFor)
		add(fam[fVendor][top], why, why)
	}
	sort.SliceStable(items, func(a, b int) bool { return items[a].strength > items[b].strength })
	for i, it := range items {
		if i == maxReasons {
			break
		}
		counted = append(counted, it.a)
		stable = append(stable, it.b)
	}
	return counted, stable
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
