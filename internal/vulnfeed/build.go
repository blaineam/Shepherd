// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"shepherd/internal/vulnscan"
)

// Selection thresholds. A CVE joins the feed when CISA lists it as
// exploited in the wild (whatever its score), or when the NVD scores it
// as reachable over the network without credentials and at least this
// severe. Everything else — local bugs, ones that need an account, low
// scores — is left out on purpose: a home-network scanner that lit up on
// every medium CVE in an old PHP would train people to ignore it.
const (
	criticalScore = 9.0
	highScore     = 7.0
)

// Stats is what a build chose and why, for the log and the feed's Source.
type Stats struct {
	Considered int
	KEV        int
	Critical   int
	High       int
	NoRange    int // selected but with no usable version range
	Rejected   int
}

// Build turns the fetched CVEs (keyed by product name) and the KEV catalog
// into a feed. It is deterministic for the same inputs so the published
// JSON only changes when the data does.
func Build(now time.Time, cves map[string][]CVE, kev map[string]KEVEntry) (*vulnscan.Feed, Stats) {
	var st Stats
	feed := &vulnscan.Feed{Schema: vulnscan.FeedSchema, GeneratedAt: now.UTC().Truncate(time.Second)}

	for _, p := range Products {
		critical := map[string][]vulnscan.VersionRange{}
		high := map[string][]vulnscan.VersionRange{}
		for _, c := range cves[p.Name] {
			st.Considered++
			if rejected(c) {
				st.Rejected++
				continue
			}
			ranges := affectedRanges(c, p)
			kevEntry, inKEV := kev[c.ID]
			score, av, pr, ui := cvss(c)
			networkNoCreds := av == "NETWORK" && pr == "NONE"
			switch {
			case inKEV:
				if len(ranges) == 0 {
					st.NoRange++
					continue
				}
				st.KEV++
				feed.Signatures = append(feed.Signatures, kevSignature(p, c, kevEntry, ranges))
			case networkNoCreds && score >= criticalScore:
				if len(ranges) == 0 {
					st.NoRange++
					continue
				}
				st.Critical++
				critical[c.ID] = ranges
			case networkNoCreds && ui == "NONE" && score >= highScore:
				if len(ranges) == 0 {
					st.NoRange++
					continue
				}
				st.High++
				high[c.ID] = ranges
			}
		}
		if len(critical) > 0 {
			feed.Signatures = append(feed.Signatures, aggregateSignature(p, vulnscan.SeverityCritical, critical))
		}
		if len(high) > 0 {
			feed.Signatures = append(feed.Signatures, aggregateSignature(p, vulnscan.SeverityHigh, high))
		}
	}
	sort.Slice(feed.Signatures, func(i, j int) bool { return feed.Signatures[i].ID < feed.Signatures[j].ID })
	feed.Source = fmt.Sprintf("NVD CVE API 2.0 and CISA KEV, built by cmd/vulnfeed: %d CVEs considered, %d exploited-in-the-wild, %d critical, %d high", st.Considered, st.KEV, st.Critical, st.High)
	return feed, st
}

func rejected(c CVE) bool {
	if strings.EqualFold(c.VulnStatus, "Rejected") {
		return true
	}
	return strings.HasPrefix(description(c), "** REJECT **")
}

func description(c CVE) string {
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			return strings.TrimSpace(d.Value)
		}
	}
	if len(c.Descriptions) > 0 {
		return strings.TrimSpace(c.Descriptions[0].Value)
	}
	return ""
}

// cvss picks the metric to judge by: CVSS 3.1 over 3.0, and within one
// version the NVD's own ("Primary") assessment over a CNA's.
func cvss(c CVE) (score float64, attackVector, privilegesRequired, userInteraction string) {
	pick := func(ms []cvssMetric) (cvssMetric, bool) {
		if len(ms) == 0 {
			return cvssMetric{}, false
		}
		for _, m := range ms {
			if m.Type == "Primary" {
				return m, true
			}
		}
		return ms[0], true
	}
	m, ok := pick(c.Metrics.V31)
	if !ok {
		m, ok = pick(c.Metrics.V30)
	}
	if !ok {
		return 0, "", "", ""
	}
	return m.CVSSData.BaseScore, m.CVSSData.AttackVector, m.CVSSData.PrivilegesRequired, m.CVSSData.UserInteraction
}

// affectedRanges reads the CVE's affected configurations for this product
// into version ranges. A match whose version is a wildcard with no bounds
// at all would mean "every version ever", which is never what a CVE really
// means and would flag every install, so it is dropped.
func affectedRanges(c CVE, p Product) []vulnscan.VersionRange {
	seen := map[vulnscan.VersionRange]bool{}
	var out []vulnscan.VersionRange
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable || !matchesProduct(m.Criteria, p) {
					continue
				}
				r, ok := rangeOf(m)
				if !ok || seen[r] {
					continue
				}
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return rangeKey(out[i]) < rangeKey(out[j]) })
	return out
}

func matchesProduct(criteria string, p Product) bool {
	for _, cpe := range p.CPEs {
		if strings.HasPrefix(criteria, cpe+":") {
			return true
		}
	}
	return false
}

// rangeOf turns one CPE match into a version range. The version is the
// sixth colon-separated field of a CPE 2.3 string
// ("cpe:2.3:a:openbsd:openssh:9.6:p1:..." → "9.6"); "*" defers to the
// explicit bounds and "-" means no version information at all.
func rangeOf(m CPEMatch) (vulnscan.VersionRange, bool) {
	parts := strings.Split(m.Criteria, ":")
	if len(parts) < 6 {
		return vulnscan.VersionRange{}, false
	}
	v := parts[5]
	switch v {
	case "-":
		return vulnscan.VersionRange{}, false
	case "*":
		r := vulnscan.VersionRange{GTE: cleanVersion(m.VersionStartIncluding), GT: cleanVersion(m.VersionStartExcluding), LTE: cleanVersion(m.VersionEndIncluding), LT: cleanVersion(m.VersionEndExcluding)}
		if r.GTE == "" && r.GT == "" && r.LTE == "" && r.LT == "" {
			return vulnscan.VersionRange{}, false
		}
		return r, true
	}
	v = cleanVersion(v)
	if v == "" {
		return vulnscan.VersionRange{}, false
	}
	return vulnscan.VersionRange{EQ: v}, true
}

// cleanVersion drops anything vulnscan's own parser could not read (it
// wants dotted numbers with at most one trailing suffix), and unescapes the
// CPE backslash escaping ("1\.2" is "1.2").
func cleanVersion(v string) string {
	v = strings.ReplaceAll(v, `\`, "")
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !(v[0] >= '0' && v[0] <= '9') {
		return ""
	}
	if _, ok := parseable(v); !ok {
		return ""
	}
	return v
}

// parseable mirrors vulnscan.ParseFeed's version validation by round-
// tripping a one-signature feed through it, so the generator can never
// emit a version the consumer rejects.
func parseable(v string) (string, bool) {
	doc := fmt.Sprintf(`{"schema":1,"signatures":[{"id":"x","name":"x","severity":"low","description":"x","match":{"product":"openssh","versions":[{"eq":%q}]}}]}`, v)
	_, err := vulnscan.ParseFeed([]byte(doc))
	return v, err == nil
}

func rangeKey(r vulnscan.VersionRange) string {
	return r.CVE + "|" + r.GTE + "|" + r.GT + "|" + r.LTE + "|" + r.LT + "|" + r.EQ
}

const maxDescription = 600

func kevSignature(p Product, c CVE, k KEVEntry, ranges []vulnscan.VersionRange) vulnscan.FeedSignature {
	desc := description(c)
	if len(desc) > maxDescription {
		desc = desc[:maxDescription-1] + "…"
	}
	if k.ShortDescription != "" && desc == "" {
		desc = k.ShortDescription
	}
	desc += fmt.Sprintf(" CISA added this to its Known Exploited Vulnerabilities catalog on %s: it is being exploited in the wild, not just theoretically. Update %s now.", k.DateAdded, p.Label)
	return vulnscan.FeedSignature{
		ID:          "kev-" + strings.ToLower(c.ID),
		Name:        fmt.Sprintf("%s: %s (actively exploited)", p.Label, c.ID),
		Severity:    vulnscan.SeverityCritical,
		Description: strings.TrimSpace(desc),
		CVEs:        []string{c.ID},
		Match:       vulnscan.FeedMatch{Product: p.Name, Versions: ranges},
	}
}

func aggregateSignature(p Product, sev vulnscan.Severity, byCVE map[string][]vulnscan.VersionRange) vulnscan.FeedSignature {
	ids := make([]string, 0, len(byCVE))
	for id := range byCVE {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var ranges []vulnscan.VersionRange
	for _, id := range ids {
		for _, r := range byCVE[id] {
			r.CVE = id
			ranges = append(ranges, r)
		}
	}
	tier, what := "critical", "critical (CVSS 9.0 or higher) and exploitable over the network with no credentials"
	if sev == vulnscan.SeverityHigh {
		tier, what = "high", "high (CVSS 7.0 to 8.9) and exploitable over the network with no credentials and no user interaction"
	}
	return vulnscan.FeedSignature{
		ID:       fmt.Sprintf("nvd-%s-%s", tier, p.Name),
		Name:     fmt.Sprintf("%s with known %s-severity CVEs", p.Label, tier),
		Severity: sev,
		Description: fmt.Sprintf("This %s version falls inside the affected range of at least one of %d CVEs the NVD rates %s. "+
			"The matched CVE identifiers are in the evidence; look each up at nvd.nist.gov/vuln/detail/<id>. "+
			"A distribution that backports fixes without changing the version string will show up here too, so check what your vendor actually patched; "+
			"otherwise update %s to a current release.", p.Label, len(ids), what, p.Label),
		Match: vulnscan.FeedMatch{Product: p.Name, Versions: ranges},
	}
}
