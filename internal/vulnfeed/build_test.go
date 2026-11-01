// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"shepherd/internal/vulnscan"
)

// fixture builds one NVD-shaped CVE record. metrics is the cvssMetricV31
// list; matches the cpeMatch entries of a single OR node.
func fixture(t *testing.T, id, status, desc string, score float64, av, pr, ui string, matches ...CPEMatch) CVE {
	t.Helper()
	type cvss struct {
		Type     string `json:"type"`
		CVSSData struct {
			BaseScore          float64 `json:"baseScore"`
			AttackVector       string  `json:"attackVector"`
			PrivilegesRequired string  `json:"privilegesRequired"`
			UserInteraction    string  `json:"userInteraction"`
		} `json:"cvssData"`
	}
	var m cvss
	m.Type = "Primary"
	m.CVSSData.BaseScore, m.CVSSData.AttackVector, m.CVSSData.PrivilegesRequired, m.CVSSData.UserInteraction = score, av, pr, ui
	doc := map[string]any{
		"id": id, "vulnStatus": status, "published": "2024-07-01T00:00:00.000",
		"descriptions":   []map[string]string{{"lang": "es", "value": "otro"}, {"lang": "en", "value": desc}},
		"metrics":        map[string]any{"cvssMetricV31": []cvss{m}},
		"configurations": []map[string]any{{"nodes": []map[string]any{{"operator": "OR", "cpeMatch": matches}}}},
	}
	b, _ := json.Marshal(doc)
	var c CVE
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func openssh(v string, bounds ...string) CPEMatch {
	m := CPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:openbsd:openssh:" + v + ":*:*:*:*:*:*:*"}
	for i := 0; i+1 < len(bounds); i += 2 {
		switch bounds[i] {
		case "gte":
			m.VersionStartIncluding = bounds[i+1]
		case "gt":
			m.VersionStartExcluding = bounds[i+1]
		case "lte":
			m.VersionEndIncluding = bounds[i+1]
		case "lt":
			m.VersionEndExcluding = bounds[i+1]
		}
	}
	return m
}

func TestBuildSelectsKEVCriticalAndHighAndSkipsTheRest(t *testing.T) {
	now := time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	cves := map[string][]CVE{"openssh": {
		fixture(t, "CVE-2024-6387", "Analyzed", "A signal handler race condition in sshd.", 8.1, "NETWORK", "NONE", "NONE", openssh("*", "gte", "8.5", "lt", "9.8")),
		fixture(t, "CVE-2023-38408", "Analyzed", "PKCS#11 feature in ssh-agent.", 9.8, "NETWORK", "NONE", "NONE", openssh("*", "lt", "9.3p2")),
		fixture(t, "CVE-2023-51385", "Analyzed", "OS command injection.", 6.5, "NETWORK", "NONE", "NONE", openssh("*", "lt", "9.6")),
		fixture(t, "CVE-2021-41617", "Analyzed", "Supplemental groups.", 7.0, "LOCAL", "LOW", "NONE", openssh("*", "gte", "6.2", "lte", "8.7")),
		fixture(t, "CVE-2020-15778", "Analyzed", "scp backtick.", 7.8, "NETWORK", "NONE", "REQUIRED", openssh("*", "lte", "8.3p1")),
		fixture(t, "CVE-2018-15473", "Modified", "Username enumeration.", 7.5, "NETWORK", "NONE", "NONE", openssh("*", "lt", "7.8")),
		fixture(t, "CVE-2016-0777", "Modified", "Roaming leak.", 7.5, "NETWORK", "NONE", "NONE", openssh("7.1", ""), openssh("7.0", "")),
		fixture(t, "CVE-1999-0001", "Rejected", "** REJECT ** not a bug", 10, "NETWORK", "NONE", "NONE", openssh("*", "lt", "99")),
		fixture(t, "CVE-2000-0001", "Analyzed", "Unbounded wildcard.", 10, "NETWORK", "NONE", "NONE", openssh("*")),
		fixture(t, "CVE-2000-0002", "Analyzed", "No version at all.", 10, "NETWORK", "NONE", "NONE", openssh("-")),
	}}
	kev := map[string]KEVEntry{"CVE-2024-6387": {CVEID: "CVE-2024-6387", DateAdded: "2024-07-02", ShortDescription: "regreSSHion"}}

	feed, st := Build(now, cves, kev)
	if st.Considered != 10 || st.KEV != 1 || st.Critical != 1 || st.High != 2 || st.Rejected != 1 || st.NoRange != 2 {
		t.Fatalf("stats = %+v", st)
	}
	if !feed.GeneratedAt.Equal(now) || feed.Schema != 1 || !strings.Contains(feed.Source, "10 CVEs considered") {
		t.Fatalf("feed envelope = %+v", feed)
	}
	ids := []string{}
	for _, s := range feed.Signatures {
		ids = append(ids, s.ID)
	}
	if strings.Join(ids, ",") != "kev-cve-2024-6387,nvd-critical-openssh,nvd-high-openssh" {
		t.Fatalf("signatures = %v", ids)
	}

	kevSig := feed.Signatures[0]
	if kevSig.Severity != vulnscan.SeverityCritical || kevSig.CVEs[0] != "CVE-2024-6387" || kevSig.Match.Product != "openssh" {
		t.Fatalf("kev signature = %+v", kevSig)
	}
	if !strings.Contains(kevSig.Description, "signal handler race") || !strings.Contains(kevSig.Description, "2024-07-02") || !strings.Contains(kevSig.Name, "actively exploited") {
		t.Fatalf("kev description/name = %q / %q", kevSig.Description, kevSig.Name)
	}
	if len(kevSig.Match.Versions) != 1 || kevSig.Match.Versions[0] != (vulnscan.VersionRange{GTE: "8.5", LT: "9.8"}) {
		t.Fatalf("kev ranges = %+v", kevSig.Match.Versions)
	}

	crit := feed.Signatures[1]
	if crit.Severity != vulnscan.SeverityCritical || len(crit.Match.Versions) != 1 || crit.Match.Versions[0] != (vulnscan.VersionRange{LT: "9.3p2", CVE: "CVE-2023-38408"}) {
		t.Fatalf("critical aggregate = %+v", crit)
	}
	if !strings.Contains(crit.Description, "1 CVEs") || !strings.Contains(crit.Description, "backports") {
		t.Fatalf("critical description = %q", crit.Description)
	}

	high := feed.Signatures[2]
	// CVE-2016-0777 has two exact versions, CVE-2018-15473 one bound: three
	// ranges, each tagged, sorted by CVE.
	want := []vulnscan.VersionRange{{EQ: "7.0", CVE: "CVE-2016-0777"}, {EQ: "7.1", CVE: "CVE-2016-0777"}, {LT: "7.8", CVE: "CVE-2018-15473"}}
	if len(high.Match.Versions) != len(want) {
		t.Fatalf("high ranges = %+v", high.Match.Versions)
	}
	for i := range want {
		if high.Match.Versions[i] != want[i] {
			t.Fatalf("high range %d = %+v, want %+v", i, high.Match.Versions[i], want[i])
		}
	}
	if len(high.CVEs) != 0 {
		t.Fatal("aggregates carry CVEs per range, not on the signature (the list would be enormous for PHP)")
	}

	// And the whole thing round-trips through the consumer and matches.
	b, _ := json.Marshal(feed)
	parsed, err := vulnscan.ParseFeed(b)
	if err != nil {
		t.Fatal(err)
	}
	sigs, skipped := parsed.Compile()
	if len(skipped) != 0 || len(sigs) != 3 {
		t.Fatalf("compiled %d, skipped %v", len(sigs), skipped)
	}
	m := vulnscan.EvaluateWith(vulnscan.Probe{Connected: true, Port: 22, Banner: "SSH-2.0-OpenSSH_9.6p1"}, sigs)
	got := map[string]string{}
	for _, x := range m {
		got[x.Signature.ID] = x.Evidence
	}
	if _, ok := got["kev-cve-2024-6387"]; !ok {
		t.Fatalf("9.6p1 should hit regreSSHion: %+v", got)
	}
	if _, ok := got["nvd-critical-openssh"]; ok {
		t.Fatalf("9.6p1 is past 9.3p2: %+v", got)
	}
	m = vulnscan.EvaluateWith(vulnscan.Probe{Connected: true, Port: 22, Banner: "SSH-2.0-OpenSSH_7.1"}, sigs)
	for _, x := range m {
		if x.Signature.ID == "nvd-high-openssh" && !strings.Contains(x.Evidence, "CVE-2016-0777, CVE-2018-15473 (2 CVEs)") {
			t.Fatalf("7.1 evidence = %q", x.Evidence)
		}
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	now := time.Now()
	cves := map[string][]CVE{"nginx": {
		fixture(t, "CVE-2021-23017", "Analyzed", "Resolver off-by-one.", 7.7, "NETWORK", "NONE", "NONE",
			CPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", VersionStartIncluding: "0.6.18", VersionEndExcluding: "1.20.1"},
			CPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:f5:nginx:1.21.0:*:*:*:*:*:*:*"},
			CPEMatch{Vulnerable: false, Criteria: "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
		),
	}}
	a, _ := Build(now, cves, nil)
	b, _ := Build(now, cves, nil)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatal("two builds of the same input differ")
	}
	if len(a.Signatures) != 1 || len(a.Signatures[0].Match.Versions) != 2 {
		t.Fatalf("signatures = %+v", a.Signatures)
	}
}

func TestBuildPrefersPrimaryV31ThenV30Metrics(t *testing.T) {
	c := fixture(t, "CVE-2020-1", "Analyzed", "x", 9.8, "NETWORK", "NONE", "NONE", openssh("*", "lt", "1"))
	// Add a secondary 3.1 metric first in the list; Primary must still win.
	var secondary cvssMetric
	secondary.Type = "Secondary"
	secondary.CVSSData.BaseScore = 2
	c.Metrics.V31 = append([]cvssMetric{secondary}, c.Metrics.V31...)
	if score, _, _, _ := cvss(c); score != 9.8 {
		t.Fatalf("score = %v", score)
	}
	c.Metrics.V31 = nil
	var v30 cvssMetric
	v30.CVSSData.BaseScore = 5
	c.Metrics.V30 = []cvssMetric{v30}
	if score, _, _, _ := cvss(c); score != 5 {
		t.Fatalf("v30 fallback score = %v", score)
	}
	c.Metrics.V30 = nil
	if score, av, _, _ := cvss(c); score != 0 || av != "" {
		t.Fatal("no metrics should score zero")
	}
}

func TestRangeOfHandlesCPEVersionForms(t *testing.T) {
	cases := []struct {
		m    CPEMatch
		want vulnscan.VersionRange
		ok   bool
	}{
		{CPEMatch{Criteria: "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"}, vulnscan.VersionRange{EQ: "1.1.1k"}, true},
		{CPEMatch{Criteria: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", VersionStartExcluding: "1.0", VersionEndIncluding: "1.1.1w"}, vulnscan.VersionRange{GT: "1.0", LTE: "1.1.1w"}, true},
		{CPEMatch{Criteria: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"}, vulnscan.VersionRange{}, false},
		{CPEMatch{Criteria: "cpe:2.3:a:openssl:openssl:-:*:*:*:*:*:*:*"}, vulnscan.VersionRange{}, false},
		{CPEMatch{Criteria: "cpe:2.3:a:openssl:openssl:beta:*:*:*:*:*:*:*"}, vulnscan.VersionRange{}, false},
		{CPEMatch{Criteria: "garbage"}, vulnscan.VersionRange{}, false},
		{CPEMatch{Criteria: `cpe:2.3:a:php:php:7\.4\.3:*:*:*:*:*:*:*`}, vulnscan.VersionRange{EQ: "7.4.3"}, true},
	}
	for _, c := range cases {
		got, ok := rangeOf(c.m)
		if ok != c.ok || got != c.want {
			t.Errorf("rangeOf(%+v) = %+v, %v; want %+v, %v", c.m, got, ok, c.want, c.ok)
		}
	}
}

func TestProductsAreAllFingerprintable(t *testing.T) {
	known := map[string]bool{}
	for _, p := range vulnscan.KnownProducts() {
		known[p] = true
	}
	seen := map[string]bool{}
	for _, p := range Products {
		if !known[p.Name] {
			t.Errorf("product %q is in the feed table but internal/vulnscan cannot fingerprint it", p.Name)
		}
		if seen[p.Name] {
			t.Errorf("product %q listed twice", p.Name)
		}
		seen[p.Name] = true
		if p.Label == "" || len(p.CPEs) == 0 {
			t.Errorf("product %q needs a label and at least one CPE", p.Name)
		}
		for _, cpe := range p.CPEs {
			if !strings.HasPrefix(cpe, "cpe:2.3:a:") || strings.HasSuffix(cpe, ":") || strings.Count(cpe, ":") != 4 {
				t.Errorf("product %q: CPE %q is not a cpe:2.3:a:vendor:product prefix", p.Name, cpe)
			}
		}
	}
	for name := range known {
		if !seen[name] {
			t.Errorf("internal/vulnscan can fingerprint %q but the feed never builds signatures for it", name)
		}
	}
}

func TestDescriptionFallsBackAndKEVSignatureTruncates(t *testing.T) {
	var c CVE
	if description(c) != "" {
		t.Fatal("no descriptions should read as empty")
	}
	c = fixture(t, "CVE-2020-2", "Analyzed", "", 9, "NETWORK", "NONE", "NONE", openssh("*", "lt", "1"))
	c.Descriptions = c.Descriptions[:1] // only the Spanish one is left
	if description(c) != "otro" {
		t.Fatalf("description = %q, want the first available language", description(c))
	}
	p := Products[0]
	// Empty NVD text: CISA's short description stands in.
	c.Descriptions = nil
	sig := kevSignature(p, c, KEVEntry{DateAdded: "2024-01-02", ShortDescription: "CISA says so"}, []vulnscan.VersionRange{{LT: "1"}})
	if !strings.HasPrefix(sig.Description, "CISA says so") || !strings.Contains(sig.Description, "2024-01-02") {
		t.Fatalf("description = %q", sig.Description)
	}
	// A very long NVD text is cut, with an ellipsis, before the CISA sentence.
	long := fixture(t, "CVE-2020-3", "Analyzed", strings.Repeat("word ", 300), 9, "NETWORK", "NONE", "NONE", openssh("*", "lt", "1"))
	sig = kevSignature(p, long, KEVEntry{DateAdded: "2024-01-02"}, []vulnscan.VersionRange{{LT: "1"}})
	if !strings.Contains(sig.Description, "… CISA added") || len(sig.Description) > maxDescription+200 {
		t.Fatalf("long description not truncated: %d chars", len(sig.Description))
	}
	if matchesProduct("cpe:2.3:a:other:thing:1:*:*:*:*:*:*:*", p) {
		t.Fatal("another vendor's CPE must not match")
	}
	if cleanVersion("  ") != "" || cleanVersion("v1.2") != "" {
		t.Fatal("blank or non-numeric versions clean to empty")
	}
}

func TestBuildCountsKEVWithoutRangesAndRejectDescriptions(t *testing.T) {
	cves := map[string][]CVE{"openssh": {
		fixture(t, "CVE-2020-9", "Analyzed", "** REJECT ** withdrawn", 9.8, "NETWORK", "NONE", "NONE", openssh("*", "lt", "1")),
		fixture(t, "CVE-2020-8", "Analyzed", "in KEV but unbounded", 5, "LOCAL", "LOW", "NONE", openssh("*")),
	}}
	_, st := Build(time.Now(), cves, map[string]KEVEntry{"CVE-2020-8": {CVEID: "CVE-2020-8"}})
	if st.Rejected != 1 || st.NoRange != 1 || st.KEV != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if cleanVersion("1..2") != "" {
		t.Fatal("a version the consumer cannot parse must be dropped")
	}
}
