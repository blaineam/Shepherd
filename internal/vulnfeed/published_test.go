// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"os"
	"strings"
	"testing"

	"shepherd/internal/vulnscan"
)

// The feed actually checked into the repository (what every Shepherd
// fetches) must parse, compile without skipping anything, and recognize a
// few well-known vulnerable versions. Only positive assertions about CVEs
// that will never leave the NVD, so a daily rebuild cannot break this.
func TestPublishedFeedParsesAndRecognizesKnownVulnerableVersions(t *testing.T) {
	b, err := os.ReadFile("../../feeds/vulnscan.json")
	if err != nil {
		t.Fatal(err)
	}
	feed, err := vulnscan.ParseFeed(b)
	if err != nil {
		t.Fatal(err)
	}
	if feed.GeneratedAt.IsZero() || len(feed.Signatures) < 20 {
		t.Fatalf("feed looks empty: %d signatures, built %v", len(feed.Signatures), feed.GeneratedAt)
	}
	sigs, skipped := feed.Compile()
	if len(skipped) != 0 {
		t.Fatalf("the published feed names products this build cannot fingerprint: %v", skipped)
	}

	evidence := func(port int, banner, server string) map[string]string {
		out := map[string]string{}
		for _, m := range vulnscan.EvaluateWith(vulnscan.Probe{Connected: true, Port: port, Banner: banner, HTTPServer: server}, sigs) {
			out[m.Signature.ID] = m.Evidence
		}
		return out
	}
	// regreSSHion (CVE-2024-6387, CVSS 8.1): OpenSSH 8.5 up to 9.8.
	if ev := evidence(22, "SSH-2.0-OpenSSH_9.6p1", ""); !strings.Contains(ev["nvd-high-openssh"], "CVE-2024-6387") {
		t.Errorf("OpenSSH 9.6p1 should be in the high tier via CVE-2024-6387: %v", ev)
	}
	// The 2021 Apache path traversal (CVE-2021-41773, in KEV) on exactly 2.4.49.
	if ev := evidence(80, "", "Apache/2.4.49 (Unix)"); ev["kev-cve-2021-41773"] == "" {
		t.Errorf("Apache 2.4.49 should hit the KEV signature for CVE-2021-41773: %v", ev)
	}
	// Heartbleed (CVE-2014-0160, in KEV) on OpenSSL 1.0.1f, read out of the
	// second token of a Server header; the Apache token in front of it is
	// fingerprinted independently.
	if ev := evidence(80, "", "Apache/2.2.22 (Ubuntu) OpenSSL/1.0.1f"); ev["kev-cve-2014-0160"] == "" || ev["nvd-high-apache"] == "" {
		t.Errorf("OpenSSL 1.0.1f should be recognized as Heartbleed-vulnerable and Apache 2.2.22 as outdated: %v", ev)
	}
	// Every signature has the fields the portal shows.
	for _, s := range sigs {
		if s.Name == "" || s.Description == "" || s.Source != vulnscan.SourceFeed {
			t.Errorf("signature %q is incomplete", s.ID)
		}
	}
}
