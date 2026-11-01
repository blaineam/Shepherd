// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import (
	"strings"
	"testing"
	"time"
)

const sampleFeed = `{
  "schema": 1,
  "generated_at": "2026-11-01T06:00:00Z",
  "source": "test",
  "signatures": [
    {
      "id": "kev-cve-2024-6387", "name": "OpenSSH regreSSHion", "severity": "critical",
      "description": "Signal handler race in sshd.", "cves": ["CVE-2024-6387"], "ports": [22],
      "match": {"product": "openssh", "versions": [{"gte": "8.5", "lt": "9.8"}]}
    },
    {
      "id": "nvd-high-openssl", "name": "OpenSSL with known high-severity CVEs", "severity": "high",
      "description": "Falls inside an affected range.",
      "match": {"product": "openssl", "versions": [
        {"lt": "1.1.1l", "cve": "CVE-2021-3711"},
        {"gte": "3.0.0", "lt": "3.0.7", "cve": "CVE-2022-3602"},
        {"lt": "1.1.1t", "cve": "CVE-2023-0286"}
      ]}
    },
    {
      "id": "backdoor-text", "name": "Tampered build", "severity": "critical",
      "description": "Known backdoored banner.",
      "match": {"contains": "ProFTPD 1.3.3c"}
    },
    {
      "id": "future-product", "name": "Something newer", "severity": "low",
      "description": "A product this build cannot fingerprint.",
      "match": {"product": "quantumd", "versions": [{"lt": "2"}]}
    },
    {
      "id": "telnet-exposed", "name": "Telnet exposed (feed)", "severity": "critical",
      "description": "Overrides the built-in's severity.", "ports": [23],
      "match": {"contains": ""}
    }
  ]
}`

// The last signature above has an empty matcher on purpose for the
// override test; fix it up before parsing in the tests that want a valid
// feed.
func validSampleFeed() string {
	return strings.Replace(sampleFeed, `"match": {"contains": ""}`, `"match": {"contains": "login:"}`, 1)
}

func TestParseFeedAcceptsAValidFeed(t *testing.T) {
	f, err := ParseFeed([]byte(validSampleFeed()))
	if err != nil {
		t.Fatal(err)
	}
	if f.Schema != 1 || len(f.Signatures) != 5 || !f.GeneratedAt.Equal(time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("feed = %+v", f)
	}
}

func TestParseFeedRejectsBadEnvelopes(t *testing.T) {
	cases := map[string]string{
		"not json":         `{`,
		"wrong schema":     `{"schema": 2, "signatures": []}`,
		"missing id":       `{"schema": 1, "signatures": [{"name": "x", "severity": "low", "description": "d", "match": {"contains": "a"}}]}`,
		"duplicate id":     `{"schema": 1, "signatures": [{"id": "a", "name": "x", "severity": "low", "description": "d", "match": {"contains": "a"}}, {"id": "a", "name": "y", "severity": "low", "description": "d", "match": {"contains": "b"}}]}`,
		"bad severity":     `{"schema": 1, "signatures": [{"id": "a", "name": "x", "severity": "scary", "description": "d", "match": {"contains": "a"}}]}`,
		"no description":   `{"schema": 1, "signatures": [{"id": "a", "name": "x", "severity": "low", "match": {"contains": "a"}}]}`,
		"empty matcher":    sampleFeed,
		"both matchers":    `{"schema": 1, "signatures": [{"id": "a", "name": "x", "severity": "low", "description": "d", "match": {"contains": "a", "product": "nginx"}}]}`,
		"contains+version": `{"schema": 1, "signatures": [{"id": "a", "name": "x", "severity": "low", "description": "d", "match": {"contains": "a", "versions": [{"lt": "1"}]}}]}`,
		"bad version":      `{"schema": 1, "signatures": [{"id": "a", "name": "x", "severity": "low", "description": "d", "match": {"product": "nginx", "versions": [{"lt": "one"}]}}]}`,
	}
	for name, doc := range cases {
		if _, err := ParseFeed([]byte(doc)); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
	if _, err := ParseFeed(make([]byte, maxFeedBytes+1)); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Errorf("oversized feed: %v", err)
	}
}

func TestCompileSkipsUnknownProductsAndMarksSource(t *testing.T) {
	f, err := ParseFeed([]byte(validSampleFeed()))
	if err != nil {
		t.Fatal(err)
	}
	sigs, skipped := f.Compile()
	if len(skipped) != 1 || skipped[0] != "future-product" {
		t.Fatalf("skipped = %v", skipped)
	}
	if len(sigs) != 4 {
		t.Fatalf("compiled %d signatures, want 4", len(sigs))
	}
	for _, s := range sigs {
		if s.Source != SourceFeed || s.Match == nil {
			t.Errorf("%s: source %q, match nil=%v", s.ID, s.Source, s.Match == nil)
		}
	}
	if sigs[0].CVEs[0] != "CVE-2024-6387" || sigs[0].Ports[0] != 22 {
		t.Errorf("first signature lost its CVEs or ports: %+v", sigs[0])
	}
}

func compiled(t *testing.T) []Signature {
	t.Helper()
	f, err := ParseFeed([]byte(validSampleFeed()))
	if err != nil {
		t.Fatal(err)
	}
	sigs, _ := f.Compile()
	return sigs
}

func TestFeedProductVersionRanges(t *testing.T) {
	sigs := compiled(t)
	in := func(banner string) []Match {
		return EvaluateWith(Probe{Connected: true, Port: 22, Banner: banner}, sigs)
	}
	m := hasFinding(t, in("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"), "kev-cve-2024-6387")
	if m.Evidence != "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13" {
		t.Errorf("evidence = %q", m.Evidence)
	}
	hasFinding(t, in("SSH-2.0-OpenSSH_8.5"), "kev-cve-2024-6387") // gte is inclusive
	mustNotMatch(t, in("SSH-2.0-OpenSSH_9.8p1"), "kev-cve-2024-6387")
	mustNotMatch(t, in("SSH-2.0-OpenSSH_8.4"), "kev-cve-2024-6387")
	mustNotMatch(t, in("SSH-2.0-dropbear_2020.81"), "kev-cve-2024-6387")
}

func TestFeedAggregatedSignatureReportsMatchedCVEs(t *testing.T) {
	sigs := compiled(t)
	p := Probe{Connected: true, Port: 80, HTTPServer: "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3"}
	m := hasFinding(t, EvaluateWith(p, sigs), "nvd-high-openssl")
	// 1.1.1f is below both 1.1.1l and 1.1.1t but not in the 3.0 range.
	if !strings.Contains(m.Evidence, "CVE-2021-3711") || !strings.Contains(m.Evidence, "CVE-2023-0286") || strings.Contains(m.Evidence, "CVE-2022-3602") {
		t.Fatalf("evidence = %q", m.Evidence)
	}
	if !strings.HasSuffix(m.Evidence, "(2 CVEs)") {
		t.Errorf("evidence should count the CVEs: %q", m.Evidence)
	}
	p.HTTPServer = "nginx/1.25.3 OpenSSL/3.0.2"
	m = hasFinding(t, EvaluateWith(p, sigs), "nvd-high-openssl")
	if !strings.HasSuffix(m.Evidence, "— CVE-2022-3602") {
		t.Errorf("single CVE evidence = %q", m.Evidence)
	}
	p.HTTPServer = "nginx/1.25.3 OpenSSL/3.2.1"
	mustNotMatch(t, EvaluateWith(p, sigs), "nvd-high-openssl")
}

func TestFeedContainsMatcherLooksAtBannerAndServerHeader(t *testing.T) {
	sigs := compiled(t)
	hasFinding(t, EvaluateWith(Probe{Connected: true, Port: 21, Banner: "220 ProFTPD 1.3.3c Server ready"}, sigs), "backdoor-text")
	hasFinding(t, EvaluateWith(Probe{Connected: true, Port: 80, HTTPServer: "proftpd 1.3.3C"}, sigs), "backdoor-text")
	mustNotMatch(t, EvaluateWith(Probe{Connected: true, Port: 21, Banner: "220 ProFTPD 1.3.8 Server ready"}, sigs), "backdoor-text")
}

func TestFeedSignatureNeverFiresOnAProbeThatNeverConnected(t *testing.T) {
	sigs := compiled(t)
	if m := EvaluateWith(Probe{Port: 22, Banner: "SSH-2.0-OpenSSH_9.6"}, sigs); len(m) != 0 {
		t.Fatalf("matches on an unconnected probe: %+v", m)
	}
}

func TestEvidenceWithCVEsCapsALongList(t *testing.T) {
	var ids []string
	for i := 0; i < 12; i++ {
		ids = append(ids, "CVE-2020-"+strings.Repeat("0", 2)+string(rune('a'+i)))
	}
	ids = append(ids, ids[0]) // a duplicate collapses
	got := evidenceWithCVEs("x", ids)
	if !strings.Contains(got, "and 4 more (12 CVEs)") {
		t.Fatalf("got %q", got)
	}
	if evidenceWithCVEs("raw", nil) != "raw" {
		t.Fatal("no CVEs should leave the evidence alone")
	}
}

func TestVersionRangeBounds(t *testing.T) {
	v := func(s string) parsedVersion { p, _ := parseVersion(s); return p }
	cases := []struct {
		r    VersionRange
		in   []string
		out  []string
		name string
	}{
		{VersionRange{EQ: "2.4.49"}, []string{"2.4.49"}, []string{"2.4.48", "2.4.50"}, "eq"},
		{VersionRange{GT: "1.0", LTE: "1.2"}, []string{"1.1", "1.2", "1.0.1"}, []string{"1.0", "1.2.1"}, "gt/lte"},
		{VersionRange{}, []string{"0", "99.9"}, nil, "unbounded"},
	}
	for _, c := range cases {
		cr := c.r.compile()
		for _, s := range c.in {
			if !cr.contains(v(s)) {
				t.Errorf("%s: %s should be inside %+v", c.name, s, c.r)
			}
		}
		for _, s := range c.out {
			if cr.contains(v(s)) {
				t.Errorf("%s: %s should be outside %+v", c.name, s, c.r)
			}
		}
	}
}

func TestFingerprintFindsEveryKnownProduct(t *testing.T) {
	got := map[string]string{}
	for _, pv := range fingerprint(Probe{Banner: "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"}) {
		got[pv.product] = pv.version
	}
	for _, pv := range fingerprint(Probe{Banner: "SSH-2.0-dropbear_2019.78"}) {
		got[pv.product] = pv.version
	}
	for _, pv := range fingerprint(Probe{Banner: "220 (vsFTPd 3.0.3)"}) {
		got[pv.product] = pv.version
	}
	for _, pv := range fingerprint(Probe{Banner: "220 ProFTPD 1.3.5e Server (Debian)"}) {
		got[pv.product] = pv.version
	}
	for _, pv := range fingerprint(Probe{Banner: "220 mail.example ESMTP Exim 4.92 Tue"}) {
		got[pv.product] = pv.version
	}
	for _, pv := range fingerprint(Probe{HTTPServer: "Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/7.4.3 mod_ssl/2.4.49"}) {
		got[pv.product] = pv.version
	}
	for _, pv := range fingerprint(Probe{HTTPServer: "nginx/1.18.0"}) {
		got[pv.product] = pv.version
	}
	for _, pv := range fingerprint(Probe{HTTPServer: "lighttpd/1.4.35"}) {
		got[pv.product] = pv.version
	}
	for _, pv := range fingerprint(Probe{HTTPServer: "Boa/0.94.14rc21"}) {
		got[pv.product] = pv.version
	}
	for _, pv := range fingerprint(Probe{HTTPServer: "mini_httpd/1.19 19dec2003"}) {
		got[pv.product] = pv.version
	}
	for _, pv := range fingerprint(Probe{HTTPServer: "GoAhead-Webs/2.5.0"}) {
		got[pv.product] = pv.version
	}
	for _, pv := range fingerprint(Probe{HTTPServer: "Microsoft-IIS/10.0"}) {
		got[pv.product] = pv.version
	}
	want := map[string]string{
		"openssh": "7.4p1", "dropbear": "2019.78", "vsftpd": "3.0.3", "proftpd": "1.3.5e", "exim": "4.92",
		"apache": "2.4.49", "openssl": "1.1.1k", "php": "7.4.3", "nginx": "1.18.0", "lighttpd": "1.4.35",
		"boa": "0.94.14rc21", "mini_httpd": "1.19", "goahead": "2.5.0", "microsoft-iis": "10.0",
	}
	for p, v := range want {
		if got[p] != v {
			t.Errorf("%s: got %q, want %q", p, got[p], v)
		}
	}
	if _, ok := got["mod_ssl"]; ok {
		t.Error("mod_ssl is not a product a feed may target")
	}
	for _, p := range KnownProducts() {
		if _, ok := want[p]; !ok {
			t.Errorf("KnownProducts lists %q, which this test does not cover", p)
		}
	}
	if len(KnownProducts()) != len(want) {
		t.Errorf("KnownProducts = %v", KnownProducts())
	}
}

func TestScannerSignaturesMergesFeedAndOverridesByID(t *testing.T) {
	s := New(Options{})
	builtin := len(s.Signatures())
	if builtin != len(BuiltinSignatures()) {
		t.Fatalf("with no feed, Signatures should be the built-ins: %d vs %d", builtin, len(BuiltinSignatures()))
	}
	s.SetFeedSignatures(compiled(t))
	all := s.Signatures()
	// 4 compiled, one of which overrides telnet-exposed in place.
	if len(all) != builtin+3 {
		t.Fatalf("len = %d, want %d", len(all), builtin+3)
	}
	for i, sig := range all {
		if sig.ID == "telnet-exposed" {
			if sig.Source != SourceFeed || sig.Severity != SeverityCritical || i != 0 {
				t.Fatalf("override not applied in place: idx %d, %+v", i, sig)
			}
		}
	}
	ids := []string{}
	for _, sig := range all[builtin:] {
		ids = append(ids, sig.ID)
	}
	if strings.Join(ids, ",") != "backdoor-text,kev-cve-2024-6387,nvd-high-openssl" {
		t.Fatalf("feed signatures should follow the built-ins sorted by ID: %v", ids)
	}
	s.SetFeedSignatures(nil)
	if len(s.Signatures()) != builtin {
		t.Fatal("nil should clear the feed")
	}
}

func TestScanUsesFeedSignatures(t *testing.T) {
	c := &scriptedConn{script: [][]byte{[]byte("SSH-2.0-OpenSSH_9.6p1\r\n")}}
	s := New(Options{Dial: dialScripted(c, nil)})
	s.SetFeedSignatures(compiled(t))
	out := s.Scan(t.Context(), []Target{{DeviceID: "d1", IP: "192.0.2.1", Ports: []int{22}}})
	if len(out) != 1 {
		t.Fatalf("out = %+v", out)
	}
	found := false
	for _, f := range out[0].Findings {
		if f.SignatureID == "kev-cve-2024-6387" && f.Active && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Fatalf("feed signature did not produce a finding: %+v", out[0].Findings)
	}
}
