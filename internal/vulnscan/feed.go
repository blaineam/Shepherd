// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// FeedSchema is the only feed schema version this build understands. A
// feed with a different number is rejected outright rather than
// half-applied.
const FeedSchema = 1

// Signature sources, for the portal: a built-in one is reviewed code in
// this repository; a feed one arrived as data (docs/VULNSCAN.md's
// "Signature feed" section).
const (
	SourceBuiltin = "builtin"
	SourceFeed    = "feed"
)

// Feed is the on-the-wire shape of a signature feed: a plain JSON document
// of declarative signatures. Nothing in a feed is code — a signature can
// only ever say "this product, in these version ranges" or "this text in
// a banner" — so a feed cannot make Shepherd probe anything new or run
// anything; it can only name more things to recognize in data the probes
// in probe.go already collect. cmd/vulnfeed builds the published one from
// the NVD and CISA's Known Exploited Vulnerabilities catalog; a FeedUpdater
// (feedsource.go) keeps a running Shepherd supplied with it.
type Feed struct {
	Schema      int             `json:"schema"`
	GeneratedAt time.Time       `json:"generated_at"`
	Source      string          `json:"source,omitempty"`
	Signatures  []FeedSignature `json:"signatures"`
}

// FeedSignature is one declarative signature. ID, Name, Severity,
// Description and Ports mean exactly what they do on Signature; Match says
// what to look for.
type FeedSignature struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Severity    Severity  `json:"severity"`
	Description string    `json:"description"`
	CVEs        []string  `json:"cves,omitempty"`
	Ports       []int     `json:"ports,omitempty"`
	Match       FeedMatch `json:"match"`
}

// FeedMatch is the declarative matcher. Exactly one of Product or Contains
// is set:
//
//   - Product names a fingerprintable product (KnownProducts) and Versions
//     lists the affected version ranges; the signature fires when the probe
//     reveals that product at a version inside any range. An empty Versions
//     list means any version of the product.
//   - Contains is a case-insensitive substring looked for in the banner or
//     the HTTP Server header (the vsftpd-2.3.4 style of match).
type FeedMatch struct {
	Product  string         `json:"product,omitempty"`
	Versions []VersionRange `json:"versions,omitempty"`
	Contains string         `json:"contains,omitempty"`
}

// VersionRange bounds a set of dotted versions. Every set bound must hold.
// CVE optionally names the CVE this particular range came from, so an
// aggregated signature (one per product and severity tier) can still
// report exactly which CVEs a device's version falls into.
type VersionRange struct {
	GTE string `json:"gte,omitempty"`
	GT  string `json:"gt,omitempty"`
	LTE string `json:"lte,omitempty"`
	LT  string `json:"lt,omitempty"`
	EQ  string `json:"eq,omitempty"`
	CVE string `json:"cve,omitempty"`
}

// maxFeedBytes caps a feed document; the published one is a few hundred
// kilobytes at most.
const maxFeedBytes = 8 << 20

// ParseFeed decodes and validates a feed document. It is strict about the
// envelope (schema, unique non-empty IDs, a valid severity, a matcher that
// says something) and lenient about products: a signature for a product
// this build cannot fingerprint is not an error, it is simply skipped by
// Compile, so a newer feed never breaks an older Shepherd.
func ParseFeed(b []byte) (*Feed, error) {
	if len(b) > maxFeedBytes {
		return nil, fmt.Errorf("feed is larger than the %d MiB cap", maxFeedBytes>>20)
	}
	var f Feed
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("feed is not valid JSON: %w", err)
	}
	if f.Schema != FeedSchema {
		return nil, fmt.Errorf("feed schema %d is not the supported schema %d", f.Schema, FeedSchema)
	}
	seen := map[string]bool{}
	for i, sig := range f.Signatures {
		if sig.ID == "" {
			return nil, fmt.Errorf("signature %d has no id", i)
		}
		if seen[sig.ID] {
			return nil, fmt.Errorf("signature id %q appears twice", sig.ID)
		}
		seen[sig.ID] = true
		if sig.Name == "" || sig.Description == "" {
			return nil, fmt.Errorf("signature %q needs a name and a description", sig.ID)
		}
		if !sig.Severity.valid() {
			return nil, fmt.Errorf("signature %q has unknown severity %q", sig.ID, sig.Severity)
		}
		if err := sig.Match.validate(); err != nil {
			return nil, fmt.Errorf("signature %q: %w", sig.ID, err)
		}
	}
	return &f, nil
}

func (m FeedMatch) validate() error {
	switch {
	case m.Product != "" && m.Contains != "":
		return errors.New("match sets both product and contains")
	case m.Product == "" && m.Contains == "":
		return errors.New("match sets neither product nor contains")
	case m.Contains != "" && len(m.Versions) > 0:
		return errors.New("a contains match cannot have version ranges")
	}
	for _, r := range m.Versions {
		for _, v := range []string{r.GTE, r.GT, r.LTE, r.LT, r.EQ} {
			if v == "" {
				continue
			}
			if _, ok := parseVersion(v); !ok {
				return fmt.Errorf("version %q is not a dotted numeric version", v)
			}
		}
	}
	return nil
}

// Compile turns the feed into runnable Signatures. Signatures naming a
// product this build cannot fingerprint are returned in skipped (by ID)
// rather than compiled, see ParseFeed.
func (f *Feed) Compile() (sigs []Signature, skipped []string) {
	for _, fs := range f.Signatures {
		if fs.Match.Product != "" && !knownProduct(fs.Match.Product) {
			skipped = append(skipped, fs.ID)
			continue
		}
		sigs = append(sigs, fs.compile())
	}
	return sigs, skipped
}

func (fs FeedSignature) compile() Signature {
	m := fs.Match
	sig := Signature{
		ID: fs.ID, Name: fs.Name, Severity: fs.Severity, Description: fs.Description,
		Ports: append([]int(nil), fs.Ports...), CVEs: append([]string(nil), fs.CVEs...), Source: SourceFeed,
	}
	if m.Contains != "" {
		needle := strings.ToLower(m.Contains)
		sig.Match = func(p Probe) (string, bool) {
			for _, hay := range []string{p.Banner, p.HTTPServer} {
				if hay != "" && strings.Contains(strings.ToLower(hay), needle) {
					return hay, true
				}
			}
			return "", false
		}
		return sig
	}
	ranges := make([]compiledRange, 0, len(m.Versions))
	for _, r := range m.Versions {
		ranges = append(ranges, r.compile())
	}
	sig.Match = func(p Probe) (string, bool) {
		for _, pv := range fingerprint(p) {
			if pv.product != m.Product {
				continue
			}
			v, ok := parseVersion(pv.version)
			if !ok {
				continue
			}
			if len(ranges) == 0 {
				return pv.evidence, true
			}
			var cves []string
			hit := false
			for _, r := range ranges {
				if !r.contains(v) {
					continue
				}
				hit = true
				if r.cve != "" {
					cves = append(cves, r.cve)
				}
			}
			if !hit {
				continue
			}
			return evidenceWithCVEs(pv.evidence, cves), true
		}
		return "", false
	}
	return sig
}

// evidenceWithCVEs appends the matched CVE IDs (deduplicated, sorted, and
// capped so a very old build does not produce a paragraph) to the raw
// evidence string.
func evidenceWithCVEs(evidence string, cves []string) string {
	if len(cves) == 0 {
		return evidence
	}
	uniq := map[string]bool{}
	var ids []string
	for _, c := range cves {
		if !uniq[c] {
			uniq[c] = true
			ids = append(ids, c)
		}
	}
	sort.Strings(ids)
	const show = 8
	n := len(ids)
	if n > show {
		return fmt.Sprintf("%s — %s and %d more (%d CVEs)", evidence, strings.Join(ids[:show], ", "), n-show, n)
	}
	if n == 1 {
		return evidence + " — " + ids[0]
	}
	return fmt.Sprintf("%s — %s (%d CVEs)", evidence, strings.Join(ids, ", "), n)
}

type compiledRange struct {
	gte, gt, lte, lt, eq                parsedVersion
	hasGTE, hasGT, hasLTE, hasLT, hasEQ bool
	cve                                 string
}

func (r VersionRange) compile() compiledRange {
	var c compiledRange
	c.cve = r.CVE
	c.gte, c.hasGTE = parseVersion(r.GTE)
	c.gt, c.hasGT = parseVersion(r.GT)
	c.lte, c.hasLTE = parseVersion(r.LTE)
	c.lt, c.hasLT = parseVersion(r.LT)
	c.eq, c.hasEQ = parseVersion(r.EQ)
	return c
}

func (c compiledRange) contains(v parsedVersion) bool {
	if c.hasEQ && !v.equal(c.eq) {
		return false
	}
	if c.hasGTE && v.less(c.gte) {
		return false
	}
	if c.hasGT && !c.gt.less(v) {
		return false
	}
	if c.hasLTE && c.lte.less(v) {
		return false
	}
	if c.hasLT && !v.less(c.lt) {
		return false
	}
	return true
}

// productVersion is one "product X at version Y" fact a Probe reveals,
// with the raw text it was read from as evidence.
type productVersion struct {
	product, version, evidence string
}

// bannerProducts are the products whose version a plaintext greeting
// (SSH, FTP, SMTP) states outright. The capture group is the version.
var bannerProducts = []struct {
	product string
	re      *regexp.Regexp
}{
	{"openssh", regexp.MustCompile(`(?i)OpenSSH[_-]([0-9]+(?:\.[0-9]+)*(?:p[0-9]+)?)`)},
	{"dropbear", regexp.MustCompile(`(?i)dropbear[_-]([0-9]+(?:\.[0-9]+)*)`)},
	{"vsftpd", regexp.MustCompile(`(?i)vsFTPd ([0-9]+(?:\.[0-9]+)*)`)},
	{"proftpd", regexp.MustCompile(`(?i)ProFTPD ([0-9]+(?:\.[0-9]+)*[a-z]?)`)},
	{"exim", regexp.MustCompile(`(?i)\bExim ([0-9]+(?:\.[0-9]+)*)`)},
}

// serverTokenRE matches every "Product/version" token in an HTTP Server
// header ("Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/7.4.3" has three).
var serverTokenRE = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_.-]*)/([0-9]+(?:\.[0-9]+)*[A-Za-z0-9]*)`)

// serverProducts maps a lower-cased Server-header token to the product
// name feeds use. Tokens not listed here (mod_ssl, Python, Phusion, ...)
// are ignored: a feed can only target what this table names.
var serverProducts = map[string]string{
	"apache":        "apache",
	"nginx":         "nginx",
	"lighttpd":      "lighttpd",
	"openssl":       "openssl",
	"php":           "php",
	"boa":           "boa",
	"mini_httpd":    "mini_httpd",
	"goahead-webs":  "goahead",
	"goahead":       "goahead",
	"microsoft-iis": "microsoft-iis",
}

// KnownProducts lists every product name a feed signature may use in
// Match.Product, sorted. cmd/vulnfeed's own product table is tested
// against it so the published feed never names something this build
// silently skips.
func KnownProducts() []string {
	seen := map[string]bool{}
	var out []string
	for _, bp := range bannerProducts {
		if !seen[bp.product] {
			seen[bp.product] = true
			out = append(out, bp.product)
		}
	}
	for _, p := range serverProducts {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func knownProduct(name string) bool {
	for _, p := range KnownProducts() {
		if p == name {
			return true
		}
	}
	return false
}

// fingerprint lists every product and version one port's Probe reveals:
// the banner's own product token, and every recognized token of an HTTP
// Server header.
func fingerprint(p Probe) []productVersion {
	var out []productVersion
	if p.Banner != "" {
		for _, bp := range bannerProducts {
			if m := bp.re.FindStringSubmatch(p.Banner); m != nil {
				out = append(out, productVersion{bp.product, m[1], p.Banner})
			}
		}
	}
	if p.HTTPServer != "" {
		for _, m := range serverTokenRE.FindAllStringSubmatch(p.HTTPServer, -1) {
			if product, ok := serverProducts[strings.ToLower(m[1])]; ok {
				out = append(out, productVersion{product, m[2], p.HTTPServer})
			}
		}
	}
	return out
}
