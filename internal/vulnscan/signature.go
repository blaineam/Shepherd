// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import "strings"

// Probe is everything a Signature's Match function gets to look at: one
// open port on one device, and whatever Shepherd learned about it with a
// single gentle, protocol-appropriate exchange (see probe.go). All network
// I/O happens before Match is ever called, so Match itself is a pure
// function over already-collected data — what keeps BuiltinSignatures a
// plain, testable table instead of scattered logic.
type Probe struct {
	Port int

	// Connected is true once the TCP connect itself succeeded. Evaluate
	// never runs a signature against a probe that never connected: a
	// refused or unreachable port must never produce a finding just because
	// it was on the list of ports to check.
	Connected bool

	// Banner is the first printable bytes a plaintext protocol sent
	// unprompted after connecting (SSH, FTP, SMTP, POP3, IMAP, Telnet),
	// bounded in length and cleaned of control characters. Empty when the
	// port never sent one, the read timed out, or the port was probed a
	// different way (HTTP, Docker, SMB1).
	Banner string

	// HTTPServer is the "Server:" response header from a minimal plaintext
	// HTTP probe, when one was attempted and answered. Empty otherwise,
	// including on HTTPS ports: this package only speaks plain HTTP (see
	// docs/VULNSCAN.md's "Not detected" section).
	HTTPServer string
	HTTPStatus int

	// FTPAnonLogin is true when an FTP server accepted "USER anonymous"
	// followed by a password, ending in a 230 reply: anyone can log in.
	FTPAnonLogin bool

	// SMB1Negotiated is true when port 445 answered a raw SMBv1 Negotiate
	// Protocol Request with an SMBv1-framed reply (header 0xFF 'SMB'),
	// meaning the server still speaks the EternalBlue-era protocol version.
	SMB1Negotiated bool

	// DockerAPIOpen is true when a plain, unauthenticated GET /version on
	// port 2375 came back looking like Docker's own Engine API.
	DockerAPIOpen bool
}

// Signature is one curated, named vulnerability check. See docs/VULNSCAN.md
// for the full list and the reasoning (including named CVEs) behind each
// one. BuiltinSignatures is the only place new ones should be added.
type Signature struct {
	ID          string
	Name        string
	Severity    Severity
	Description string
	// Ports restricts which open ports this signature is even tried
	// against. Empty means "any port a probe ran against" (used by the
	// web-server-banner signatures, which key off Probe.HTTPServer rather
	// than one fixed port, since a home admin UI can live on any of
	// several).
	Ports []int
	// Match inspects one port's Probe and reports whether the signature
	// fired, plus the evidence to record alongside it (the banner, the
	// parsed version, or a short fixed explanation). Match does no I/O.
	Match func(Probe) (evidence string, matched bool)
}

func (sig Signature) appliesToPort(port int) bool {
	if len(sig.Ports) == 0 {
		return true
	}
	for _, p := range sig.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// Match pairs a fired Signature with the evidence Match returned.
type Match struct {
	Signature Signature
	Evidence  string
}

// Evaluate runs every built-in signature against one port's Probe and
// returns every one that fired. Scanner.Scan is the real caller; it is
// exported so the signature list can be unit-tested directly, with no
// network involved at all.
func Evaluate(p Probe) []Match {
	if !p.Connected {
		return nil
	}
	var out []Match
	for _, sig := range allSignatures {
		if !sig.appliesToPort(p.Port) {
			continue
		}
		if evidence, ok := sig.Match(p); ok {
			out = append(out, Match{Signature: sig, Evidence: evidence})
		}
	}
	return out
}

// allSignatures is computed once; BuiltinSignatures returns a copy so a
// caller can never mutate the package's own table.
var allSignatures = buildSignatures()

// BuiltinSignatures returns the full curated signature table.
func BuiltinSignatures() []Signature {
	return append([]Signature(nil), allSignatures...)
}

func buildSignatures() []Signature {
	return []Signature{
		{
			ID: "telnet-exposed", Name: "Telnet exposed", Severity: SeverityHigh, Ports: []int{23},
			Description: "Telnet accepts remote logins in plain text, with no encryption at all: anything else on the " +
				"network path can read a password typed over it. It is also the single most common way IoT botnets " +
				"such as Mirai spread, by trying default credentials over open Telnet.",
			Match: func(p Probe) (string, bool) { return "port 23 accepted a connection", true },
		},
		{
			ID: "ssh-protocol-1", Name: "SSH protocol version 1", Severity: SeverityCritical, Ports: []int{22},
			Description: "This server still offers SSH protocol version 1, which is broken by design (no real integrity " +
				"protection, among other weaknesses) and has been obsolete for two decades. Only SSH-2 should ever be offered.",
			Match: func(p Probe) (string, bool) {
				major, ok := parseSSHProtocolMajor(p.Banner)
				if !ok || major != 1 {
					return "", false
				}
				return p.Banner, true
			},
		},
		{
			ID: "ssh-missing-roaming-fix", Name: "OpenSSH missing the 2016 roaming fix", Severity: SeverityCritical, Ports: []int{22},
			Description: "OpenSSH versions before 7.1p2 shipped an experimental client \"roaming\" feature with an " +
				"information-leak bug (CVE-2016-0777) and a matching memory-disclosure bug (CVE-2016-0778), fixed in " +
				"an emergency release in January 2016. A server this old is missing roughly a decade of fixes beyond " +
				"just those two.",
			Match: matchOpenSSHBelow("7.1"),
		},
		{
			ID: "ssh-outdated-openssh", Name: "Outdated OpenSSH", Severity: SeverityHigh, Ports: []int{22},
			Description: "OpenSSH versions before 7.8 are missing the fix for a username-enumeration timing side " +
				"channel (CVE-2018-15473) and other hardening landed since. Update to a current OpenSSH release.",
			Match: matchOpenSSHRange("7.1", "7.8"),
		},
		{
			ID: "ftp-unencrypted", Name: "FTP exposed, unencrypted", Severity: SeverityMedium, Ports: []int{21},
			Description: "FTP sends credentials and file contents in plain text; anyone on the network path can read " +
				"them. Prefer SFTP (over SSH) if remote file transfer is actually needed.",
			Match: func(p Probe) (string, bool) {
				if !strings.HasPrefix(p.Banner, "220") {
					return "", false
				}
				return p.Banner, true
			},
		},
		{
			ID: "ftp-anonymous-login", Name: "FTP anonymous login allowed", Severity: SeverityHigh, Ports: []int{21},
			Description: "This FTP server accepted the well-known \"anonymous\" account with no real password, which " +
				"may expose files to anyone on the network who knows (or guesses) the address.",
			Match: func(p Probe) (string, bool) {
				if !p.FTPAnonLogin {
					return "", false
				}
				return "USER anonymous was accepted", true
			},
		},
		{
			ID: "ftp-vsftpd-234-backdoor", Name: "vsftpd 2.3.4 backdoor", Severity: SeverityCritical, Ports: []int{21},
			Description: "vsftpd 2.3.4's source archive was tampered with for a few days in 2011: a backdoor (CVE-2011-2523) " +
				"opens a root shell on port 6200 after a crafted login. Treat this build as compromised and reinstall " +
				"from a clean source rather than just upgrading in place.",
			Match: func(p Probe) (string, bool) {
				if !strings.Contains(strings.ToLower(p.Banner), "vsftpd 2.3.4") {
					return "", false
				}
				return p.Banner, true
			},
		},
		{
			ID: "apache-path-traversal-2021", Name: "Apache path-traversal/RCE (2021)", Severity: SeverityCritical,
			Description: "Apache httpd 2.4.49 and 2.4.50 shipped a path-traversal bug that, depending on configuration, " +
				"allows reading arbitrary files or remote code execution (CVE-2021-41773, CVE-2021-42013). Update past 2.4.51.",
			Match: matchApacheExact("2.4.49", "2.4.50"),
		},
		{
			ID: "apache-eol-2.2", Name: "Apache 2.2.x (end of life)", Severity: SeverityHigh,
			Description: "The Apache httpd 2.2.x line reached end of life in 2018 and has not received security fixes " +
				"since. Update to a current 2.4.x release.",
			Match: matchApacheMinor(2),
		},
		{
			ID: "apache-outdated", Name: "Outdated Apache httpd", Severity: SeverityLow,
			Description: "This Apache httpd 2.4.x build is older than 2.4.49 and is missing security fixes released " +
				"since, including (depending on exact version) the 2021 path-traversal issue fixed in 2.4.51. Update " +
				"to the latest 2.4.x release.",
			Match: matchApacheOutdated24,
		},
		{
			ID: "nginx-resolver-cve", Name: "Outdated nginx (resolver bug)", Severity: SeverityMedium,
			Description: "nginx builds before 1.20.1/1.21.0 are missing the fix for an off-by-one heap write in the " +
				"DNS resolver (CVE-2021-23017), which matters if the \"resolver\" directive is configured. Update to a " +
				"current release either way; this build is also missing other fixes from since.",
			Match: matchNginxOld,
		},
		{
			ID: "lighttpd-outdated", Name: "Outdated lighttpd", Severity: SeverityLow,
			Description: "This lighttpd build is several years old. Shepherd does not have a specific CVE on file for " +
				"this version (no CVE database is bundled — see docs/VULNSCAN.md), but a build this old is worth " +
				"checking against lighttpd's own release notes for fixed issues.",
			Match: matchLighttpdOld,
		},
		{
			ID: "docker-unauthenticated-api", Name: "Docker API exposed, unauthenticated", Severity: SeverityCritical, Ports: []int{2375},
			Description: "The Docker Engine API on port 2375 answered an unauthenticated request. Anyone who can reach " +
				"this port can run arbitrary containers with full control of this host (for example, mounting the root " +
				"filesystem) — equivalent to having a root shell. Bind this port to loopback/the tailnet only, enable " +
				"TLS client-certificate auth, or remove the exposure entirely.",
			Match: func(p Probe) (string, bool) {
				if !p.DockerAPIOpen {
					return "", false
				}
				return "GET /version answered with no authentication", true
			},
		},
		{
			ID: "smb1-enabled", Name: "SMBv1 enabled", Severity: SeverityCritical, Ports: []int{445},
			Description: "This server answered an SMBv1 Negotiate Protocol request, the protocol version exploited by " +
				"EternalBlue, WannaCry and NotPetya. Disable SMBv1 and use SMBv2/3 only.",
			Match: func(p Probe) (string, bool) {
				if !p.SMB1Negotiated {
					return "", false
				}
				return "answered an SMBv1-framed Negotiate Protocol response", true
			},
		},
	}
}

func matchOpenSSHBelow(ceiling string) func(Probe) (string, bool) {
	ceil, _ := parseVersion(ceiling)
	return func(p Probe) (string, bool) {
		_, v, ok := parseOpenSSHVersion(p.Banner)
		if !ok {
			return "", false
		}
		pv, ok := parseVersion(v)
		if !ok || !pv.less(ceil) {
			return "", false
		}
		return p.Banner, true
	}
}

func matchOpenSSHRange(floor, ceiling string) func(Probe) (string, bool) {
	lo, _ := parseVersion(floor)
	hi, _ := parseVersion(ceiling)
	return func(p Probe) (string, bool) {
		_, v, ok := parseOpenSSHVersion(p.Banner)
		if !ok {
			return "", false
		}
		pv, ok := parseVersion(v)
		if !ok || pv.less(lo) || !pv.less(hi) {
			return "", false
		}
		return p.Banner, true
	}
}

func matchApacheExact(versions ...string) func(Probe) (string, bool) {
	return func(p Probe) (string, bool) {
		product, version, ok := parseServerVersion(p.HTTPServer)
		if !ok || product != "apache" {
			return "", false
		}
		for _, v := range versions {
			if version == v {
				return p.HTTPServer, true
			}
		}
		return "", false
	}
}

func matchApacheMinor(minor int) func(Probe) (string, bool) {
	return func(p Probe) (string, bool) {
		product, version, ok := parseServerVersion(p.HTTPServer)
		if !ok || product != "apache" {
			return "", false
		}
		pv, ok := parseVersion(version)
		if !ok || len(pv) < 2 || pv[1] != minor {
			return "", false
		}
		return p.HTTPServer, true
	}
}

func matchApacheOutdated24(p Probe) (string, bool) {
	product, version, ok := parseServerVersion(p.HTTPServer)
	if !ok || product != "apache" {
		return "", false
	}
	pv, ok := parseVersion(version)
	if !ok || len(pv) < 2 || pv[1] != 4 {
		return "", false
	}
	ceil, _ := parseVersion("2.4.49")
	if !pv.less(ceil) {
		return "", false
	}
	return p.HTTPServer, true
}

var nginxResolverCeiling, _ = parseVersion("1.20.1")

func matchNginxOld(p Probe) (string, bool) {
	product, version, ok := parseServerVersion(p.HTTPServer)
	if !ok || product != "nginx" {
		return "", false
	}
	pv, ok := parseVersion(version)
	if !ok || !pv.less(nginxResolverCeiling) {
		return "", false
	}
	return p.HTTPServer, true
}

var lighttpdCeiling, _ = parseVersion("1.4.50")

func matchLighttpdOld(p Probe) (string, bool) {
	product, version, ok := parseServerVersion(p.HTTPServer)
	if !ok || product != "lighttpd" {
		return "", false
	}
	pv, ok := parseVersion(version)
	if !ok || !pv.less(lighttpdCeiling) {
		return "", false
	}
	return p.HTTPServer, true
}
