// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import "testing"

func hasFinding(t *testing.T, matches []Match, id string) Match {
	t.Helper()
	for _, m := range matches {
		if m.Signature.ID == id {
			return m
		}
	}
	t.Fatalf("no match for signature %q in %+v", id, matches)
	return Match{}
}

func mustNotMatch(t *testing.T, matches []Match, id string) {
	t.Helper()
	for _, m := range matches {
		if m.Signature.ID == id {
			t.Fatalf("signature %q matched, want no match: %+v", id, m)
		}
	}
}

func TestEvaluateTelnetExposed(t *testing.T) {
	m := Evaluate(Probe{Connected: true, Port: 23})
	hasFinding(t, m, "telnet-exposed")
}

func TestEvaluateSSHProtocol1(t *testing.T) {
	m := Evaluate(Probe{Connected: true, Port: 22, Banner: "SSH-1.5-1.2.27"})
	got := hasFinding(t, m, "ssh-protocol-1")
	if got.Signature.Severity != SeverityCritical {
		t.Fatalf("severity = %v", got.Signature.Severity)
	}
	mustNotMatch(t, Evaluate(Probe{Connected: true, Port: 22, Banner: "SSH-2.0-OpenSSH_9.6"}), "ssh-protocol-1")
}

func TestEvaluateOpenSSHVersionBands(t *testing.T) {
	// Below 7.1: missing the 2016 roaming-bug emergency fix.
	m := Evaluate(Probe{Connected: true, Port: 22, Banner: "SSH-2.0-OpenSSH_6.6"})
	hasFinding(t, m, "ssh-missing-roaming-fix")
	mustNotMatch(t, m, "ssh-outdated-openssh")

	// 7.1 up to (not including) 7.8: missing the username-enumeration fix.
	m = Evaluate(Probe{Connected: true, Port: 22, Banner: "SSH-2.0-OpenSSH_7.4"})
	hasFinding(t, m, "ssh-outdated-openssh")
	mustNotMatch(t, m, "ssh-missing-roaming-fix")

	// 7.8 and newer: neither fires.
	m = Evaluate(Probe{Connected: true, Port: 22, Banner: "SSH-2.0-OpenSSH_9.6"})
	mustNotMatch(t, m, "ssh-missing-roaming-fix")
	mustNotMatch(t, m, "ssh-outdated-openssh")

	// A non-OpenSSH SSH server: neither OpenSSH-specific signature fires.
	m = Evaluate(Probe{Connected: true, Port: 22, Banner: "SSH-2.0-dropbear_2020.81"})
	mustNotMatch(t, m, "ssh-missing-roaming-fix")
	mustNotMatch(t, m, "ssh-outdated-openssh")
}

func TestEvaluateFTPSignatures(t *testing.T) {
	m := Evaluate(Probe{Connected: true, Port: 21, Banner: "220 (vsFTPd 3.0.3)"})
	hasFinding(t, m, "ftp-unencrypted")
	mustNotMatch(t, m, "ftp-vsftpd-234-backdoor")
	mustNotMatch(t, m, "ftp-anonymous-login")

	m = Evaluate(Probe{Connected: true, Port: 21, Banner: "220 (vsFTPd 2.3.4)"})
	hasFinding(t, m, "ftp-vsftpd-234-backdoor")

	m = Evaluate(Probe{Connected: true, Port: 21, Banner: "220 Ready", FTPAnonLogin: true})
	hasFinding(t, m, "ftp-anonymous-login")

	// No FTP-looking banner at all: the unencrypted-exposure signature,
	// which needs that confirmation, does not fire.
	mustNotMatch(t, Evaluate(Probe{Connected: true, Port: 21, Banner: ""}), "ftp-unencrypted")
}

func TestEvaluateWebServerSignatures(t *testing.T) {
	hasFinding(t, Evaluate(Probe{Connected: true, Port: 80, HTTPServer: "Apache/2.4.49 (Unix)"}), "apache-path-traversal-2021")
	hasFinding(t, Evaluate(Probe{Connected: true, Port: 80, HTTPServer: "Apache/2.2.15 (CentOS)"}), "apache-eol-2.2")
	hasFinding(t, Evaluate(Probe{Connected: true, Port: 80, HTTPServer: "Apache/2.4.10"}), "apache-outdated")
	mustNotMatch(t, Evaluate(Probe{Connected: true, Port: 80, HTTPServer: "Apache/2.4.58"}), "apache-outdated")
	hasFinding(t, Evaluate(Probe{Connected: true, Port: 80, HTTPServer: "nginx/1.18.0"}), "nginx-resolver-cve")
	mustNotMatch(t, Evaluate(Probe{Connected: true, Port: 80, HTTPServer: "nginx/1.25.3"}), "nginx-resolver-cve")
	hasFinding(t, Evaluate(Probe{Connected: true, Port: 80, HTTPServer: "lighttpd/1.4.28"}), "lighttpd-outdated")
	// This matters regardless of which "HTTP admin" port it was found on.
	hasFinding(t, Evaluate(Probe{Connected: true, Port: 8080, HTTPServer: "nginx/1.10.0"}), "nginx-resolver-cve")
}

func TestEvaluateDockerAndSMB1(t *testing.T) {
	hasFinding(t, Evaluate(Probe{Connected: true, Port: 2375, DockerAPIOpen: true}), "docker-unauthenticated-api")
	mustNotMatch(t, Evaluate(Probe{Connected: true, Port: 2375, DockerAPIOpen: false}), "docker-unauthenticated-api")
	hasFinding(t, Evaluate(Probe{Connected: true, Port: 445, SMB1Negotiated: true}), "smb1-enabled")
	mustNotMatch(t, Evaluate(Probe{Connected: true, Port: 445, SMB1Negotiated: false}), "smb1-enabled")
}

func TestEvaluateSkipsEmptyProbe(t *testing.T) {
	if m := Evaluate(Probe{Connected: true, Port: 22}); len(m) != 0 {
		t.Fatalf("Evaluate(empty probe) = %+v, want no matches", m)
	}
}

func TestEveryBuiltinSignatureHasRequiredFields(t *testing.T) {
	seen := map[string]bool{}
	for _, sig := range BuiltinSignatures() {
		if sig.ID == "" || sig.Name == "" || sig.Description == "" {
			t.Fatalf("signature missing required field: %+v", sig)
		}
		if !Severity(sig.Severity).valid() {
			t.Fatalf("signature %s has invalid severity %q", sig.ID, sig.Severity)
		}
		if sig.Match == nil {
			t.Fatalf("signature %s has no Match func", sig.ID)
		}
		if seen[sig.ID] {
			t.Fatalf("duplicate signature ID %q", sig.ID)
		}
		seen[sig.ID] = true
	}
}
