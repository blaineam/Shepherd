// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want []int
		ok   bool
	}{
		{"7.4", []int{7, 4}, true},
		{"7.4p1", []int{7, 4}, true}, // trailing patch-letter suffix is stripped
		{"1.20.1", []int{1, 20, 1}, true},
		{"2.4.49", []int{2, 4, 49}, true},
		{"", nil, false},
		{"not-a-version", nil, false},
	}
	for _, c := range cases {
		got, ok := parseVersion(c.in)
		if ok != c.ok {
			t.Fatalf("parseVersion(%q) ok = %v, want %v", c.in, ok, c.ok)
		}
		if !ok {
			continue
		}
		if len(got) != len(c.want) {
			t.Fatalf("parseVersion(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Fatalf("parseVersion(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"7.4", "7.8", true},
		{"7.8", "7.4", false},
		{"7.4", "7.4", false},
		{"7.4", "7.4.1", true}, // missing trailing component reads as 0
		{"7.4.1", "7.4", false},
		{"1.20.0", "1.20.1", true},
		{"2.2.0", "2.4.0", true},
	}
	for _, c := range cases {
		a, _ := parseVersion(c.a)
		b, _ := parseVersion(c.b)
		if got := a.less(b); got != c.want {
			t.Errorf("(%q).less(%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestParseServerVersion(t *testing.T) {
	cases := []struct {
		header  string
		product string
		version string
		ok      bool
	}{
		{"Apache/2.4.49 (Unix)", "apache", "2.4.49", true},
		{"nginx/1.18.0", "nginx", "1.18.0", true},
		{"lighttpd/1.4.28", "lighttpd", "1.4.28", true},
		{"Microsoft-IIS/10.0", "", "", false},
		{"", "", "", false},
		{"Apache", "", "", false}, // no version at all
	}
	for _, c := range cases {
		product, version, ok := parseServerVersion(c.header)
		if ok != c.ok {
			t.Fatalf("parseServerVersion(%q) ok = %v, want %v", c.header, ok, c.ok)
		}
		if !ok {
			continue
		}
		if product != c.product {
			t.Fatalf("parseServerVersion(%q) product = %q, want %q", c.header, product, c.product)
		}
		got, _ := parseVersion(version)
		want, _ := parseVersion(c.version)
		if !got.equal(want) {
			t.Fatalf("parseServerVersion(%q) version = %q, want %q", c.header, version, c.version)
		}
	}
}

func TestParseSSHBanner(t *testing.T) {
	cases := []struct {
		banner      string
		protoMajor  int
		protoOK     bool
		software    string
		softwareVer string
		softwareOK  bool
	}{
		{"SSH-2.0-OpenSSH_9.6", 2, true, "openssh", "9.6", true},
		{"SSH-1.99-OpenSSH_3.4p1", 1, true, "openssh", "3.4", true},
		{"SSH-1.5-1.2.27", 1, true, "", "", false},
		{"not an ssh banner", 0, false, "", "", false},
		{"", 0, false, "", "", false},
	}
	for _, c := range cases {
		major, protoOK := parseSSHProtocolMajor(c.banner)
		if protoOK != c.protoOK || (protoOK && major != c.protoMajor) {
			t.Fatalf("parseSSHProtocolMajor(%q) = %d, %v, want %d, %v", c.banner, major, protoOK, c.protoMajor, c.protoOK)
		}
		software, version, ok := parseOpenSSHVersion(c.banner)
		if ok != c.softwareOK {
			t.Fatalf("parseOpenSSHVersion(%q) ok = %v, want %v", c.banner, ok, c.softwareOK)
		}
		if !ok {
			continue
		}
		if software != c.software {
			t.Fatalf("parseOpenSSHVersion(%q) software = %q, want %q", c.banner, software, c.software)
		}
		got, _ := parseVersion(version)
		want, _ := parseVersion(c.softwareVer)
		if !got.equal(want) {
			t.Fatalf("parseOpenSSHVersion(%q) version = %q, want %q", c.banner, version, c.softwareVer)
		}
	}
}
