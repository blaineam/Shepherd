// SPDX-License-Identifier: AGPL-3.0-or-later

package classify

import "testing"

func TestRegistrable(t *testing.T) {
	for host, want := range map[string]string{
		"example.com":                      "example.com",
		"www.example.com":                  "example.com",
		"a.b.c.d.example.com":              "example.com",
		"x.example.co.uk":                  "example.co.uk",
		"example.co.uk":                    "example.co.uk",
		"co.uk":                            "",
		"cam.example.com.au":               "example.com.au",
		"bucket.s3.amazonaws.com":          "s3.amazonaws.com",
		"amazonaws.com":                    "",
		"x.us-east-1.elb.amazonaws.com":    "us-east-1.elb.amazonaws.com", // one label above the private suffix, never the customer's name
		"d111.cloudfront.net":              "d111.cloudfront.net",
		"a.b.d111.cloudfront.net":          "d111.cloudfront.net",
		"someone.github.io":                "someone.github.io",
		"localhost":                        "",
		"":                                 "",
		".":                                "",
		"a.b.c.d.e.f.g.h.i.j.example.org":  "example.org",
		"1.2.3.4.5.6.7.8.9.example.net":    "example.net",
		"deep.name.with.many.labels.co.jp": "labels.co.jp",
	} {
		if got := registrable(host); got != want {
			t.Errorf("registrable(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestRegistrableDoesNotAllocate(t *testing.T) {
	n := testing.AllocsPerRun(100, func() { _ = registrable("cdn.eu.region.example.co.uk") })
	if n != 0 {
		t.Errorf("registrable allocated %v times", n)
	}
}

func TestLowerTrimAndObservable(t *testing.T) {
	if got := lowerTrim("WWW.Example.COM."); got != "www.example.com" {
		t.Errorf("lowerTrim = %q", got)
	}
	if n := testing.AllocsPerRun(100, func() { _ = lowerTrim("www.example.com.") }); n != 0 {
		t.Errorf("lowerTrim of a lower-case name allocated %v times", n)
	}
	for host, want := range map[string]bool{
		"example.com": true, "a.example.org": true,
		"4.3.2.1.in-addr.arpa": false, "printer.local": false, "nas.lan": false, "router.home": false,
		"host.internal": false, "x": false, "": false, "a.b": true, "localhost": false,
	} {
		if got := observable(host); got != want {
			t.Errorf("observable(%q) = %v, want %v", host, got, want)
		}
	}
	long := make([]byte, 260)
	for i := range long {
		long[i] = 'a'
	}
	if observable(string(long) + ".com") {
		t.Error("an over-long name is not observable")
	}
}
