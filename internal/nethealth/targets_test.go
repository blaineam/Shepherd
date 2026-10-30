// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

import (
	"reflect"
	"testing"
)

func TestHostFromUpstream(t *testing.T) {
	cases := []struct{ in, want string }{
		{"9.9.9.10", "9.9.9.10"},
		{"tcp://1.1.1.1", "1.1.1.1"},
		{"udp://1.1.1.1", "1.1.1.1"},
		{"tls://dns.quad9.net:853", "dns.quad9.net"},
		{"tls://dns.quad9.net", "dns.quad9.net"},
		{"https://dns.google/dns-query", "dns.google"},
		{"[2001:db8::1111]:853", "2001:db8::1111"},
		{"[::1]", "::1"},
		{"2001:db8::1111", "2001:db8::1111"},
		{"  9.9.9.10  ", "9.9.9.10"},
		{"", ""},
	}
	for _, c := range cases {
		if got := hostFromUpstream(c.in); got != c.want {
			t.Errorf("hostFromUpstream(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDefaultTargets(t *testing.T) {
	got := DefaultTargets([]string{"9.9.9.10", "tcp://1.1.1.1", "tls://dns.quad9.net:853"})
	want := []string{"9.9.9.10", "1.1.1.1", "dns.quad9.net", "8.8.8.8"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DefaultTargets = %v, want %v", got, want)
	}
}

func TestDefaultTargetsDedupesAndSkipsEmpty(t *testing.T) {
	got := DefaultTargets([]string{"1.1.1.1", "", "1.1.1.1", "8.8.8.8"})
	want := []string{"1.1.1.1", "8.8.8.8"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DefaultTargets = %v, want %v", got, want)
	}
}

func TestDefaultTargetsEmptyUpstreamsStillGetsPublicTargets(t *testing.T) {
	got := DefaultTargets(nil)
	if !reflect.DeepEqual(got, PublicAnycastTargets) {
		t.Errorf("DefaultTargets(nil) = %v, want %v", got, PublicAnycastTargets)
	}
}
