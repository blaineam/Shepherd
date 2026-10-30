// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"net/netip"
	"testing"
)

func TestPresetsAreWellFormed(t *testing.T) {
	ids := map[string]bool{}
	for _, p := range Presets() {
		if p.ID == "" || p.Name == "" || p.Provider == "" || p.Description == "" || p.Privacy == "" {
			t.Errorf("%s: missing text field: %+v", p.ID, p)
		}
		if ids[p.ID] {
			t.Errorf("duplicate id %s", p.ID)
		}
		ids[p.ID] = true
		switch p.Filtering {
		case FilterNone, FilterMalware, FilterAds, FilterFamily:
		default:
			t.Errorf("%s: filtering %q", p.ID, p.Filtering)
		}
		if p.DoH == "" || p.DoT == "" {
			t.Errorf("%s: every preset must offer encrypted transports", p.ID)
		}
		for _, ip := range p.IPv4 {
			if a, err := netip.ParseAddr(ip); err != nil || !a.Is4() {
				t.Errorf("%s: bad IPv4 %q", p.ID, ip)
			}
		}
		for _, ip := range p.IPv6 {
			if a, err := netip.ParseAddr(ip); err != nil || !a.Is6() {
				t.Errorf("%s: bad IPv6 %q", p.ID, ip)
			}
		}
		for _, form := range []string{"ip", "doh", "dot"} {
			for _, a := range p.Upstreams(form) {
				if err := ValidateUpstream(a); err != nil {
					t.Errorf("%s/%s: %v", p.ID, form, err)
				}
			}
		}
	}
	if len(ids) < 9 {
		t.Errorf("catalog has %d presets", len(ids))
	}
}

func TestPresetUpstreamsAndLookup(t *testing.T) {
	p, ok := PresetByID("cloudflare")
	if !ok {
		t.Fatal("cloudflare preset missing")
	}
	if got := p.Upstreams("ip"); len(got) != 4 || got[0] != "1.1.1.1" {
		t.Errorf("ip = %v", got)
	}
	if got := p.Upstreams("doh"); len(got) != 1 || got[0] != "https://cloudflare-dns.com/dns-query" {
		t.Errorf("doh = %v", got)
	}
	if got := p.Upstreams("dot"); len(got) != 1 || got[0] != "tls://one.one.one.one" {
		t.Errorf("dot = %v", got)
	}
	if p.Upstreams("bogus") != nil {
		t.Error("unknown form must be nil")
	}
	if _, ok := PresetByID("nope"); ok {
		t.Error("unknown id must not match")
	}
	empty := Preset{}
	if empty.Upstreams("doh") != nil || empty.Upstreams("dot") != nil {
		t.Error("a preset without those forms returns nil")
	}
}
