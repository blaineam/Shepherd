// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"fmt"
	"testing"
	"time"
)

func searchFixture(t testing.TB) (*Registry, *fakeClock, map[string]string) {
	r, clk := newReg(t)
	ids := map[string]string{}
	ids["cam"] = r.Observe(Observation{MAC: vmac, IP: "192.0.2.10", Source: SourceMDNS, Hostname: "porch-cam", Services: []string{"_rtsp._tcp"}})
	clk.Advance(2 * time.Hour)
	ids["tv"] = r.Observe(Observation{MAC: macA, IP: "192.0.2.11", Source: SourceMDNS, Hostname: "den-tv", Services: []string{"_googlecast._tcp"}, VendorHint: "Apple"})
	clk.Advance(2 * time.Hour)
	ids["anon"] = r.Observe(Observation{Source: SourceDNS, IP: "2001:db8::99"})
	ids["old"] = r.Observe(Observation{MAC: macB, IP: "192.0.2.12"})
	r.Observe(Observation{MAC: macB, IP: "192.0.2.13"}) // .12 becomes a past IP
	r.CreateGroup("Kids", "")
	r.CreateGroup("Smart Home", "")
	r.BulkAssignGroup([]string{ids["tv"]}, "kids")
	r.BulkAssignGroup([]string{ids["cam"], ids["tv"]}, "smart-home")
	r.SetExcluded(ids["cam"], true)
	r.SetTags(ids["tv"], []string{"Living Room"})
	r.Rename(ids["old"], "Dad's Laptop")
	return r, clk, ids
}

func idsOf(p Page) []string {
	var out []string
	for _, d := range p.Items {
		out = append(out, d.ID)
	}
	return out
}

func TestSearchFilters(t *testing.T) {
	r, _, ids := searchFixture(t)
	for _, tc := range []struct {
		q    string
		want []string
	}{
		{"", []string{"cam", "tv", "anon", "old"}},
		{"porch", []string{"cam"}},
		{"PORCH-CAM", []string{"cam"}},
		{"192.0.2.11", []string{"tv"}},
		{"192.0.2.12", []string{"old"}}, // past IP
		{"2001:db8::99", []string{"anon"}},
		{"02:00:5e:00:00:0a", []string{"tv"}},
		{"02005e00000a", []string{"tv"}},
		{"examplecoo", nil},
		{"examplec", []string{"cam"}},
		{"dad", []string{"old"}},
		{"living", []string{"tv"}},
		{"kids", []string{"tv"}},
		{"smart home", []string{"cam", "tv"}}, // two ANDed terms, group name has both words
		{`"smart home"`, []string{"cam", "tv"}},
		{"camera", []string{"cam"}},
		{"group:kids", []string{"tv"}},
		{"group:KIDS", []string{"tv"}},
		{`group:"smart home"`, []string{"cam", "tv"}},
		{"group:smart-home", []string{"cam", "tv"}},
		{"group:none", []string{"anon", "old"}},
		{"-group:kids", []string{"cam", "anon", "old"}},
		{"vendor:apple", []string{"tv"}},
		{"vendor:example", []string{"cam"}},
		{"type:camera", []string{"cam"}},
		{"type:tv", []string{"tv"}},
		{"type:unknown", []string{"anon"}},
		{"type:laptop", []string{"old"}},
		{"type:cam", []string{"cam"}},
		{"type:toaster", nil},
		{"ip:192.0.2.", []string{"cam", "tv", "old"}},
		{"ip:2001:db8", []string{"anon"}},
		{"mac:02:00:5e", []string{"tv", "old"}},
		{"mac:00005e", []string{"cam"}},
		{"seen:1h", []string{"anon", "old"}},
		{"seen:3h", []string{"tv", "anon", "old"}},
		{"seen:1d", []string{"cam", "tv", "anon", "old"}},
		{"seen:90m", []string{"anon", "old"}},
		{"seen:1w", []string{"cam", "tv", "anon", "old"}},
		{"seen:30s", []string{"anon", "old"}},
		{"seen:2h30m", []string{"tv", "anon", "old"}},
		{"seen:soon", nil},
		{"seen:", nil},
		{"excluded:true", []string{"cam"}},
		{"excluded:no", []string{"tv", "anon", "old"}},
		{"excluded:maybe", nil},
		{"unnamed:true", []string{"anon"}},
		{"unnamed:false", []string{"cam", "tv", "old"}},
		{"unnamed:what", nil},
		{"tag:living", []string{"tv"}},
		{"name:den", []string{"tv"}},
		{"-name:den", []string{"cam", "anon", "old"}},
		{"group:kids vendor:apple type:tv", []string{"tv"}},
		{"group:kids type:camera", nil},
		{"-printer -zzz", []string{"cam", "tv", "anon", "old"}},
		{"unknownkey:value", nil}, // not a filter: free text that matches nothing
		{"-zzzz", []string{"cam", "tv", "anon", "old"}},
	} {
		got := idsOf(r.Search(tc.q, SearchOptions{Sort: SortName, Limit: 100}))
		want := map[string]bool{}
		for _, k := range tc.want {
			want[ids[k]] = true
		}
		gm := map[string]bool{}
		for _, g := range got {
			gm[g] = true
		}
		if len(gm) != len(want) {
			t.Errorf("%q: got %v, want %v", tc.q, got, tc.want)
			continue
		}
		for k := range want {
			if !gm[k] {
				t.Errorf("%q: missing %s in %v", tc.q, k, got)
			}
		}
	}
}

func TestSearchSortAndPaging(t *testing.T) {
	r, clk := newReg(t)
	for i := 0; i < 7; i++ {
		id := r.Observe(Observation{Source: SourceDNS, IP: fmt.Sprintf("192.0.2.%d", i+1)})
		r.Rename(id, fmt.Sprintf("dev-%d", 6-i)) // names descend while recency ascends
		clk.Advance(time.Minute)
	}
	recent := r.Search("", SearchOptions{Sort: SortRecent, Limit: 3})
	if recent.Total != 7 || len(recent.Items) != 3 || recent.Limit != 3 {
		t.Fatalf("%+v", recent.Total)
	}
	eq(t, recent.Items[0].Alias, "dev-0") // most recent
	byName := r.Search("", SearchOptions{Sort: SortName, Offset: 2, Limit: 3})
	eq(t, byName.Items[0].Alias, "dev-2")
	eq(t, byName.Offset, 2)
	last := r.Search("", SearchOptions{Sort: SortName, Offset: 6, Limit: 3})
	if len(last.Items) != 1 {
		t.Fatal("last page")
	}
	past := r.Search("", SearchOptions{Offset: 99})
	if len(past.Items) != 0 || past.Total != 7 || past.Offset != 7 {
		t.Fatalf("%+v", past)
	}
	neg := r.Search("", SearchOptions{Offset: -5})
	eq(t, neg.Offset, 0)
	eq(t, neg.Limit, 50)
	eq(t, r.Search("", SearchOptions{Limit: 9999}).Limit, 500)
}

func TestSortTieBreaks(t *testing.T) {
	r, _ := newReg(t)
	a := r.Observe(Observation{IP: "192.0.2.1"})
	b := r.Observe(Observation{IP: "192.0.2.2"})
	r.Rename(a, "same")
	r.Rename(b, "same")
	p := r.Search("", SearchOptions{Sort: SortRecent})
	if p.Items[0].ID > p.Items[1].ID {
		t.Fatal("ID tie-break")
	}
}

func TestTokenize(t *testing.T) {
	got := tokenize(`a  b:"c d"  "e f" g:`)
	eq(t, len(got), 4)
	eq(t, got[1], "b:c d")
	eq(t, got[2], "e f")
	if _, ok := parseSince("-5m"); ok {
		t.Fatal("negative duration accepted")
	}
	if d, ok := parseSince("1.5h"); !ok || d != 90*time.Minute {
		t.Fatal("fractional")
	}
}
