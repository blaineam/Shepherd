// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCleanText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"  Kids\tTablet\n", "Kids Tablet"},
		{"a\x00b\x07c", "abc"},
		{"zero​width", "zerowidth"},
		{"rtl‮evil", "rtlevil"},
		{"a   b", "a b"},
		{"bad\xffutf8", "badutf8"},
		{" x ", "x"},
		{"", ""},
	}
	for _, c := range cases {
		if got := cleanText(c.in, 100); got != c.want {
			t.Errorf("cleanText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCleanTextCapsOnRuneBoundary(t *testing.T) {
	in := strings.Repeat("é", 100) // 2 bytes each
	got := cleanText(in, 11)
	if len(got) > 11 || !utf8.ValidString(got) || len(got) != 10 {
		t.Fatalf("got %q (%d bytes)", got, len(got))
	}
	if got := cleanText("abc def", 4); got != "abc" {
		t.Fatalf("trailing space not trimmed: %q", got)
	}
}

func TestSanitizeDevices(t *testing.T) {
	long := strings.Repeat("x", 500)
	p, err := Sanitize(Plan{
		Source:   "src\n",
		Warnings: []string{"from source\x00"},
		Groups: []PlanGroup{
			{Name: "  Kids; Rooms "}, {Name: "kids; rooms", Color: "#112233"}, {Name: ""},
			{Name: "Bad Color", Color: "red"},
		},
		Devices: []PlanDevice{
			{MAC: "02-00-5E-00-00-01", IPs: []string{"192.0.2.5", "::ffff:192.0.2.5", "127.0.0.1", "nope", "", "192.0.2.6%eth0x"}, Name: "A\x00 name‮", Hostname: long, Vendor: long, Notes: long,
				Groups: []string{"Kids; Rooms", "Extra", ""}, Tags: []string{" Child ", "child", "a;b", ""}, Type: "TV", Hints: []string{"tv", "TV", ""}, Connection: "Wireless"},
			{MAC: "02:00:5e:00:00:01", IPs: []string{"192.0.2.7"}, Name: "dup", Hostname: "h", Excluded: true, Paused: true, Groups: []string{"Third"}, Tags: []string{"x"}, Hints: []string{"h2"}},
			{MAC: "garbage", IPs: []string{"192.0.2.9"}, Name: "ip only", Type: "spaceship"},
			{MAC: "garbage", Name: "nothing"},
			{Name: "empty"},
			{IPs: []string{"192.0.2.20"}},
			{IPs: []string{"192.0.2.20"}, Name: "same ip", Infrastructure: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != "src" {
		t.Errorf("source %q", p.Source)
	}
	if len(p.Devices) != 3 {
		t.Fatalf("devices: %+v", p.Devices)
	}
	d := p.Devices[0]
	if d.MAC != "02:00:5e:00:00:01" || d.Name != "A name" || len(d.Hostname) != MaxHostnameBytes || len(d.Vendor) != MaxVendorBytes || len(d.Notes) != MaxNotesBytes {
		t.Errorf("device 0: %+v", d)
	}
	if strings.Join(d.IPs, ",") != "192.0.2.5,192.0.2.7" {
		t.Errorf("ips %v", d.IPs)
	}
	if strings.Join(d.Groups, "|") != "Kids, Rooms|Extra|Third" || strings.Join(d.Tags, "|") != "child|a,b|x" {
		t.Errorf("groups %v tags %v", d.Groups, d.Tags)
	}
	if d.Type != "tv" || !d.Excluded || !d.Paused || d.Hostname == "" || strings.Join(d.Hints, "|") != "tv|h2" {
		t.Errorf("merge lost something: %+v", d)
	}
	if p.Devices[1].MAC != "" || p.Devices[1].Type != "" || p.Devices[1].IPs[0] != "192.0.2.9" {
		t.Errorf("ip-only device: %+v", p.Devices[1])
	}
	if p.Devices[2].Type != "router/infrastructure" || !p.Devices[2].Excluded || p.Devices[2].Name != "same ip" {
		t.Errorf("infra merge: %+v", p.Devices[2])
	}
	var names []string
	for _, g := range p.Groups {
		names = append(names, g.Name)
	}
	if strings.Join(names, "|") != "Kids, Rooms|Bad Color|Extra|Third" || p.Groups[0].Color != "#112233" {
		t.Errorf("groups %+v", p.Groups)
	}
	joined := strings.Join(p.Warnings, "\n")
	for _, want := range []string{"from source", "empty name", "#rrggbb", "not a usable IP", "not a usable MAC", "neither a usable MAC", "unknown device type"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning %q in:\n%s", want, joined)
		}
	}
}

func TestSanitizeLimits(t *testing.T) {
	big := Plan{Devices: make([]PlanDevice, MaxDevices+1)}
	if _, err := Sanitize(big); err != ErrPlanTooLarge {
		t.Fatalf("devices: %v", err)
	}
	if _, err := Sanitize(Plan{Groups: make([]PlanGroup, MaxGroups+1)}); err != ErrPlanTooLarge {
		t.Fatalf("groups: %v", err)
	}
	// Groups implied by devices count too.
	var p Plan
	for i := 0; i <= MaxGroups; i++ {
		p.Devices = append(p.Devices, PlanDevice{IPs: []string{"192.0.2.1"}, Groups: []string{string(rune('a'+i%26)) + strings.Repeat("z", i/26)}})
		p.Devices[i].IPs = []string{"198.51.100." + itoa(i%250+1)}
		p.Devices[i].MAC = macN(i)
	}
	if _, err := Sanitize(p); err != ErrPlanTooLarge {
		t.Fatalf("implied groups: %v", err)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func macN(i int) string {
	const hex = "0123456789abcdef"
	return "02:00:5e:00:" + string(hex[(i>>4)&15]) + string(hex[(i>>8)&15]) + ":" + string(hex[i&15]) + string(hex[(i>>4)&15])
}

func TestWarningsAreCapped(t *testing.T) {
	var p Plan
	for i := 0; i < MaxWarnings+50; i++ {
		p.Devices = append(p.Devices, PlanDevice{Name: "x"})
	}
	out, err := Sanitize(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Warnings) != MaxWarnings+1 || !strings.Contains(out.Warnings[MaxWarnings], "left out") {
		t.Fatalf("warnings: %d, last %q", len(out.Warnings), out.Warnings[len(out.Warnings)-1])
	}
}
