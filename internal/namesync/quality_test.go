// SPDX-License-Identifier: AGPL-3.0-or-later

package namesync

import "testing"

func TestQuality(t *testing.T) {
	cases := []struct {
		name, vendor string
		want         int
	}{
		{"", "", Useless},
		{"   ", "", Useless},
		{"Unknown", "", Useless},
		{"private", "", Useless},
		{"*", "", Useless},
		{"192.0.2.87", "", Useless},
		{"2001:db8::1", "", Useless},
		{"02005E00A1B2", "", Useless},
		{"02:00:5e:00:a1:b2", "", Useless},
		{"02-00-5e-00-a1-b2", "", Useless},
		{"ExampleCo Networks", "ExampleCo Networks", Generic},
		{"Acme", "Shenzhen Acme Technology Co., Ltd.", Generic},
		{"eero", "eero inc.", Generic},
		{"XP200M", "ExampleCo Inc.", Machine},
		{"Q404", "", Machine},
		{"PS5-1B3C5D", "", Machine},
		{"Mac-K7QZ4T9XWB", "", Machine},
		{"Presence-Sensor-X2-41D7", "", Machine},
		{"Weather_HB-00123456", "", Machine},
		{"Module7E21", "", Machine},
		{"iPhone", "Apple, Inc.", Plain},
		{"NAS", "", Plain},
		{"Grill", "", Plain},
		{"PS5", "", Plain},
		{"Ceiling Fan M2-c13e9a", "", Plain},
		{"[TV] webOS TV OLED55X1ABC", "", Plain},
		{"Kitchen-Speaker", "", Hostname},
		{"sams.macbook", "", Hostname},
		{"Sam’s MacBook Pro", "Apple, Inc.", Human},
		{"TV Soundbar", "", Human},
		{"Apple TV 4K", "", Human},
		{"iPhone 15 Pro", "", Human},
		{"Kitchen speaker", "Sonos", Human},
	}
	for _, c := range cases {
		if got := Quality(c.name, c.vendor); got != c.want {
			t.Errorf("Quality(%q, %q) = %d, want %d", c.name, c.vendor, got, c.want)
		}
	}
}

func TestScoreAddsTheTypedBonusButNeverToAUselessName(t *testing.T) {
	if got := score(Entry{Name: "XP200M", Typed: true}); got != Machine+typedBonus {
		t.Errorf("typed machine name scored %d", got)
	}
	if got := score(Entry{Name: "Unknown", Typed: true}); got != Useless {
		t.Errorf("typed placeholder scored %d", got)
	}
	// A typed hostname-like name still loses to nothing a person would say.
	if score(Entry{Name: "XP200M", Typed: true}) >= score(Entry{Name: "Kitchen plug"}) {
		t.Error("a typed model number beat a readable name")
	}
	// A maker's name someone typed is worth as much as a plain word.
	if got := score(Entry{Name: "Grill", Vendor: "Grill Works LLC", Typed: true}); got != Generic+typedBonus {
		t.Errorf("typed maker name scored %d", got)
	}
}

func TestFit(t *testing.T) {
	if got := fit("Sam’s MacBook Pro", 5); got != "Sam’s" {
		t.Errorf("fit cut to %q", got)
	}
	if got := fit("short", 32); got != "short" {
		t.Errorf("fit changed %q", got)
	}
	if got := fit("anything at all", 0); got != "anything at all" {
		t.Errorf("no limit changed %q", got)
	}
}
