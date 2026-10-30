// SPDX-License-Identifier: AGPL-3.0-or-later

package classify

import (
	"strings"
	"testing"

	"shepherd/internal/devices"
)

// corpus is a labelled set of invented device profiles built from synthetic
// traffic. The names looked up are the real service names the shipped rules
// are about (that is the feature); every address, client and device is a
// documentation value.
func corpus() []profile {
	return []profile{
		{name: "camera that only talks to its cloud", vendor: "Hangzhou Hikvision Digital Technology",
			lookups: []lookup{{"ius.hik-connect.com", "203.0.113.10", 120}, {"dev.hik-connect.com", "203.0.113.11", 60}, {"pool.ntp.example.org", "203.0.113.12", 6}},
			want:    devices.TypeCamera, minConf: 0.8},
		{name: "camera with a randomized MAC", random: true,
			lookups: []lookup{{"p2p.hik-connect.com", "203.0.113.10", 80}, {"api.ezvizlife.com", "203.0.113.13", 40}},
			want:    devices.TypeCamera, minConf: 0.75},
		{name: "wyze-style camera", vendor: "Wyze Labs",
			lookups: []lookup{{"api.wyzecam.com", "203.0.113.20", 50}},
			want:    devices.TypeCamera, minConf: 0.7},
		{name: "doorbell", random: true,
			lookups: []lookup{{"fw.ring.com", "203.0.113.30", 70}, {"api.ring.com", "203.0.113.31", 30}},
			want:    devices.TypeDoorbell, minConf: 0.5},
		{name: "TV that streams", vendor: "LG Electronics",
			lookups: []lookup{{"ipv4-c001.1.oca.nflxso.net", "198.51.100.5", 40}, {"www.netflix.com", "198.51.100.6", 25},
				{"us.lgtvsdp.com", "203.0.113.40", 10}, {"app.lgappstv.com", "203.0.113.41", 10}, {"cdn.disneyplus.com", "203.0.113.42", 12}},
			want: devices.TypeTV, minConf: 0.7},
		{name: "streaming stick", vendor: "Roku",
			lookups: []lookup{{"scribe.logs.roku.com", "203.0.113.50", 60}, {"www.netflix.com", "198.51.100.6", 20}},
			want:    devices.TypeStreamingBox, minConf: 0.75},
		{name: "phone with mixed use", random: true,
			lookups: []lookup{{"connectivitycheck.gstatic.com", "2001:db8::1", 30}, {"mtalk.google.com", "2001:db8::2", 40},
				{"www.netflix.com", "198.51.100.6", 15}, {"photos.example.com", "203.0.113.60", 50}, {"news.example.org", "203.0.113.61", 40}},
			want: devices.TypePhone, minConf: 0.5},
		{name: "laptop doing updates", random: true,
			lookups: []lookup{{"download.windowsupdate.com", "203.0.113.70", 20}, {"www.msftconnecttest.com", "203.0.113.71", 30},
				{"docs.example.com", "203.0.113.72", 60}},
			want: devices.TypeLaptop, minConf: 0.5},
		{name: "printer", vendor: "Brother Industries", services: []string{"_ipp._tcp", "_pdl-datastream._tcp"},
			lookups: []lookup{{"firmware.example.net", "203.0.113.80", 3}},
			want:    devices.TypePrinter, minConf: 0.9},
		{name: "printer that phones home", vendor: "Hewlett Packard",
			lookups: []lookup{{"h10000.www1.hpeprint.com", "203.0.113.81", 25}, {"api.hpconnected.com", "203.0.113.82", 20}},
			want:    devices.TypePrinter, minConf: 0.8},
		{name: "smart speaker", vendor: "Sonos", services: []string{"_sonos._tcp", "_spotify-connect._tcp"},
			lookups: []lookup{{"update.sonos.com", "203.0.113.90", 30}},
			want:    devices.TypeSpeaker, minConf: 0.95},
		{name: "game console", vendor: "Nintendo",
			lookups: []lookup{{"conntest.nintendowifi.net", "203.0.113.100", 40}},
			want:    devices.TypeGameConsole, minConf: 0.95},
		{name: "playstation", random: true,
			lookups: []lookup{{"gs2.ww.prod.dl.playstation.net", "203.0.113.101", 60}, {"auth.api.sonyentertainmentnetwork.com", "203.0.113.102", 20}},
			want:    devices.TypeGameConsole, minConf: 0.85},
		{name: "thermostat", vendor: "ecobee",
			lookups: []lookup{{"rest.ecobee.com", "203.0.113.110", 30}},
			want:    devices.TypeThermostat, minConf: 0.95},
		{name: "smart plug on a cloud platform", vendor: "Espressif",
			lookups: []lookup{{"a1.tuya.com", "203.0.113.120", 30}, {"m1.tuya.com", "203.0.113.121", 20}},
			want:    devices.TypeSmartPlug, minConf: 0.8},
		{name: "hue bridge", vendor: "Signify", services: []string{"_hue._tcp", "_hap._tcp"},
			lookups: []lookup{{"discovery.meethue.com", "203.0.113.125", 12}},
			want:    devices.TypeSmartHome, minConf: 0.9},
		{name: "NAS", vendor: "Synology",
			lookups: []lookup{{"checkip.synology.com", "203.0.113.130", 10}, {"xyz.quickconnect.to", "203.0.113.131", 20}},
			want:    devices.TypeNAS, minConf: 0.9},
		{name: "access point", vendor: "Ubiquiti",
			lookups: []lookup{{"fw-download.ui.com", "203.0.113.140", 5}},
			want:    devices.TypeRouter, minConf: 0.7},
		{name: "smart ring", random: true,
			lookups: []lookup{{"api.ouraring.com", "203.0.113.150", 25}},
			want:    devices.TypeWearable, minConf: 0.5},
		{name: "named by its owner", vendor: "Obscure Widgets", names: []string{"Front-Porch-Camera"},
			want: devices.TypeCamera, minConf: 0.75},
		// Hard cases: the right behaviour is honesty, not a guess.
		{name: "randomized MAC, unfamiliar domains", random: true,
			lookups: []lookup{{"a.example.com", "203.0.113.160", 20}, {"b.example.net", "203.0.113.161", 20}, {"c.example.org", "192.0.2.200", 20}},
			want:    devices.TypeUnknown, wantUnsure: true},
		{name: "conflicting signals", vendor: "Obscure Widgets",
			lookups: []lookup{{"ius.hik-connect.com", "203.0.113.10", 40}, {"update.sonos.com", "203.0.113.90", 40}},
			want:    devices.TypeUnknown, wantUnsure: true},
		{name: "unfamiliar domains behind a streaming network", vendor: "Obscure Widgets",
			lookups: []lookup{{"edge1.example.com", "198.51.100.20", 50}, {"edge2.example.net", "198.51.100.21", 50}},
			want:    devices.TypeUnknown, wantUnsure: true},
		{name: "silent device with an unknown maker", vendor: "Obscure Widgets", want: devices.TypeUnknown, wantUnsure: true},
		{name: "apple device, no other evidence", vendor: "Apple", want: devices.TypeUnknown, wantUnsure: true},
	}
}

// TestScenarioCorpus classifies every invented device and measures accuracy.
func TestScenarioCorpus(t *testing.T) {
	correct, total := 0, 0
	for i, p := range corpus() {
		t.Run(p.name, func(t *testing.T) {
			c, _ := newClassifier(t)
			key := "dev-" + string(rune('a'+i%26))
			p.feed(c, key, "192.0.2.50")
			r := c.Classify(key)
			total++
			switch {
			case r.Type == p.want:
				correct++
			case p.wantUnsure && r.Type == devices.TypeUnknown:
				correct++
			default:
				t.Errorf("got %s, want %s", describe(r), p.want)
				return
			}
			if p.want != devices.TypeUnknown && r.Confidence < p.minConf {
				t.Errorf("confidence %.2f below the expected %.2f (%s)", r.Confidence, p.minConf, describe(r))
			}
			if p.want == devices.TypeUnknown && r.Confidence >= DefaultThreshold {
				t.Errorf("an unknown device reports confidence %.2f at or above the threshold", r.Confidence)
			}
			if len(r.Reasons) == 0 {
				t.Error("every result must explain itself")
			}
			if r.Type != devices.TypeUnknown && r.Confidence < DefaultThreshold {
				t.Error("a named class is never below the threshold")
			}
		})
	}
	acc := float64(correct) / float64(total)
	t.Logf("corpus accuracy: %d/%d = %.0f%%", correct, total, acc*100)
	if acc < 1 {
		t.Errorf("corpus accuracy %.2f, want 1.00", acc)
	}
}

// Reasons read as plain sentences a person can follow.
func TestReasonsReadWell(t *testing.T) {
	c, _ := newClassifier(t)
	profile{vendor: "Hangzhou Hikvision Digital Technology",
		lookups: []lookup{{"ius.hik-connect.com", "203.0.113.10", 100}}}.feed(c, "cam", "192.0.2.51")
	r := c.Classify("cam")
	mustType(t, r.Type, devices.TypeCamera, describe(r))
	joined := strings.Join(r.Reasons, " | ")
	for _, want := range []string{"Most of its recognised lookups go to a camera cloud service", "Manufacturer (Hangzhou Hikvision Digital Technology) is known for IP cameras"} {
		if !strings.Contains(joined, want) {
			t.Errorf("reasons %q missing %q", joined, want)
		}
	}
	if len(r.Reasons) > maxReasons+1 {
		t.Errorf("too many reasons: %v", r.Reasons)
	}
	// The stored form has no counts, so it does not change as the counts grow.
	before := r.Summary()
	look(c, "192.0.2.51", "ius.hik-connect.com", "203.0.113.10", 30)
	if after := c.Classify("cam").Summary(); after != before {
		t.Errorf("summary changed with the counts: %q -> %q", before, after)
	}
	if strings.ContainsAny(before, "0123456789") {
		t.Errorf("the stored reason should carry no numbers: %q", before)
	}

	// A count reads naturally for smaller amounts.
	c2, _ := newClassifier(t)
	c2.ObserveDevice("tv", "", nil, false)
	c2.SetResolver(func(string) string { return "tv" })
	look(c2, "192.0.2.52", "www.netflix.com", "198.51.100.6", 1)
	look(c2, "192.0.2.52", "www.disneyplus.com", "198.51.100.6", 1)
	look(c2, "192.0.2.52", "x.example.com", "203.0.113.1", 1)
	r2 := c2.Classify("tv")
	if !strings.Contains(strings.Join(r2.Reasons, "|"), "2 lookups to a streaming service") {
		t.Errorf("reasons = %v", r2.Reasons)
	}
}

func TestRandomizedMACHidesTheVendor(t *testing.T) {
	c, _ := newClassifier(t)
	c.ObserveDevice("priv", "Sonos", []string{}, true) // a vendor that would say speaker, if it could be trusted
	r := c.Classify("priv")
	if r.Type != devices.TypeUnknown {
		t.Errorf("a private address must not be classified by vendor: %s", describe(r))
	}
	if !strings.Contains(strings.Join(r.Reasons, "|"), "private (randomized) address") {
		t.Errorf("the private address should be mentioned: %v", r.Reasons)
	}
	if r.Score(devices.TypeSpeaker) != 0 {
		t.Error("vendor evidence must be ignored for randomized MACs")
	}
	c.ObserveDevice("priv", "Sonos", nil, false)
	if r := c.Classify("priv"); r.Type != devices.TypeSpeaker {
		t.Errorf("the same vendor on a real MAC is a speaker: %s", describe(r))
	}
}

// ASN evidence is weak by design: alone it never names a device, and it never
// outvotes a domain.
func TestASNEvidenceIsWeakAndNeverOutvotesDomains(t *testing.T) {
	c, _ := newClassifier(t)
	c.ObserveDevice("a", "", nil, false)
	c.SetResolver(func(string) string { return "a" })
	for i := 0; i < 500; i++ {
		c.Observe("192.0.2.60", "n"+string(rune('a'+i%26))+".example.com", ips("198.51.100.7", "198.51.100.8"))
	}
	r := c.Classify("a")
	if r.Type != devices.TypeUnknown {
		t.Fatalf("ASN evidence alone named a device: %s", describe(r))
	}
	if s := r.Score(devices.TypeTV); s <= 0 || s > asnCap {
		t.Errorf("ASN-only TV score %.2f must be positive but at most the cap %.2f", s, asnCap)
	}
	if !strings.Contains(strings.Join(r.Reasons, "|"), "resolve to a streaming network") {
		t.Errorf("the network should be mentioned: %v", r.Reasons)
	}

	// Strong domain evidence for a different class wins even when every
	// answer sits on a TV network.
	c2, _ := newClassifier(t)
	c2.ObserveDevice("b", "", nil, false)
	c2.SetResolver(func(string) string { return "b" })
	for i := 0; i < 100; i++ {
		c2.Observe("192.0.2.61", "ius.hik-connect.com", ips("198.51.100.7"))
		c2.Observe("192.0.2.61", "x"+string(rune('a'+i%26))+".example.net", ips("198.51.100.8"))
	}
	r2 := c2.Classify("b")
	mustType(t, r2.Type, devices.TypeCamera, describe(r2))
	if r2.Score(devices.TypeTV) >= r2.Score(devices.TypeCamera) {
		t.Errorf("ASN hint outvoted a domain: tv %.2f camera %.2f", r2.Score(devices.TypeTV), r2.Score(devices.TypeCamera))
	}

	// Together with a manufacturer prior the weak hint adds to a borderline
	// device, which is what it is for, but it is a nudge, not a verdict.
	c3, _ := newClassifier(t)
	c3.ObserveDevice("c", "TCL", nil, false) // TCL: tv 0.45, below the threshold alone
	c3.SetResolver(func(string) string { return "c" })
	before := c3.Classify("c")
	mustType(t, before.Type, devices.TypeUnknown, describe(before))
	for i := 0; i < 200; i++ {
		c3.Observe("192.0.2.62", "e"+string(rune('a'+i%26))+".example.com", ips("198.51.100.7"))
	}
	after := c3.Classify("c")
	if !(after.Score(devices.TypeTV) > before.Score(devices.TypeTV)) {
		t.Errorf("the network should add to the TV score: %.2f -> %.2f", before.Score(devices.TypeTV), after.Score(devices.TypeTV))
	}
	if after.Score(devices.TypeTV)-before.Score(devices.TypeTV) > asnCap {
		t.Errorf("the network added more than its cap")
	}
}

// Shared CDN and cloud networks carry no weight and are not mistaken for evidence.
func TestSharedNetworksSayNothing(t *testing.T) {
	c, _ := newClassifier(t)
	c.SetResolver(func(string) string { return "s" })
	c.ObserveDevice("s", "", nil, false)
	for i := 0; i < 300; i++ {
		c.Observe("192.0.2.63", "h"+string(rune('a'+i%26))+".example.com", ips("203.0.113.5", "2001:db8::9"))
	}
	r := c.Classify("s")
	mustType(t, r.Type, devices.TypeUnknown, describe(r))
	if len(r.scores) != 0 {
		t.Errorf("shared networks produced evidence: %v", r.scores)
	}
	sh := c.st.shardFor("s")
	e := sh.m["s"]
	if e.shared < 100 {
		t.Errorf("shared answers should be tallied, got %v", e.shared)
	}
}

func TestConflictingStrongEvidenceLowersConfidence(t *testing.T) {
	solo, _ := newClassifier(t)
	solo.ObserveDevice("x", "", nil, false)
	solo.SetResolver(func(string) string { return "x" })
	look(solo, "192.0.2.64", "ius.hik-connect.com", "203.0.113.10", 50)
	r1 := solo.Classify("x")

	mixed, _ := newClassifier(t)
	mixed.ObserveDevice("x", "", nil, false)
	mixed.SetResolver(func(string) string { return "x" })
	look(mixed, "192.0.2.64", "ius.hik-connect.com", "203.0.113.10", 50)
	look(mixed, "192.0.2.64", "update.sonos.com", "203.0.113.11", 4)
	r2 := mixed.Classify("x")
	if !(r2.Confidence < r1.Confidence) {
		t.Errorf("a competing class should lower confidence: %.2f vs %.2f", r2.Confidence, r1.Confidence)
	}
	if len(r2.Alternatives) == 0 || r2.Alternatives[0].Type != devices.TypeSpeaker {
		t.Errorf("the runner-up should be listed: %v", r2.Alternatives)
	}
	if !strings.Contains(strings.Join(r2.Reasons, "|"), "also points to a speaker") {
		t.Errorf("the conflict should be explained: %v", r2.Reasons)
	}
	// Close relatives (TV and streaming box) are not a real conflict.
	rel, _ := newClassifier(t)
	rel.ObserveDevice("x", "", nil, false)
	rel.SetResolver(func(string) string { return "x" })
	look(rel, "192.0.2.64", "www.netflix.com", "203.0.113.10", 50)
	look(rel, "192.0.2.64", "www.hulu.com", "203.0.113.10", 50)
	r3 := rel.Classify("x")
	mustType(t, r3.Type, devices.TypeTV, describe(r3))
}

func TestUnknownEmptyAndForgotten(t *testing.T) {
	c, _ := newClassifier(t)
	r := c.Classify("nobody")
	mustType(t, r.Type, devices.TypeUnknown, describe(r))
	if r.Confidence != 0 || len(r.Reasons) != 1 || r.Summary() == "" {
		t.Errorf("empty result = %+v", r)
	}
	c.ObserveDevice("d", "", nil, false)
	r = c.Classify("d")
	mustType(t, r.Type, devices.TypeUnknown, describe(r))
	c.Forget("d")
	if _, ok := c.Retained("d"); ok {
		t.Error("Forget must drop the device")
	}
}
