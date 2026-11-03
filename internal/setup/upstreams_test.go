// SPDX-License-Identifier: AGPL-3.0-or-later

package setup

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeProbe answers in the given time per address, or fails when the
// duration is negative, so a test can describe a resolver's behaviour the
// way the owner would experience it.
func fakeProbe(by map[string]time.Duration) func(context.Context, string) error {
	return func(_ context.Context, addr string) error {
		d, ok := by[addr]
		if !ok {
			return errors.New("no route to " + addr)
		}
		if d < 0 {
			return errors.New(addr + " did not answer")
		}
		time.Sleep(d)
		return nil
	}
}

func byID(ms []Measurement, id string) Measurement {
	for _, m := range ms {
		if m.ID == id {
			return m
		}
	}
	return Measurement{}
}

func TestMeasurePrefersEncryptedFilteringWhenItAnswersWell(t *testing.T) {
	// The point of measuring: a resolver that protects more is preferred,
	// but only while it actually answers from this house.
	ms := Measure(context.Background(), Candidates, fakeProbe(map[string]time.Duration{
		"tls://dns.quad9.net":               2 * time.Millisecond,
		"tls://security.cloudflare-dns.com": 2 * time.Millisecond,
		"tls://cloudflare-dns.com":          time.Millisecond,
		"1.1.1.1":                           0,
		"1.0.0.1":                           0,
		"8.8.8.8":                           0,
		"8.8.4.4":                           0,
		"9.9.9.9":                           0,
		"149.112.112.112":                   0,
		"9.9.9.10":                          0,
		"149.112.112.10":                    0,
	}))
	if len(ms) != len(Candidates) {
		t.Fatalf("measured %d of %d", len(ms), len(Candidates))
	}
	if !ms[0].Recommended || !ms[0].Encrypted || !ms[0].Filters {
		t.Errorf("the recommendation should be encrypted and filtering, got %+v", ms[0])
	}
	// Plain resolvers answering in no time at all must not outrank it:
	// the trade this makes is deliberate.
	plain := byID(ms, "cloudflare")
	if plain.Recommended {
		t.Error("a plain resolver was recommended over an encrypted filtering one")
	}
	if !plain.OK || plain.Probes != 2*probesPer {
		t.Errorf("every address should have been probed: %+v", plain)
	}
	// Exactly one recommendation, or the page has nothing to tick.
	n := 0
	for _, m := range ms {
		if m.Recommended {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d recommendations", n)
	}
}

func TestMeasureSinksAnythingThatLostAProbe(t *testing.T) {
	// A dropped query is a device that waits and then goes elsewhere, so
	// reliability outranks everything, including being encrypted.
	ms := Measure(context.Background(), Candidates, fakeProbe(map[string]time.Duration{
		"tls://dns.quad9.net":               -1, // drops
		"tls://security.cloudflare-dns.com": -1,
		"tls://cloudflare-dns.com":          -1,
		"9.9.9.9":                           time.Millisecond,
		"149.112.112.112":                   time.Millisecond,
		"1.1.1.1":                           0,
		"1.0.0.1":                           0,
		"8.8.8.8":                           0,
		"8.8.4.4":                           0,
		"9.9.9.10":                          0,
		"149.112.112.10":                    0,
	}))
	rec := ms[0]
	if !rec.Recommended || rec.Encrypted {
		t.Errorf("a resolver that lost probes should not be recommended: %+v", rec)
	}
	lost := byID(ms, "quad9-dot")
	if lost.OK || lost.Lost != probesPer || lost.Error == "" {
		t.Errorf("the failing resolver should say so: %+v", lost)
	}
	// Its failure is reported, not hidden, so the owner can see why the
	// one they might have expected was not chosen.
	for _, m := range ms {
		if m.ID == "quad9-dot" && m.Recommended {
			t.Error("a resolver that answered nothing was recommended")
		}
	}
}

func TestMeasurePassesOverAnEncryptedResolverThatIsTooSlow(t *testing.T) {
	// Preferring encryption is not worth paying for on every uncached
	// lookup; past slowMs a quick plain resolver is the better trade.
	slow := time.Duration(slowMs+50) * time.Millisecond
	ms := Measure(context.Background(), []Candidate{
		{ID: "slow-dot", Name: "Slow DoT", Encrypted: true, Filters: true, Addrs: []string{"tls://slow.example.com"}},
		{ID: "quick", Name: "Quick plain", Addrs: []string{"192.0.2.10"}},
	}, fakeProbe(map[string]time.Duration{
		"tls://slow.example.com": slow,
		"192.0.2.10":             time.Millisecond,
	}))
	if ms[0].ID != "quick" || !ms[0].Recommended {
		t.Errorf("the quick one should win: %+v", ms)
	}
	if got := byID(ms, "slow-dot"); !got.OK || got.MedianMs < slowMs {
		t.Errorf("the slow one should still be offered, with its number: %+v", got)
	}
}

func TestMeasureWithNothingAnsweringRecommendsNothing(t *testing.T) {
	ms := Measure(context.Background(), Candidates, func(context.Context, string) error {
		return errors.New("the uplink is down")
	})
	for _, m := range ms {
		if m.Recommended {
			t.Errorf("%s was recommended with nothing answering", m.ID)
		}
		if m.OK || m.Error == "" {
			t.Errorf("%+v", m)
		}
	}
}

func TestMeasureWithoutAProbeJustListsThem(t *testing.T) {
	// A build that cannot test still has to offer the choice.
	ms := Measure(context.Background(), Candidates, nil)
	if len(ms) != len(Candidates) {
		t.Fatalf("measured %d", len(ms))
	}
	for _, m := range ms {
		if m.OK || m.Probes != 0 || m.Recommended {
			t.Errorf("%+v should carry no measurement", m)
		}
	}
}

func TestMeasureStopsWhenTheOwnerGivesUp(t *testing.T) {
	// The page is waiting on this, so a cancelled request must not keep
	// probing a resolver that is not going to answer.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ms := Measure(ctx, Candidates, func(context.Context, string) error {
		t.Error("no probe should have been sent")
		return nil
	})
	if len(ms) != len(Candidates) {
		t.Errorf("measured %d", len(ms))
	}
}

func TestMedianOfWhatAnswered(t *testing.T) {
	if got := median(nil); got != 0 {
		t.Errorf("median(nil) = %v", got)
	}
	if got := median([]float64{3, 1, 2}); got != 2 {
		t.Errorf("odd median = %v", got)
	}
	if got := median([]float64{4, 1, 3, 2}); got != 2.5 {
		t.Errorf("even median = %v", got)
	}
}

func TestEveryCandidateIsUsable(t *testing.T) {
	// A typo in this list is a resolver nobody can use, found at the
	// worst possible moment.
	seen := map[string]bool{}
	for _, c := range Candidates {
		if c.ID == "" || c.Name == "" || c.Note == "" || len(c.Addrs) == 0 {
			t.Errorf("incomplete candidate: %+v", c)
		}
		if seen[c.ID] {
			t.Errorf("duplicate candidate id %q", c.ID)
		}
		seen[c.ID] = true
	}
	// The ones setup leads with have to exist, or the whole preference is
	// theory.
	var encryptedFiltering int
	for _, c := range Candidates {
		if c.Encrypted && c.Filters {
			encryptedFiltering++
		}
	}
	if encryptedFiltering < 2 {
		t.Errorf("only %d encrypted filtering candidates", encryptedFiltering)
	}
}

func TestRankEndpointReturnsWhatThePageDraws(t *testing.T) {
	r := newRig(t)
	got := r.json("POST", "/api/setup/upstream-rank", "", 200)
	results, _ := got["results"].([]any)
	if len(results) != len(Candidates) {
		t.Fatalf("results = %v", got["results"])
	}
	first, _ := results[0].(map[string]any)
	if first["recommended"] != true || first["name"] == nil || first["median_ms"] == nil {
		t.Errorf("the page needs the numbers the ranking was made from: %v", first)
	}
}
