// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"testing"
	"time"

	"shepherd/internal/intercept"
)

func TestStatsRateComputesPerSecondDeltas(t *testing.T) {
	prev := intercept.ControllerStats{
		FramesExamined:          100,
		BytesExamined:           10_000,
		FramesNotForShepherd:    20,
		FramesForShepherdItself: 5,
		FramesRelayed:           80,
		BytesRelayed:            8_000,
	}
	cur := intercept.ControllerStats{
		FramesExamined:          100 + 200,
		BytesExamined:           10_000 + 20_000,
		FramesNotForShepherd:    20 + 50,
		FramesForShepherdItself: 5 + 7,
		FramesRelayed:           80 + 150,
		BytesRelayed:            8_000 + 15_000,
	}
	got := statsRate(prev, cur, 2*time.Second)
	want := "examined=100 pkt/s relayed=75 pkt/s (7500 B/s) not_for_shepherd=50 for_shepherd_itself=7"
	if got != want {
		t.Fatalf("statsRate = %q, want %q", got, want)
	}
}

func TestStatsRateHandlesZeroElapsedWithoutDividingByZero(t *testing.T) {
	var s intercept.ControllerStats
	want := "n/a (no time elapsed)"
	if got := statsRate(s, s, 0); got != want {
		t.Fatalf("statsRate with zero elapsed = %q, want %q", got, want)
	}
	if got := statsRate(s, s, -time.Second); got != want {
		t.Fatalf("statsRate with negative elapsed = %q, want %q", got, want)
	}
}

func TestFormatSinceZeroAndNonZero(t *testing.T) {
	if got := formatSince(time.Time{}); got != "never" {
		t.Fatalf("formatSince(zero) = %q, want %q", got, "never")
	}
	past := time.Now().Add(-5 * time.Second)
	if got := formatSince(past); got == "never" {
		t.Fatal("formatSince(non-zero) must not report never")
	}
}
