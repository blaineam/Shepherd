// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"strings"
	"testing"
)

// sampleFrame builds the first 60 bytes of an IPv4 TCP frame with the
// given IP ID and TTL, from 02:00:00:00:00:01 to 02:00:00:00:00:02.
func sampleFrame(id uint16, ttl uint8, src, dst [4]byte) FrameSample {
	b := make([]byte, 60)
	copy(b[0:6], []byte{2, 0, 0, 0, 0, 2})
	copy(b[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	b[14] = 0x45
	binary.BigEndian.PutUint16(b[16:18], 1500)
	binary.BigEndian.PutUint16(b[18:20], id)
	b[22] = ttl
	b[23] = 6
	copy(b[26:30], src[:])
	copy(b[30:34], dst[:])
	binary.BigEndian.PutUint16(b[34:36], 51000)
	binary.BigEndian.PutUint16(b[36:38], 443)
	return FrameSample{Seq: uint64(id), Len: 1514, Bytes: b}
}

func TestSummarizeSamplesTellsALoopFromTraffic(t *testing.T) {
	phone := [4]byte{192, 0, 2, 37}
	site := [4]byte{198, 51, 100, 7}

	t.Run("fresh ids are traffic", func(t *testing.T) {
		var s []FrameSample
		for i := uint16(1); i <= 10; i++ {
			s = append(s, sampleFrame(1000+i, 64, phone, site))
		}
		lines := SummarizeSamples(s)
		if len(lines) != 2 {
			t.Fatalf("lines = %q", lines)
		}
		if !strings.Contains(lines[0], "10 sampled frames in 1 flows") {
			t.Errorf("header = %q", lines[0])
		}
		if !strings.Contains(lines[1], "distinct ids") || !strings.Contains(lines[1], "ttl 64") || !strings.Contains(lines[1], "10 ids") {
			t.Errorf("flow line = %q", lines[1])
		}
		if !strings.Contains(lines[1], "192.0.2.37->198.51.100.7 :51000->:443") {
			t.Errorf("flow line = %q", lines[1])
		}
	})

	t.Run("one id with falling ttl is a router loop", func(t *testing.T) {
		var s []FrameSample
		for ttl := uint8(64); ttl > 54; ttl-- {
			s = append(s, sampleFrame(777, ttl, phone, site))
		}
		lines := SummarizeSamples(s)
		if !strings.Contains(lines[1], "FALLING TTL") || !strings.Contains(lines[1], "ttl 55-64") || !strings.Contains(lines[1], "1 ids") {
			t.Errorf("flow line = %q", lines[1])
		}
	})

	t.Run("one id with one ttl is a layer 2 loop", func(t *testing.T) {
		var s []FrameSample
		for i := 0; i < 10; i++ {
			s = append(s, sampleFrame(777, 64, phone, site))
		}
		lines := SummarizeSamples(s)
		if !strings.Contains(lines[1], "SAME TTL: circulating at layer 2") {
			t.Errorf("flow line = %q", lines[1])
		}
	})

	t.Run("non-ipv4 and short samples are counted, not parsed", func(t *testing.T) {
		s := []FrameSample{{Bytes: []byte{1, 2, 3}}, sampleFrame(1, 64, phone, site)}
		s[0].Bytes = make([]byte, 60) // ethertype 0
		lines := SummarizeSamples(s)
		if !strings.Contains(lines[0], "(1 not IPv4)") {
			t.Errorf("header = %q", lines[0])
		}
	})

	if SummarizeSamples(nil) != nil {
		t.Error("nil samples must summarize to nothing")
	}
}

// With no in-kernel relay attached -- the userspace relay, or nothing
// attached yet -- the sampling accessors report nothing rather than
// guessing. The engine logs these only when they are non-zero, so this is
// the path a userspace relay takes every second.
func TestSamplingAccessorsReportNothingWithoutAnInKernelRelay(t *testing.T) {
	c, _, _ := newTestController(t, nil)

	if got := c.FrameSamples(); got != nil {
		t.Errorf("FrameSamples() = %v, want nil with no relay attached", got)
	}
	if ours, gw := c.ReturnPathCounts(); ours != 0 || gw != 0 {
		t.Errorf("ReturnPathCounts() = (%d, %d), want (0, 0)", ours, gw)
	}
	if got := c.DuplicatesSuppressed(); got != 0 {
		t.Errorf("DuplicatesSuppressed() = %d, want 0", got)
	}
	if got := c.DuplicatesByDevice(); len(got) != 0 {
		t.Errorf("DuplicatesByDevice() = %v, want empty", got)
	}

	// A data plane that is not a frameSampler is also handled: the
	// interface is optional on purpose, so a future data plane need not
	// implement it to be usable.
	c.setObserver(notASampler{})
	defer c.setObserver(nil)
	if got := c.FrameSamples(); got != nil {
		t.Errorf("FrameSamples() = %v, want nil for a data plane that does not sample", got)
	}
	if got := c.DuplicatesSuppressed(); got != 0 {
		t.Errorf("DuplicatesSuppressed() = %d, want 0 for a data plane that does not sample", got)
	}
	if got := c.DuplicatesByDevice(); len(got) != 0 {
		t.Errorf("DuplicatesByDevice() = %v, want empty for a data plane that does not sample", got)
	}
	if ours, gw := c.ReturnPathCounts(); ours != 0 || gw != 0 {
		t.Errorf("ReturnPathCounts() = (%d, %d), want (0, 0) for a data plane that does not sample", ours, gw)
	}
}

// notASampler is a steered-set observer with no sampling, which is what a
// data plane other than the XDP one looks like.
type notASampler struct{}

func (notASampler) steeredSetChanged([]steeredEntry) {}

// EchoDelays.Verdict is what points the next person at a culprit, so a
// wrong threshold here misleads rather than merely underperforms. Each
// shape is checked, and so is its refusal to speak from a handful.
func TestEchoDelaysVerdictPointsAtTheRightPlace(t *testing.T) {
	cases := []struct {
		name string
		d    EchoDelays
		want string
	}{
		{"too few samples to say anything", EchoDelays{Under10us: 49}, ""},
		{"nothing at all", EchoDelays{}, ""},
		{
			"almost all under 10us: it never left the machine",
			EchoDelays{Under10us: 900, Under100us: 50, Under1ms: 50},
			"look at the host, not the network",
		},
		{
			"tens of microseconds: a wired switch sending it back",
			EchoDelays{Under10us: 9, Under100us: 17093, Under1ms: 4229, Under10ms: 6},
			"consistent with a wired switch sending it straight back",
		},
		{
			"hundreds of microseconds: a round trip through the router",
			EchoDelays{Under100us: 100, Under1ms: 900},
			"consistent with a round trip through the router",
		},
		{
			"milliseconds: a wireless hop or a mesh backhaul",
			EchoDelays{Under100us: 100, Under10ms: 600, Over10ms: 300},
			"wireless hop or a mesh backhaul",
		},
		{
			"spread across the buckets, so more than one path",
			EchoDelays{Under10us: 200, Under100us: 300, Under1ms: 300, Under10ms: 100, Over10ms: 100},
			"more than one path may be returning frames",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.d.Verdict()
			if tc.want == "" {
				if got != "" {
					t.Fatalf("Verdict() = %q, want silence from %d samples", got, tc.d.Total())
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("Verdict() = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

func TestEchoDelaysTotalAndString(t *testing.T) {
	d := EchoDelays{Under10us: 1, Under100us: 2, Under1ms: 3, Under10ms: 4, Over10ms: 5}
	if got := d.Total(); got != 15 {
		t.Errorf("Total() = %d, want 15", got)
	}
	if got := (EchoDelays{}).Total(); got != 0 {
		t.Errorf("Total() of nothing = %d, want 0", got)
	}
	// Every bucket has to appear, since this line is read as the record of
	// what was measured.
	s := d.String()
	for _, want := range []string{"<10us:1", "<100us:2", "<1ms:3", "<10ms:4", ">10ms:5"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
}
