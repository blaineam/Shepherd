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
