// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import (
	"errors"
	"math/rand"
	"net/netip"
	"testing"
)

func TestMACHelpers(t *testing.T) {
	m, err := ParseMAC("02:00:5E:00:00:0a")
	if err != nil || m != (MAC{2, 0, 0x5e, 0, 0, 10}) {
		t.Fatalf("ParseMAC = %v, %v", m, err)
	}
	if m.String() != "02:00:5e:00:00:0a" {
		t.Fatalf("String = %s", m)
	}
	for _, bad := range []string{"", "02:00:5e:00:00", "02-00-5e-00-00-0a", "zz:00:5e:00:00:0a", "02:00:5e:00:00:0g"} {
		if _, err := ParseMAC(bad); err == nil {
			t.Errorf("ParseMAC(%q) accepted", bad)
		}
	}
	if !(MAC{}).IsZero() || !Broadcast.IsMulticast() || !(MAC{1, 0, 0x5e, 0, 0, 1}).IsMulticast() {
		t.Error("zero/multicast predicates")
	}
	if !rnd(1).IsLocallyAdministered() || stable(1).IsLocallyAdministered() {
		t.Error("locally administered predicate")
	}
	if stable(1).usable() != true || Broadcast.usable() || (MAC{}).usable() {
		t.Error("usable")
	}
}

func TestKinds(t *testing.T) {
	cases := []struct {
		f    Frame
		want Kind
		grat bool
		name string
	}{
		{NewRequest(stable(1), ip(10), ip(1)), KindRequest, false, "request"},
		{NewReply(stable(1), ip(1), stable(2), ip(10)), KindReply, false, "reply"},
		{NewProbe(stable(1), ip(10)), KindProbe, false, "probe"},
		{NewAnnounce(stable(1), ip(10)), KindAnnounce, true, "announce"},
		{NewGratuitousReply(stable(1), ip(10)), KindGratuitousReply, true, "gratuitous-reply"},
		{Frame{Op: 9}, KindUnknown, false, "unknown"},
	}
	for _, c := range cases {
		if c.f.Kind() != c.want || c.f.IsGratuitous() != c.grat || c.want.String() != c.name {
			t.Errorf("%s: kind=%v grat=%v", c.name, c.f.Kind(), c.f.IsGratuitous())
		}
	}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	frames := []Frame{
		NewRequest(stable(1), ip(10), ip(1)),
		NewReply(stable(1), ip(1), stable(2), ip(10)),
		NewProbe(rnd(3), ip(20)),
		NewAnnounce(stable(4), ip(30)),
		NewGratuitousReply(stable(5), ip(40)),
	}
	tagged := NewRequest(stable(6), ip(50), ip(1))
	tagged.Tagged, tagged.VLAN = true, 42
	frames = append(frames, tagged)
	for _, f := range frames {
		b, err := f.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if len(b) < 60 {
			t.Fatalf("not padded: %d", len(b))
		}
		got, err := ParseFrame(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != f {
			t.Errorf("round trip\n got %+v\nwant %+v", got, f)
		}
	}
}

func TestMarshalRejectsBadFrames(t *testing.T) {
	good := NewRequest(stable(1), ip(10), ip(1))
	bad := []Frame{good, good, good}
	bad[0].SenderIP = netip.MustParseAddr("2001:db8::1")
	bad[1].Op = 7
	bad[2].Tagged, bad[2].VLAN = true, 5000
	for i, f := range bad {
		if _, err := f.Marshal(); err == nil {
			t.Errorf("case %d marshalled", i)
		}
	}
	if _, err := (Frame{Op: OpRequest}).Marshal(); err == nil {
		t.Error("zero addresses marshalled")
	}
}

func valid(t *testing.T) []byte {
	b, err := NewRequest(stable(1), ip(10), ip(1)).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseErrors(t *testing.T) {
	b := valid(t)
	mut := func(f func([]byte) []byte) []byte { return f(append([]byte(nil), b...)) }
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrMalformed},
		{"short ethernet", b[:13], ErrMalformed},
		{"truncated body", b[:14+27], ErrMalformed},
		{"ipv4 ethertype", mut(func(x []byte) []byte { x[12], x[13] = 0x08, 0x00; return x }), ErrNotARP},
		{"truncated vlan", mut(func(x []byte) []byte { x[12], x[13] = 0x81, 0x00; return x[:16] }), ErrMalformed},
		{"qinq", mut(func(x []byte) []byte {
			x[12], x[13], x[16], x[17] = 0x81, 0x00, 0x88, 0xa8
			return x
		}), ErrNotARP},
		{"hardware type", mut(func(x []byte) []byte { x[15] = 6; return x }), ErrNotARP},
		{"protocol type", mut(func(x []byte) []byte { x[16] = 0x86; return x }), ErrNotARP},
		{"hlen", mut(func(x []byte) []byte { x[18] = 8; return x }), ErrMalformed},
		{"plen", mut(func(x []byte) []byte { x[19] = 16; return x }), ErrMalformed},
		{"op", mut(func(x []byte) []byte { x[21] = 3; return x }), ErrMalformed},
	}
	for _, c := range cases {
		if _, err := ParseFrame(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestVLANTagParsed(t *testing.T) {
	f := NewRequest(stable(1), ip(10), ip(1))
	f.Tagged, f.VLAN = true, 7
	b, _ := f.Marshal()
	got, err := ParseFrame(b)
	if err != nil || !got.Tagged || got.VLAN != 7 || got.SenderIP != ip(10) {
		t.Fatalf("got %+v err %v", got, err)
	}
}

// Random and truncated input must never panic.
func TestParseNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	b := valid(t)
	for i := 0; i < 50000; i++ {
		buf := make([]byte, rng.Intn(80))
		rng.Read(buf)
		ParseFrame(buf)
		// A valid frame with random corruption and random truncation.
		c := append([]byte(nil), b...)
		for j := rng.Intn(4); j > 0; j-- {
			c[rng.Intn(len(c))] = byte(rng.Intn(256))
		}
		ParseFrame(c[:rng.Intn(len(c)+1)])
	}
	for n := 0; n <= len(b); n++ {
		ParseFrame(b[:n])
	}
}

func FuzzParseFrame(f *testing.F) {
	good, _ := NewRequest(stable(1), ip(10), ip(1)).Marshal()
	f.Add(good)
	f.Add([]byte{})
	f.Add(good[:20])
	f.Fuzz(func(t *testing.T, in []byte) {
		fr, err := ParseFrame(in)
		if err == nil {
			if _, err := fr.Marshal(); err != nil {
				t.Fatalf("parsed frame does not marshal: %v", err)
			}
		}
	})
}
