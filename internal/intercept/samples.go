// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"

	"shepherd/internal/arp"
)

// FrameSample is the start of one frame the in-kernel relay carried, as it
// arrived and before either MAC was rewritten. The XDP program records
// every 256th relayed frame per CPU into a small ring; FrameSamples drains
// it. A frame the program bounces back out with XDP_TX never reaches an
// AF_PACKET socket, so this is the only way to see what the relay is
// relaying -- and the question "what was that storm made of" has twice had
// to be answered by inference instead.
type FrameSample struct {
	Seq   uint64 // monotonic across the session; the ring overwrites oldest first
	Ts    uint64 // bpf_ktime_get_ns (CLOCK_MONOTONIC), nanoseconds
	Len   uint32 // the frame's full length on the wire
	Bytes []byte // its first 60 bytes: Ethernet, IPv4 and the start of the transport header
}

// frameSampler is implemented by a data plane that can produce samples.
type frameSampler interface {
	frameSamples() []FrameSample
	returnPathCounts() (oursReturning, toGateway uint64)
	duplicatesSuppressed() uint64
	duplicatesByDevice() map[arp.MAC]uint64
	echoDelays() EchoDelays
}

// EchoDelays is how long echoed frames took to come back, bucketed. It is
// the measurement that says *where* an echo comes from, which nothing else
// in this package has settled.
//
// A frame that never left the machine comes back in microseconds. One that
// reached a switch and was sent back takes hundreds of microseconds. One
// that crossed a wireless hop or a mesh backhaul takes longer again. So the
// shape of this histogram points at a culprit the host's own counters
// cannot name: heavy in the first bucket is something local, heavy in the
// middle is the switch, heavy at the end is the wireless side.
type EchoDelays struct {
	Under10us  uint64 `json:"under_10us"`
	Under100us uint64 `json:"under_100us"`
	Under1ms   uint64 `json:"under_1ms"`
	Under10ms  uint64 `json:"under_10ms"`
	Over10ms   uint64 `json:"over_10ms"`
}

// Total is every echoed frame the histogram counted.
func (d EchoDelays) Total() uint64 {
	return d.Under10us + d.Under100us + d.Under1ms + d.Under10ms + d.Over10ms
}

// String reads as the histogram it is, for a log line.
func (d EchoDelays) String() string {
	return fmt.Sprintf("<10us:%d <100us:%d <1ms:%d <10ms:%d >10ms:%d",
		d.Under10us, d.Under100us, d.Under1ms, d.Under10ms, d.Over10ms)
}

// Verdict names what the shape points at, or "" when there is too little
// to say. It is deliberately a pointer rather than a conclusion: it says
// where to look, not what happened.
func (d EchoDelays) Verdict() string {
	total := d.Total()
	if total < 50 {
		return ""
	}
	switch {
	case float64(d.Under10us) >= 0.8*float64(total):
		return "the echo returns in under 10us, which is too fast to have left this machine: look at the host, not the network"
	case float64(d.Under10us+d.Under100us) >= 0.8*float64(total):
		return "the echo returns in tens of microseconds, consistent with a wired switch sending it straight back"
	case float64(d.Under1ms) >= 0.5*float64(total):
		return "the echo returns in hundreds of microseconds, consistent with a round trip through the router"
	case float64(d.Under10ms+d.Over10ms) >= 0.5*float64(total):
		return "the echo takes milliseconds, consistent with a wireless hop or a mesh backhaul carrying it back"
	}
	return "the echo's delay is spread across the buckets, so more than one path may be returning frames"
}

// FrameSamples returns the relayed-frame samples recorded since the
// previous call, oldest first, or nil where the data plane in use does not
// sample (the userspace relay, or no relay attached).
func (c *Controller) FrameSamples() []FrameSample {
	o := c.observer.Load()
	if o == nil {
		return nil
	}
	s, ok := (*o).(frameSampler)
	if !ok {
		return nil
	}
	return s.frameSamples()
}

// ReturnPathCounts reports how many frames this interface has received
// that Shepherd itself transmitted: ones with its own source MAC, and ones
// addressed to the gateway's MAC. A relayed frame leaves with both, so
// either arriving back is Shepherd's output returning to the interface it
// left -- the substance of a relay loop. Zero, zero where the data plane in
// use does not count them (the userspace relay, or no relay attached).
func (c *Controller) ReturnPathCounts() (oursReturning, toGateway uint64) {
	o := c.observer.Load()
	if o == nil {
		return 0, 0
	}
	s, ok := (*o).(frameSampler)
	if !ok {
		return 0, 0
	}
	return s.returnPathCounts()
}

// DuplicatesSuppressed is how many frames the relay has refused to relay
// because it had already relayed the same frame inside its duplicate
// window -- the same frame coming round, which is what a relay loop is
// made of. A healthy relay reports zero, for as long as it runs. Zero
// where the data plane in use does not count them.
func (c *Controller) DuplicatesSuppressed() uint64 {
	n := c.duplicatesTotal.Load() // the userspace relay's own brake
	o := c.observer.Load()
	if o == nil {
		return n
	}
	s, ok := (*o).(frameSampler)
	if !ok {
		return n
	}
	return n + s.duplicatesSuppressed()
}

// EchoDelays reports how long echoed frames took to come back. Zero values
// where the data plane in use does not measure it.
func (c *Controller) EchoDelays() EchoDelays {
	o := c.observer.Load()
	if o == nil {
		return EchoDelays{}
	}
	s, ok := (*o).(frameSampler)
	if !ok {
		return EchoDelays{}
	}
	return s.echoDelays()
}

// DuplicatesByDevice is each steered device's share of the frames the
// relay refused as duplicates, keyed by MAC and omitting devices with
// none. The global DuplicatesSuppressed count cannot say whether a loop
// belongs to one device or to all of them, and that is the question still
// open about what re-delivers the frames (docs/WATCH.md). Empty where the
// data plane in use does not count them.
func (c *Controller) DuplicatesByDevice() map[arp.MAC]uint64 {
	var out map[arp.MAC]uint64
	for _, d := range c.Status() { // the userspace relay's own brake
		if d.DuplicatesSuppressed == 0 {
			continue
		}
		if out == nil {
			out = map[arp.MAC]uint64{}
		}
		out[d.MAC] += d.DuplicatesSuppressed
	}
	o := c.observer.Load()
	if o == nil {
		return out
	}
	s, ok := (*o).(frameSampler)
	if !ok {
		return out
	}
	for mac, n := range s.duplicatesByDevice() {
		if out == nil {
			out = map[arp.MAC]uint64{}
		}
		out[mac] += n
	}
	return out
}

// sampleFlow is what SummarizeSamples groups by: who sent it, where it was
// going, and the two header fields a loop would reveal. A frame circulating
// through a router loses one TTL per pass and keeps its IP ID; one
// circulating at Layer 2 keeps both; genuinely new traffic has fresh IDs.
type sampleFlow struct {
	src, dst arp.MAC
	proto    string
	srcIP    netip.Addr
	dstIP    netip.Addr
	srcPort  uint16
	dstPort  uint16
}

// SummarizeSamples reduces a batch of samples to a few log lines: the
// busiest flows, with their TTL range and how many distinct IP IDs they
// carried. Repeated IDs with falling TTLs are a frame going round through
// a router; repeated IDs with one TTL are a Layer 2 loop; all-distinct IDs
// are traffic. It never logs payload -- only addresses, ports, TTL and ID.
func SummarizeSamples(samples []FrameSample) []string {
	lines, _ := AnalyzeSamples(samples)
	return lines
}

// AnalyzeSamples is SummarizeSamples with its conclusion as a value:
// circulating is true when at least one flow's samples are the *same
// frame* seen over and over, which is what a relay loop is made of.
//
// "The same frame" means identical in the identification field, the
// total length, the TTL and the first sixteen bytes of the transport
// header -- not merely the same identification field. That distinction
// is the whole verdict: macOS, iOS and Linux (for an unconnected socket)
// send every don't-fragment packet with identification 0, so a stream of
// distinct QUIC or TCP packets from such a device shares one ID and one
// TTL while being thousands of different packets. Judged by the ID alone
// that reads as a loop, and the loop brake once stopped an overnight
// iCloud upload on that reading (docs/WATCH.md).
func AnalyzeSamples(samples []FrameSample) (lines []string, circulating bool) {
	if len(samples) == 0 {
		return nil, false
	}
	type identity struct {
		id, totLen uint16
		ttl        uint8
		l4         [16]byte
	}
	type agg struct {
		n        int
		ttlMin   uint8
		ttlMax   uint8
		ids      map[uint16]int
		seen     map[identity]int
		bytes    uint64
		nonIPv4  int
		repeated int // samples identical to one already seen in this batch
	}
	flows := map[sampleFlow]*agg{}
	other := 0
	for _, s := range samples {
		b := s.Bytes
		if len(b) < 34 || binary.BigEndian.Uint16(b[12:14]) != 0x0800 || b[14]>>4 != 4 {
			other++
			continue
		}
		var f sampleFlow
		copy(f.src[:], b[6:12])
		copy(f.dst[:], b[0:6])
		ihl := int(b[14]&0x0f) * 4
		id := binary.BigEndian.Uint16(b[18:20])
		ttl := b[22]
		f.srcIP = netip.AddrFrom4([4]byte(b[26:30]))
		f.dstIP = netip.AddrFrom4([4]byte(b[30:34]))
		switch b[23] {
		case 6:
			f.proto = "tcp"
		case 17:
			f.proto = "udp"
		case 1:
			f.proto = "icmp"
		default:
			f.proto = fmt.Sprintf("proto%d", b[23])
		}
		if (b[23] == 6 || b[23] == 17) && len(b) >= 14+ihl+4 {
			f.srcPort = binary.BigEndian.Uint16(b[14+ihl : 14+ihl+2])
			f.dstPort = binary.BigEndian.Uint16(b[14+ihl+2 : 14+ihl+4])
		}
		a := flows[f]
		if a == nil {
			a = &agg{ttlMin: ttl, ttlMax: ttl, ids: map[uint16]int{}, seen: map[identity]int{}}
			flows[f] = a
		}
		a.n++
		a.bytes += uint64(s.Len)
		if ttl < a.ttlMin {
			a.ttlMin = ttl
		}
		if ttl > a.ttlMax {
			a.ttlMax = ttl
		}
		a.ids[id]++
		// The same frame: same ID, length and TTL, and the same transport
		// header. A frame circulating through a router keeps everything
		// but the TTL, so the TTL is left out of that identity on purpose
		// and reported through the TTL range instead.
		key := identity{id: id, totLen: binary.BigEndian.Uint16(b[16:18])}
		if end := 14 + ihl + 16; end <= len(b) {
			copy(key.l4[:], b[14+ihl:end])
		}
		if a.seen[key] > 0 {
			a.repeated++
		}
		a.seen[key]++
	}
	keys := make([]sampleFlow, 0, len(flows))
	for k := range flows {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if flows[keys[i]].n != flows[keys[j]].n {
			return flows[keys[i]].n > flows[keys[j]].n
		}
		return keys[i].srcIP.Less(keys[j].srcIP)
	})
	out := []string{fmt.Sprintf("%d sampled frames in %d flows (%d not IPv4)", len(samples), len(flows), other)}
	for i, k := range keys {
		if i == 8 {
			out = append(out, fmt.Sprintf("... and %d more flows", len(keys)-i))
			break
		}
		a := flows[k]
		ttl := fmt.Sprintf("ttl %d", a.ttlMin)
		if a.ttlMax != a.ttlMin {
			ttl = fmt.Sprintf("ttl %d-%d", a.ttlMin, a.ttlMax)
		}
		ports := ""
		if k.proto == "tcp" || k.proto == "udp" {
			ports = fmt.Sprintf(" :%d->:%d", k.srcPort, k.dstPort)
		}
		verdict := "distinct packets"
		switch {
		case a.n >= 4 && a.repeated >= a.n/2 && a.ttlMax != a.ttlMin:
			verdict = "SAME FRAME, FALLING TTL: circulating through a router"
			circulating = true
		case a.n >= 4 && a.repeated >= a.n/2:
			verdict = "SAME FRAME, SAME TTL: circulating at layer 2"
			circulating = true
		case a.repeated > 0:
			verdict = fmt.Sprintf("%d repeated frames", a.repeated)
		case len(a.ids) == 1 && a.ids[0] == a.n:
			verdict = "distinct packets (id 0 on every one: a don't-fragment sender, not a loop)"
		}
		out = append(out, fmt.Sprintf("%4d  %s -> %s  %s %s->%s%s  %s  %d ids, %s  avg %d B",
			a.n, k.src, k.dst, k.proto, k.srcIP, k.dstIP, ports, ttl, len(a.ids), verdict, a.bytes/uint64(a.n)))
	}
	return out, circulating
}
