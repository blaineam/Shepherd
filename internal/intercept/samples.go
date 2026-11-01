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
	o := c.observer.Load()
	if o == nil {
		return 0
	}
	s, ok := (*o).(frameSampler)
	if !ok {
		return 0
	}
	return s.duplicatesSuppressed()
}

// DuplicatesByDevice is each steered device's share of the frames the
// relay refused as duplicates, keyed by MAC and omitting devices with
// none. The global DuplicatesSuppressed count cannot say whether a loop
// belongs to one device or to all of them, and that is the question still
// open about what re-delivers the frames (docs/WATCH.md). Empty where the
// data plane in use does not count them.
func (c *Controller) DuplicatesByDevice() map[arp.MAC]uint64 {
	o := c.observer.Load()
	if o == nil {
		return nil
	}
	s, ok := (*o).(frameSampler)
	if !ok {
		return nil
	}
	return s.duplicatesByDevice()
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
	if len(samples) == 0 {
		return nil
	}
	type agg struct {
		n        int
		ttlMin   uint8
		ttlMax   uint8
		ids      map[uint16]int
		bytes    uint64
		nonIPv4  int
		repeated int // samples whose IP ID had been seen before within this batch
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
			a = &agg{ttlMin: ttl, ttlMax: ttl, ids: map[uint16]int{}}
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
		if a.ids[id] > 0 {
			a.repeated++
		}
		a.ids[id]++
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
		verdict := "distinct ids"
		switch {
		case a.n >= 4 && a.repeated >= a.n/2 && a.ttlMax != a.ttlMin:
			verdict = "SAME IDs, FALLING TTL: circulating through a router"
		case a.n >= 4 && a.repeated >= a.n/2:
			verdict = "SAME IDs, SAME TTL: circulating at layer 2"
		case a.repeated > 0:
			verdict = fmt.Sprintf("%d repeated ids", a.repeated)
		}
		out = append(out, fmt.Sprintf("%4d  %s -> %s  %s %s->%s%s  %s  %d ids, %s  avg %d B",
			a.n, k.src, k.dst, k.proto, k.srcIP, k.dstIP, ports, ttl, len(a.ids), verdict, a.bytes/uint64(a.n)))
	}
	return out
}
