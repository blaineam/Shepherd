// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"sync"
	"time"
)

// AckMeter estimates how many bytes a steered device has *received* from
// the outbound frames Watch mode relays, which are the only frames it ever
// sees (docs/WATCH.md, "What it does not see: downloads").
//
// The trick is TCP's own bookkeeping. Every segment a device sends on a
// connection carries an acknowledgement number: the next byte it expects
// from the far end, which is to say the count of bytes it has received so
// far on that connection. A download is a stream of inbound data segments
// the relay never sees, answered by a stream of outbound ACKs it does see,
// and each ACK's number has advanced by exactly the bytes that arrived in
// between. Summing those advances per connection, and per device, gives
// the download volume without touching the return path: no second
// interception, no promiscuous capture, no mirror port, and nothing new on
// the wire. It is an estimate, and the portal says so, because it is blind
// to anything that is not TCP: QUIC (most of YouTube, some streaming), UDP
// media and VPN tunnels all show as zero received. For the same reason it
// can never over-count: an acknowledgement number only ever covers bytes
// that genuinely arrived.
//
// One AckMeter belongs to one Relay. ParallelRelay's capture sockets share
// a PACKET_FANOUT group hashed by flow, so every segment of one connection
// reaches the same worker and therefore the same meter; the Controller
// adds the per-worker estimates together. The in-kernel XDP relay does the
// same arithmetic itself (bpf/xdp_relay.c, meter_ack) with the same rules,
// so the two relays report the same number for the same traffic.
//
// Rules, per TCP segment from a steered device:
//
//   - RST forgets the connection. A SYN without ACK (a new connection's
//     first segment) carries no acknowledgement and is ignored.
//   - The first ACK seen for a connection is a baseline, never a credit:
//     a connection that was already running when steering began must not
//     be credited with everything it ever received.
//   - An acknowledgement that advances by less than MaxAdvance is credited
//     in full, modulo 2^32 so wraparound is handled. One that does not
//     advance (a duplicate ACK, a window update, a keepalive) credits
//     nothing, which is right: a duplicate ACK means data did *not*
//     arrive.
//   - An advance of MaxAdvance or more is not a download but a connection
//     this meter mistook for an old one (a reused port pair) or a frame
//     captured out of order by a wide margin; it re-baselines instead.
//   - FIN credits the final advance, then forgets the connection.
//   - Connections idle for longer than IdleTimeout are forgotten on a
//     periodic sweep; a full table admits no new connection until one
//     is freed, and then only the ones already tracked are metered.
//
// Safe for concurrent use; the lock is uncontended in practice because
// each worker has its own meter.
type AckMeter struct {
	// MaxFlows bounds the connection table (default DefaultMaxFlows).
	MaxFlows int
	// IdleTimeout forgets a connection with no segment for this long
	// (default DefaultFlowIdleTimeout).
	IdleTimeout time.Duration

	mu      sync.Mutex
	flows   map[flowKey]*flowState
	sweepAt time.Time
}

const (
	// DefaultMaxFlows is the connection table's default size per meter: a
	// busy home network has thousands of concurrent connections, not tens
	// of thousands, and each entry is small.
	DefaultMaxFlows = 65536
	// DefaultFlowIdleTimeout is how long a connection with no traffic is
	// remembered before its baseline is dropped.
	DefaultFlowIdleTimeout = 2 * time.Minute
	// MaxAdvance is the largest single acknowledgement advance credited as
	// a download. 1 GiB between two consecutive ACKs of one connection is
	// not a transfer; it is a different connection on the same port pair,
	// or a wildly reordered capture. Matches MAX_ADVANCE in xdp_relay.c.
	MaxAdvance = 1 << 30

	sweepEvery = 30 * time.Second

	ipProtoTCP   = 6
	tcpHeaderMin = 20
	tcpFlagFIN   = 0x01
	tcpFlagRST   = 0x04
	tcpFlagACK   = 0x10
)

// flowKey identifies one TCP connection as seen from the device: its own
// address and port, and the far end's. IPv4 addresses are stored as
// 4-in-6 so one key type serves both families.
type flowKey struct {
	src, dst     [16]byte
	sport, dport uint16
}

type flowState struct {
	ack  uint32
	last time.Time
}

func (m *AckMeter) maxFlows() int {
	if m.MaxFlows > 0 {
		return m.MaxFlows
	}
	return DefaultMaxFlows
}

func (m *AckMeter) idleTimeout() time.Duration {
	if m.IdleTimeout > 0 {
		return m.IdleTimeout
	}
	return DefaultFlowIdleTimeout
}

// Flows reports how many connections are currently tracked.
func (m *AckMeter) Flows() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.flows)
}

// Observe inspects one outbound Ethernet frame a steered device sent and
// returns the number of bytes its TCP acknowledgement says the device has
// received since the previous segment of that connection, or 0 for
// anything that is not a crediting TCP segment (another protocol, a new
// or unknown connection, a duplicate ACK, a frame too short to parse).
func (m *AckMeter) Observe(raw []byte, now time.Time) uint64 {
	if len(raw) < ethHeaderLen {
		return 0
	}
	var key flowKey
	var tcp []byte
	switch binary.BigEndian.Uint16(raw[12:14]) {
	case etherTypeIPv4:
		ip := raw[ethHeaderLen:]
		if len(ip) < ipv4HeaderMinLen || ip[0]>>4 != 4 {
			return 0
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < ipv4HeaderMinLen || len(ip) < ihl+tcpHeaderMin {
			return 0
		}
		if ip[9] != ipProtoTCP {
			return 0
		}
		// A later fragment carries no TCP header; the first fragment
		// (offset 0) does. The MF bit alone does not matter.
		if binary.BigEndian.Uint16(ip[6:8])&0x1fff != 0 {
			return 0
		}
		key.src = v4in6(ip[12:16])
		key.dst = v4in6(ip[16:20])
		tcp = ip[ihl:]
	case etherTypeIPv6:
		ip := raw[ethHeaderLen:]
		if len(ip) < ipv6HeaderLen+tcpHeaderMin || ip[0]>>4 != 6 {
			return 0
		}
		// TCP directly after the base header only. Extension headers
		// are rare on a LAN device's outbound TCP and not worth the
		// parsing surface here or in the kernel program.
		if ip[6] != ipProtoTCP {
			return 0
		}
		copy(key.src[:], ip[8:24])
		copy(key.dst[:], ip[24:40])
		tcp = ip[ipv6HeaderLen:]
	default:
		return 0
	}

	key.sport = binary.BigEndian.Uint16(tcp[0:2])
	key.dport = binary.BigEndian.Uint16(tcp[2:4])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	flags := tcp[13]

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.flows == nil {
		m.flows = map[flowKey]*flowState{}
		m.sweepAt = now.Add(sweepEvery)
	}
	if !now.Before(m.sweepAt) {
		m.sweepLocked(now)
	}

	if flags&tcpFlagRST != 0 {
		delete(m.flows, key)
		return 0
	}
	if flags&tcpFlagACK == 0 {
		return 0
	}
	st, ok := m.flows[key]
	if !ok {
		if len(m.flows) >= m.maxFlows() {
			m.sweepLocked(now)
			if len(m.flows) >= m.maxFlows() {
				return 0
			}
		}
		m.flows[key] = &flowState{ack: ack, last: now}
		return 0
	}
	st.last = now
	delta := ack - st.ack // uint32 arithmetic: wraps as TCP does
	credit := uint64(0)
	switch {
	case delta == 0:
	case delta >= MaxAdvance:
		st.ack = ack
	default:
		st.ack = ack
		credit = uint64(delta)
	}
	if flags&tcpFlagFIN != 0 {
		delete(m.flows, key)
	}
	return credit
}

func (m *AckMeter) sweepLocked(now time.Time) {
	cutoff := now.Add(-m.idleTimeout())
	for k, st := range m.flows {
		if st.last.Before(cutoff) {
			delete(m.flows, k)
		}
	}
	m.sweepAt = now.Add(sweepEvery)
}

func v4in6(b []byte) [16]byte {
	var out [16]byte
	out[10], out[11] = 0xff, 0xff
	copy(out[12:16], b)
	return out
}
