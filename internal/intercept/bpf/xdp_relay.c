// SPDX-License-Identifier: AGPL-3.0-or-later

// xdp_relay: Watch mode's one-sided steering relay, in the kernel.
//
// This is Relay.HandleFrame (relay.go) as an XDP program: for a frame that
// a steered device sent to Shepherd's MAC, rewrite the destination MAC to
// the real gateway's and the source MAC to Shepherd's own, count it, and
// bounce it straight back out the same interface (XDP_TX) without the
// frame ever being copied into an skb, let alone up to userspace. Every
// other frame is XDP_PASS: untouched, delivered to the kernel exactly as
// if this program were not attached. Nothing is ever dropped here.
//
// The decision rules are the same as HandleFrame's, deliberately, and the
// Go side (xdp_linux.go) keeps a test that runs this program and the Go
// Relay over the same frames and insists they agree:
//
//   1. plain IPv4 or IPv6 ethertype only (no ARP, no VLAN tags);
//   2. destination MAC is Shepherd's;
//   3. source MAC is a steered device (the `steered` map, kept in sync
//      with Controller's steered set by xdp_linux.go) AND that device is
//      steered for this frame's address family (the per-device `families`
//      bitmask: FAM_V4 for IPv4, FAM_V6 for IPv6). A device steered only
//      for IPv4 has its IPv6 passed through, and vice versa — and while no
//      device is steered for a family, no frame of that family is ever
//      relayed. This is docs/IPV6.md's hard rule, enforced per device.
//   4. and one rule the Go Relay does not need because the kernel also
//      gets its own copy of every frame an AF_PACKET socket reads: the
//      destination IP is not one of Shepherd's own (`local_ips` for IPv4,
//      `local_ips6` for IPv6). An XDP_TX frame never reaches the stack, so
//      a steered device's DNS query to Shepherd itself — addressed to
//      Shepherd's MAC and Shepherd's IP — must be passed through, not
//      relayed to the gateway.
//
// The inner packet is never touched (the IPv4 TTL / IPv6 hop limit
// included — unlike a router, this relay does not decrement it); only the
// two Ethernet addresses change.
//
// A relayed frame is also read, never written, by meter_ack: the same
// TCP-acknowledgement download estimate as Go's AckMeter (ackmeter.go),
// with the same rules, so the two relays report the same number for the
// same traffic. The per-flow state lives in the `flows` LRU map and the
// running estimate in dev_counters.rx_est / rx_est6, which the loader
// harvests like the relayed-byte counters.

#include "bpf_minimal.h"

#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define IPV4_MIN_HLEN 20
#define IPV6_HLEN 40
#define IPPROTO_TCP 6
#define TCP_HLEN 20
#define TCP_FIN 0x01
#define TCP_RST 0x04
#define TCP_ACK 0x10
// The largest acknowledgement advance credited as a download; matches
// Go's intercept.MaxAdvance. Anything bigger is a reused port pair or a
// badly reordered capture and re-baselines instead.
#define MAX_ADVANCE (1u << 30)

// The duplicate brake. A relay loop is the same frame arriving and being
// relayed over and over: every reproduction on real hardware showed a
// handful of frames with one IP ID each and a TTL that never decremented,
// circulating thousands of times a second. So the program fingerprints
// each frame it relays and refuses to relay the same frame twice inside a
// short window, which breaks a loop on its second pass whatever is
// echoing the frame.
//
// DUP_WINDOW_NS is deliberately shorter than any TCP retransmission
// timeout (Linux's minimum is 200ms) and vastly longer than a loop's round
// trip, which is microseconds. A genuine retransmission is therefore never
// suppressed, and a frame going round is caught the second time it is
// seen. A frame that really is a network-level duplicate is dropped rather
// than relayed twice, which is what should happen to it: the first copy
// already reached the gateway.
#define DUP_WINDOW_NS 100000000ULL /* 100 ms */
#define DUP_SLOTS 8192

struct dup_entry {
	__u64 fingerprint;
	__u64 ts;
};

// Family bits, matching Go's intercept.SteerV4 / SteerV6.
#define FAM_V4 1
#define FAM_V6 2

struct ethhdr {
	__u8 h_dest[ETH_ALEN];
	__u8 h_source[ETH_ALEN];
	__u16 h_proto;
} __attribute__((packed));

// Just enough of the IPv4 header to read the destination address.
struct iphdr_min {
	__u8 ver_ihl;
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
} __attribute__((packed));

// Just enough of the IPv6 header to read the destination address. The base
// header is fixed-length, so the destination always sits at offset 24.
struct ipv6hdr_min {
	__u8 ver_tc;
	__u8 tc_fl;
	__u16 fl;
	__u16 payload_len;
	__u8 next_hdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
} __attribute__((packed));

// A 16-byte IPv6 address, the key type of local_ips6.
struct in6_key {
	__u8 addr[16];
};

// Just enough of the TCP header for meter_ack: ports, the acknowledgement
// number and the flags byte.
struct tcphdr_min {
	__u16 source;
	__u16 dest;
	__u32 seq;
	__u32 ack_seq;
	__u8 doff_res;
	__u8 flags;
	__u16 window;
} __attribute__((packed));

// One TCP connection as the device sees it. IPv4 addresses are stored as
// 4-in-6 so one key type serves both families (as Go's flowKey does).
struct flow_key {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport;
	__u16 dport;
	__u32 pad;
};

struct flow_state {
	__u32 ack; // last acknowledgement number seen, host order
	__u32 pad;
};

// Set once by the loader before the program is attached.
struct relay_config {
	__u8 shepherd_mac[ETH_ALEN];
	__u8 gateway_mac[ETH_ALEN];
};

// Per-device counters, keyed by the device's MAC padded to 8 bytes. The
// loader inserts an entry (with the device's steered families) when a
// device is steered, updates families when they change, and deletes it
// when the device is fully unsteered; it reads the counters periodically
// for health verification and Status(). IPv4 and IPv6 are counted
// separately so per-family health works.
struct mac_key {
	__u8 mac[ETH_ALEN];
	__u8 pad[2];
};

struct dev_counters {
	__u64 packets;      // IPv4
	__u64 bytes;        // IPv4
	__u64 last_seen_ns; // IPv4, bpf_ktime_get_ns (CLOCK_MONOTONIC)
	__u64 packets6;     // IPv6
	__u64 bytes6;       // IPv6
	__u64 last_seen_ns6;
	// duplicates is this device's share of the frames the duplicate brake
	// refused. Per device, not just globally, because the global figure
	// cannot say whether a loop belongs to one device or to all of them --
	// and that is exactly the question left open about what re-delivers
	// them (docs/WATCH.md).
	__u64 duplicates;
	__u64 rx_est;       // IPv4: estimated bytes received, from TCP acks
	__u64 rx_est6;      // IPv6: the same
	__u8 families;      // FAM_V4 | FAM_V6
	__u8 pad[7];
};

// Global counters, per CPU so the hot path needs no atomics for them.
struct relay_stats {
	__u64 examined;        // every frame this program saw
	__u64 passed_local;    // matched a steered device but was for Shepherd itself (rule 4)
	__u64 relayed_frames;
	__u64 relayed_bytes;
	// Diagnostics for the relay loop (docs/WATCH.md). A frame this program
	// relays leaves with src = Shepherd's MAC and dst = the gateway's, so
	// either of those arriving back on this interface is Shepherd's own
	// output returning to it -- which is what a loop is made of. Counted
	// and sampled separately from the relay path, and never acted on.
	__u64 ours_returning;  // src MAC is Shepherd's own
	__u64 to_gateway;      // dst MAC is the gateway's
	// duplicates is frames refused because this program had already
	// relayed the same frame inside DUP_WINDOW_NS: the substance of a
	// relay loop, and on a healthy network a flat zero.
	__u64 duplicates;
	// How long each duplicate took to come back, bucketed. This is the
	// measurement that says where the echo comes from, which nothing else
	// has been able to settle: a frame that never left the machine returns
	// in microseconds, one that went to the switch and back takes
	// hundreds of microseconds, and one that crossed a wireless hop or a
	// mesh backhaul takes longer still. The delay is free to compute --
	// the duplicate table already holds the moment the frame first
	// arrived.
	__u64 echo_under_10us;
	__u64 echo_under_100us;
	__u64 echo_under_1ms;
	__u64 echo_under_10ms;
	__u64 echo_over_10ms;
};

// A sample of a relayed frame: its first SAMPLE_BYTES bytes (Ethernet,
// IPv4 and the start of the transport header), taken for every
// SAMPLE_EVERY-th frame the program relays on a CPU and written into a
// ring the loader reads once a second. This exists because a frame this
// program bounces back out with XDP_TX never reaches an AF_PACKET socket,
// so no packet capture on the host can see what the relay is carrying --
// and twice the answer to "what was that storm made of" had to be guessed.
// seq is a global counter so the reader can tell a fresh sample from one it
// has already seen; ts is bpf_ktime_get_ns.
#define SAMPLE_BYTES 60
#define SAMPLE_EVERY 256
#define SAMPLE_RING 128

struct frame_sample {
	__u64 seq;
	__u64 ts;
	__u32 len;
	__u32 pad;
	__u8 bytes[SAMPLE_BYTES];
	__u8 pad2[4];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct relay_config);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SAMPLE_RING);
	__type(key, __u32);
	__type(value, struct frame_sample);
} samples SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sample_cursor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct mac_key);
	__type(value, struct dev_counters);
} steered SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32); // IPv4 address, network byte order
	__type(value, __u8);
} local_ips SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct in6_key); // IPv6 address, network byte order
	__type(value, __u8);
} local_ips6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct relay_stats);
} stats SEC(".maps");

// Per CPU, not shared, and that is the whole point. As one shared table
// this caught about 80% of a steady echo and only 3% of an actual runaway,
// because is_duplicate reads a slot, compares and writes it back with no
// atomicity: at tens of thousands of frames a second across a dozen cores,
// two copies of one frame routinely both read "not seen" and both get
// relayed, so the brake failed exactly when it was needed. A per-CPU table
// has no such race, and costs nothing in accuracy here because the receive
// hash puts a flow and its echo on the same queue, and so the same CPU.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, DUP_SLOTS);
	__type(key, __u32);
	__type(value, struct dup_entry);
} recent SEC(".maps");

// The download meter's connection table. LRU so the kernel evicts the
// oldest entry itself when it fills; the loader never touches it.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct flow_state);
} flows SEC(".maps");

static __attribute__((always_inline)) int mac_equal(const __u8 *a, const __u8 *b)
{
	// Two loads instead of a byte loop: keeps the verifier's instruction
	// count low and the program branch-free here.
	return *(const __u32 *)a == *(const __u32 *)b &&
	       *(const __u16 *)(a + 4) == *(const __u16 *)(b + 4);
}

static __attribute__((always_inline)) void mac_copy(__u8 *dst, const __u8 *src)
{
	*(__u32 *)dst = *(const __u32 *)src;
	*(__u16 *)(dst + 4) = *(const __u16 *)(src + 4);
}

// take_sample copies the first SAMPLE_BYTES of the frame as it arrived
// (before the MAC rewrite) into the next ring slot. Frames shorter than
// that are not sampled; the smallest frame on the wire is 60 bytes, so in
// practice that is only a truncated one.
static __attribute__((always_inline)) void take_sample(void *data, void *data_end, __u64 len)
{
	__u32 zero = 0;
	if (data + SAMPLE_BYTES > data_end)
		return;
	__u64 *cur = bpf_map_lookup_elem(&sample_cursor, &zero);
	if (!cur)
		return;
	// Not atomic on purpose: the BPF target in use has no atomic
	// fetch-and-add with a usable result, and two CPUs occasionally
	// writing the same slot costs one sample, not correctness.
	__u64 seq = *cur + 1;
	*cur = seq;
	__u32 slot = (__u32)(seq % SAMPLE_RING);
	struct frame_sample *s = bpf_map_lookup_elem(&samples, &slot);
	if (!s)
		return;
	s->seq = seq;
	s->ts = bpf_ktime_get_ns();
	s->len = (__u32)len;
	__builtin_memcpy(s->bytes, data, SAMPLE_BYTES);
}

// fingerprint identifies one frame well enough to recognise it coming
// round again: the IPv4 identification field, the length fields, both
// addresses, the protocol and the first sixteen bytes of the transport
// header.
//
// Each part is there because something real varies it and something real
// does not. The identification field alone is not enough, because a Linux
// sender leaves it zero on an unfragmentable packet. The transport header
// is what carries the difference between two packets of a flow: for TCP
// those sixteen bytes hold the ports, the sequence and acknowledgement
// numbers, the flags and the window; for UDP the ports, the length, the
// checksum and the first eight bytes of payload, which for QUIC include
// the connection ID. The frame's own length on the wire is included as
// well as the header's, since a truncated or padded copy is a different
// frame.
//
// Two genuinely different packets colliding costs one suppressed frame.
// Two copies of one frame failing to collide costs one more pass round a
// loop that the next pass catches. Neither is serious; both get wider
// margin from more of the transport header, which is why sixteen bytes
// rather than the eight this started with.
static __attribute__((always_inline)) __u64 fingerprint(struct iphdr_min *ip, void *l4, void *data_end, __u64 wire_len)
{
	__u64 h = 1469598103934665603ULL; /* FNV-1a offset basis */
	__u32 words[9];
	words[0] = ((__u32)ip->id << 16) | (__u32)ip->tot_len;
	words[1] = ip->saddr;
	words[2] = ip->daddr;
	words[3] = ((__u32)ip->protocol << 16) | (__u32)wire_len;
	words[4] = 0;
	words[5] = 0;
	words[6] = 0;
	words[7] = 0;
	words[8] = 0;
	if (l4 + 8 <= data_end) {
		words[4] = *(__u32 *)l4;
		words[5] = *(__u32 *)(l4 + 4);
	}
	if (l4 + 16 <= data_end) {
		words[6] = *(__u32 *)(l4 + 8);
		words[7] = *(__u32 *)(l4 + 12);
	}
	for (int i = 0; i < 9; i++) {
		h ^= (__u64)words[i];
		h *= 1099511628211ULL; /* FNV-1a prime */
	}
	// Never return 0: an empty slot holds a zero fingerprint.
	return h | 1;
}

// fingerprint6 is fingerprint for IPv6. There is no identification field
// to use, so it leans on what IPv6 does have: the traffic class and flow
// label, the payload length, the next header, both 16-byte addresses and
// the first sixteen bytes of the transport header. A flow label is constant
// for a flow, so the transport header is doing most of the work here, which
// is the same thing that distinguishes two IPv4 packets of one flow.
static __attribute__((always_inline)) __u64 fingerprint6(struct ipv6hdr_min *ip6, void *l4, void *data_end, __u64 wire_len)
{
	__u64 h = 1469598103934665603ULL; /* FNV-1a offset basis */
	__u32 words[14];
	words[0] = ((__u32)ip6->tc_fl << 16) | (__u32)ip6->fl;
	words[1] = ((__u32)ip6->payload_len << 16) | ((__u32)ip6->next_hdr << 8);
	words[2] = (__u32)wire_len;
	for (int i = 0; i < 4; i++) {
		words[3 + i] = *(__u32 *)(ip6->saddr + i * 4);
		words[7 + i] = *(__u32 *)(ip6->daddr + i * 4);
	}
	words[11] = 0;
	words[12] = 0;
	words[13] = 0;
	if (l4 + 8 <= data_end) {
		words[11] = *(__u32 *)l4;
		words[12] = *(__u32 *)(l4 + 4);
	}
	if (l4 + 16 <= data_end)
		words[13] = *(__u32 *)(l4 + 8) ^ *(__u32 *)(l4 + 12);
	for (int i = 0; i < 14; i++) {
		h ^= (__u64)words[i];
		h *= 1099511628211ULL; /* FNV-1a prime */
	}
	return h | 1;
}

// is_duplicate reports whether this program already relayed this exact
// frame inside DUP_WINDOW_NS, and records it either way. One slot per
// fingerprint hash, overwritten freely: a collision costs one suppressed
// frame, and an eviction costs one unsuppressed loop pass, neither of
// which matters at the rates involved.
//
// The table is per CPU (see the map), so the read-compare-write below needs
// no atomicity and cannot lose a race to another core. It also means a
// frame and its echo must land on the same CPU to be matched, which the
// receive hash guarantees for a given flow.
static __attribute__((always_inline)) int is_duplicate(__u64 fp, __u64 now,
						       struct relay_stats *st)
{
	__u32 slot = (__u32)((fp >> 16) % DUP_SLOTS);
	struct dup_entry *e = bpf_map_lookup_elem(&recent, &slot);
	if (!e)
		return 0;
	int dup = e->fingerprint == fp && now >= e->ts && (now - e->ts) < DUP_WINDOW_NS;
	__u64 delay = now - e->ts;
	e->fingerprint = fp;
	e->ts = now;
	if (dup && st) {
		if (delay < 10000)
			st->echo_under_10us++;
		else if (delay < 100000)
			st->echo_under_100us++;
		else if (delay < 1000000)
			st->echo_under_1ms++;
		else if (delay < 10000000)
			st->echo_under_10ms++;
		else
			st->echo_over_10ms++;
	}
	return dup;
}

// meter_ack is AckMeter.Observe in the kernel: for a TCP segment the
// device is sending, credit the device with the bytes its acknowledgement
// number has advanced by since the previous segment of that connection.
// tcp points at a TCP header already bounds-checked against data_end.
static __attribute__((always_inline)) void meter_ack(struct tcphdr_min *tcp,
						     struct flow_key *key,
						     struct dev_counters *dev,
						     int is_v6)
{
	__u8 flags = tcp->flags;
	key->sport = tcp->source;
	key->dport = tcp->dest;
	if (flags & TCP_RST) {
		bpf_map_delete_elem(&flows, key);
		return;
	}
	if (!(flags & TCP_ACK))
		return;
	__u32 ack = bpf_ntohl(tcp->ack_seq);
	struct flow_state *st = bpf_map_lookup_elem(&flows, key);
	if (!st) {
		struct flow_state fresh = { .ack = ack };
		bpf_map_update_elem(&flows, key, &fresh, BPF_ANY);
		return;
	}
	__u32 delta = ack - st->ack;
	if (delta != 0) {
		st->ack = ack;
		if (delta < MAX_ADVANCE) {
			if (is_v6)
				__sync_fetch_and_add(&dev->rx_est6, (__u64)delta);
			else
				__sync_fetch_and_add(&dev->rx_est, (__u64)delta);
		}
	}
	if (flags & TCP_FIN)
		bpf_map_delete_elem(&flows, key);
}

// meter_v4 / meter_v6 find the TCP header behind an IP header the caller
// has already bounds-checked, fill the flow key's addresses, and hand off
// to meter_ack. A non-TCP packet, a later fragment, or one too short to
// hold a TCP header is left alone.
static __attribute__((always_inline)) void meter_v4(struct iphdr_min *ip,
						    void *data_end,
						    struct dev_counters *dev)
{
	if (ip->protocol != IPPROTO_TCP)
		return;
	if (ip->frag_off & bpf_htons(0x1fff))
		return;
	__u32 ihl = (ip->ver_ihl & 0x0f) * 4;
	if (ihl < IPV4_MIN_HLEN)
		return;
	struct tcphdr_min *tcp = (void *)ip + ihl;
	if ((void *)(tcp + 1) > data_end)
		return;
	struct flow_key key = {};
	key.saddr[10] = 0xff;
	key.saddr[11] = 0xff;
	key.daddr[10] = 0xff;
	key.daddr[11] = 0xff;
	__builtin_memcpy(key.saddr + 12, &ip->saddr, 4);
	__builtin_memcpy(key.daddr + 12, &ip->daddr, 4);
	meter_ack(tcp, &key, dev, 0);
}

static __attribute__((always_inline)) void meter_v6(struct ipv6hdr_min *ip6,
						    void *data_end,
						    struct dev_counters *dev)
{
	if (ip6->next_hdr != IPPROTO_TCP)
		return;
	struct tcphdr_min *tcp = (void *)(ip6 + 1);
	if ((void *)(tcp + 1) > data_end)
		return;
	struct flow_key key = {};
	__builtin_memcpy(key.saddr, ip6->saddr, 16);
	__builtin_memcpy(key.daddr, ip6->daddr, 16);
	meter_ack(tcp, &key, dev, 1);
}

// relay rewrites both MACs and counts the frame; the caller has already
// decided it should be relayed. Returns XDP_TX.
static __attribute__((always_inline)) int do_relay(struct ethhdr *eth,
						   void *data_end,
						   struct relay_config *cfg,
						   struct dev_counters *dev,
						   struct relay_stats *st,
						   __u64 len, int is_v6)
{
	if (st && (st->relayed_frames % SAMPLE_EVERY) == 0)
		take_sample(eth, data_end, len);
	mac_copy(eth->h_dest, cfg->gateway_mac);
	mac_copy(eth->h_source, cfg->shepherd_mac);
	if (is_v6) {
		__sync_fetch_and_add(&dev->packets6, 1);
		__sync_fetch_and_add(&dev->bytes6, len);
		dev->last_seen_ns6 = bpf_ktime_get_ns();
	} else {
		__sync_fetch_and_add(&dev->packets, 1);
		__sync_fetch_and_add(&dev->bytes, len);
		dev->last_seen_ns = bpf_ktime_get_ns();
	}
	if (st) {
		st->relayed_frames++;
		st->relayed_bytes += len;
	}
	return XDP_TX;
}

SEC("xdp")
int xdp_relay(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 zero = 0;

	struct relay_stats *st = bpf_map_lookup_elem(&stats, &zero);
	if (st)
		st->examined++;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	// Rule 1: plain IPv4 or IPv6 only.
	__u16 proto = eth->h_proto;
	int is_v6;
	if (proto == bpf_htons(ETH_P_IP))
		is_v6 = 0;
	else if (proto == bpf_htons(ETH_P_IPV6))
		is_v6 = 1;
	else
		return XDP_PASS;

	struct relay_config *cfg = bpf_map_lookup_elem(&config, &zero);
	if (!cfg)
		return XDP_PASS;

	// Diagnostics, before any relay decision and affecting none of them:
	// is this frame one Shepherd itself put on the wire, coming back?
	if (st) {
		int ours = mac_equal(eth->h_source, cfg->shepherd_mac);
		int togw = mac_equal(eth->h_dest, cfg->gateway_mac);
		if (ours || togw) {
			if (ours)
				st->ours_returning++;
			if (togw)
				st->to_gateway++;
			if ((st->ours_returning % SAMPLE_EVERY) == 0)
				take_sample(data, data_end, data_end - data);
		}
	}

	// Rule 2: addressed to Shepherd.
	if (!mac_equal(eth->h_dest, cfg->shepherd_mac))
		return XDP_PASS;

	// Rule 3: from a steered device, steered for this family.
	struct mac_key key = {};
	mac_copy(key.mac, eth->h_source);
	struct dev_counters *dev = bpf_map_lookup_elem(&steered, &key);
	if (!dev)
		return XDP_PASS;
	__u8 need = is_v6 ? FAM_V6 : FAM_V4;
	if (!(dev->families & need))
		return XDP_PASS;

	__u64 len = data_end - data;

	// Rule 4: not for Shepherd itself.
	if (is_v6) {
		struct ipv6hdr_min *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;
		struct in6_key k6 = {};
		__builtin_memcpy(k6.addr, ip6->daddr, 16);
		if (bpf_map_lookup_elem(&local_ips6, &k6)) {
			if (st)
				st->passed_local++;
			return XDP_PASS;
		}
		// The duplicate brake, IPv6 side. The loop that made this
		// necessary was IPv4 and IPv6 steering is off by default, but a
		// loop here would be exactly as severe, so the brake is not left
		// to cover one family only.
		__u64 fp6 = fingerprint6(ip6, (void *)(ip6 + 1), data_end, len);
		if (is_duplicate(fp6, bpf_ktime_get_ns(), st)) {
			if (st)
				st->duplicates++;
			__sync_fetch_and_add(&dev->duplicates, 1);
			return XDP_DROP;
		}
		meter_v6(ip6, data_end, dev);
		return do_relay(eth, data_end, cfg, dev, st, len, 1);
	}

	struct iphdr_min *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (bpf_map_lookup_elem(&local_ips, &ip->daddr)) {
		if (st)
			st->passed_local++;
		return XDP_PASS;
	}
	// The duplicate brake: a frame this program has already relayed inside
	// DUP_WINDOW_NS is the same frame coming round, so it is dropped rather
	// than relayed again. Dropped, not passed: IPv4 forwarding is on on
	// many hosts, and passing it would hand the kernel a frame it would
	// route straight back out of this same interface.
	__u64 now_ns = bpf_ktime_get_ns();
	__u64 fp = fingerprint(ip, (void *)ip + ((ip->ver_ihl & 0x0f) * 4), data_end, len);
	if (is_duplicate(fp, now_ns, st)) {
		if (st)
			st->duplicates++;
		__sync_fetch_and_add(&dev->duplicates, 1);
		return XDP_DROP;
	}
	meter_v4(ip, data_end, dev);
	return do_relay(eth, data_end, cfg, dev, st, len, 0);
}

char _license[] SEC("license") = "GPL";
