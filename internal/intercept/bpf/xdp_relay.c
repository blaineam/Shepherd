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

#include "bpf_minimal.h"

#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define IPV4_MIN_HLEN 20
#define IPV6_HLEN 40

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
	__u8 families;      // FAM_V4 | FAM_V6
	__u8 pad[7];
};

// Global counters, per CPU so the hot path needs no atomics for them.
struct relay_stats {
	__u64 examined;        // every frame this program saw
	__u64 passed_local;    // matched a steered device but was for Shepherd itself (rule 4)
	__u64 relayed_frames;
	__u64 relayed_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct relay_config);
} config SEC(".maps");

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

// relay rewrites both MACs and counts the frame; the caller has already
// decided it should be relayed. Returns XDP_TX.
static __attribute__((always_inline)) int do_relay(struct ethhdr *eth,
						   struct relay_config *cfg,
						   struct dev_counters *dev,
						   struct relay_stats *st,
						   __u64 len, int is_v6)
{
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
		return do_relay(eth, cfg, dev, st, len, 1);
	}

	struct iphdr_min *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (bpf_map_lookup_elem(&local_ips, &ip->daddr)) {
		if (st)
			st->passed_local++;
		return XDP_PASS;
	}
	return do_relay(eth, cfg, dev, st, len, 0);
}

char _license[] SEC("license") = "GPL";
