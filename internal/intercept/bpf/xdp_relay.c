// SPDX-License-Identifier: AGPL-3.0-or-later

// xdp_relay: Watch mode's one-sided ARP steering relay, in the kernel.
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
//   1. plain IPv4 ethertype only (no ARP, no IPv6, no VLAN tags);
//   2. destination MAC is Shepherd's;
//   3. source MAC is a currently steered device (the `steered` map, kept
//      in sync with Controller's steered set by xdp_linux.go);
//   4. and one rule the Go Relay does not need because the kernel also
//      gets its own copy of every frame an AF_PACKET socket reads: the
//      destination IP is not one of Shepherd's own (`local_ips`). An XDP_TX
//      frame never reaches the stack, so a steered device's DNS query to
//      Shepherd itself — addressed to Shepherd's MAC and Shepherd's IP —
//      must be passed through, not relayed to the gateway.
//
// IPv4 only, always (docs/IPV6.md): rule 1 is the first thing checked.

#include "bpf_minimal.h"

#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define IPV4_MIN_HLEN 20

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

// Set once by the loader before the program is attached.
struct relay_config {
	__u8 shepherd_mac[ETH_ALEN];
	__u8 gateway_mac[ETH_ALEN];
};

// Per-device counters, keyed by the device's MAC padded to 8 bytes. The
// loader inserts a zeroed entry when a device is steered and deletes it
// when it is unsteered; it reads the counters periodically for health
// verification and Status().
struct mac_key {
	__u8 mac[ETH_ALEN];
	__u8 pad[2];
};

struct dev_counters {
	__u64 packets;
	__u64 bytes;
	__u64 last_seen_ns; // bpf_ktime_get_ns (CLOCK_MONOTONIC) of the last relayed frame
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

	// Rule 1: plain IPv4 only.
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct relay_config *cfg = bpf_map_lookup_elem(&config, &zero);
	if (!cfg)
		return XDP_PASS;

	// Rule 2: addressed to Shepherd.
	if (!mac_equal(eth->h_dest, cfg->shepherd_mac))
		return XDP_PASS;

	// Rule 3: from a steered device.
	struct mac_key key = {};
	mac_copy(key.mac, eth->h_source);
	struct dev_counters *dev = bpf_map_lookup_elem(&steered, &key);
	if (!dev)
		return XDP_PASS;

	// Rule 4: not for Shepherd itself.
	struct iphdr_min *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (bpf_map_lookup_elem(&local_ips, &ip->daddr)) {
		if (st)
			st->passed_local++;
		return XDP_PASS;
	}

	// Relay: both MACs rewritten (see Relay's type comment in relay.go for
	// why the source MAC must become Shepherd's), nothing else touched.
	mac_copy(eth->h_dest, cfg->gateway_mac);
	mac_copy(eth->h_source, cfg->shepherd_mac);

	__u64 len = data_end - data;
	__sync_fetch_and_add(&dev->packets, 1);
	__sync_fetch_and_add(&dev->bytes, len);
	dev->last_seen_ns = bpf_ktime_get_ns();
	if (st) {
		st->relayed_frames++;
		st->relayed_bytes += len;
	}
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
