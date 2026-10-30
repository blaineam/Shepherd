/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * The handful of kernel ABI definitions xdp_relay.c needs, written out
 * here so the program builds with any clang that has the BPF backend and
 * no kernel headers on the build machine (macOS included). Every value is
 * part of the stable BPF UAPI (include/uapi/linux/bpf.h) and cannot change
 * without breaking every eBPF program ever shipped.
 */
#ifndef SHEPHERD_BPF_MINIMAL_H
#define SHEPHERD_BPF_MINIMAL_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))

/* Map types (enum bpf_map_type). */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6

/* XDP verdicts (enum xdp_action). */
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3

/* Program context for an XDP program. */
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

/* BTF-style map definition fields (libbpf's bpf_helpers.h convention). */
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

/* Helpers, by their stable helper IDs (enum bpf_func_id). */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;

#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)

#endif
