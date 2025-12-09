// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// 9. eBPF Map Definition: Must match the Go definition
struct flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

struct flow_stats {
    __u64 packet_count;
    __u64 last_seen;
    __u32 protocol_id; // 0x01 XFS, 0x02 Modbus/S7Comm
};

// Map to communicate flow data back to user-space (Go)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_map SEC(".maps");

// 10. The XDP Ingress Program
SEC("xdp")
int ingress_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Only handle IPv4 traffic for simplicity
    if (eth->h_proto != __bpf_constant(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Look for TCP traffic
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS; 
    }

    struct tcphdr *tcp = (void*)ip + (ip->ihl * 4);
    if ((void*)(tcp + 1) > data_end) {
        return XDP_PASS;
    }
    
    __be16 src_port = tcp->source;
    __be16 dst_port = tcp->dest;
    
    // --- Protocol Port Check (The core filter logic) ---
    __u32 proto_match = 0;
    
    // XFS typically uses proprietary ports, but 3000-5000 is common for dev/test
    if (dst_port == __bpf_constant(3000) || dst_port == __bpf_constant(4000)) {
        proto_match = 0x01; // ATM/XFS
    } 
    // Modbus default port
    else if (dst_port == __bpf_constant(502)) {
        proto_match = 0x02; // ICS/Modbus
    }
    
    if (proto_match == 0) {
        return XDP_PASS; // Drop or pass non-target traffic
    }

    // --- Update Flow Map ---
    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = src_port,
        .dport = dst_port,
    };
    
    struct flow_stats *stats;
    stats = bpf_map_lookup_elem(&flow_map, &key);
    
    if (stats) {
        // Flow exists: update stats
        stats->packet_count++;
        stats->last_seen = bpf_ktime_get_ns();
        stats->protocol_id = proto_match;
        // No need to update elem, map value is already updated
    } else {
        // New flow: create entry
        struct flow_stats new_stats = {
            .packet_count = 1,
            .last_seen = bpf_ktime_get_ns(),
            .protocol_id = proto_match,
        };
        bpf_map_update_elem(&flow_map, &key, &new_stats, BPF_ANY);
    }

    // XDP_PASS sends the packet up the normal network stack to be captured by Go's pcap
    // We filter in kernel space and pass the allowed packets to user space for inspection.
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
