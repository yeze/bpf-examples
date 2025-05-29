#include "linux/vmlinux.h"
#include "linux/bpf_helpers.h"
#include "linux/bpf_endian.h"
#include "linux/bpf_core_read.h"
#include "linux/bpf_tracing.h"

#ifndef MAX_SOCKS
#define MAX_SOCKS 65535
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef PCKT_FRAGMENTED
#define PCKT_FRAGMENTED 65343
#endif

// udp_xsks_map key: udp报文目的端口, value: socket fd
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, MAX_SOCKS);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(pinning, LIBBPF_PIN_BY_NAME); // 将map pinned在/var/run/lixdp下
} udp_xsks_map SEC(".maps");

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx) {
    __u32 off;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *ethh = data;
    off = sizeof(struct ethhdr);
    if (data + off > data_end) {
        return XDP_PASS;
    }
    if (bpf_htons(ethh->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + off;
    off += sizeof(struct iphdr);
    if (data + off > data_end) {
        return XDP_PASS;
    }
    if (iph->ihl != 5 || iph->frag_off & PCKT_FRAGMENTED) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }
    struct udphdr *udph = data + off;
    off += sizeof(struct udphdr);
    if (data + off > data_end) {
        return XDP_PASS;
    }
    // 根据目的端口将流量redirect到相应socket, 未命中则pass
    int dport = bpf_ntohs(udph->dest);
    return bpf_redirect_map(&udp_xsks_map, dport, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
