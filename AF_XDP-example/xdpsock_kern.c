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

static __always_inline void swap_src_dst_mac(void *data)
{
	__u16 *p = data;
	__u16 dst[3];

	dst[0] = p[0];
	dst[1] = p[1];
	dst[2] = p[2];
	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst[0];
	p[4] = dst[1];
	p[5] = dst[2];
}

static __always_inline void swap_src_dst_ip(struct iphdr *iph)
{
	__u32 src = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = src;
}

static __always_inline void swap_src_dst_udp(struct udphdr *udph)
{
	__u16 src = udph->source;
	udph->source = udph->dest;
	udph->dest = src;
}

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
    int dport = bpf_ntohs(udph->dest);
    if (bpf_map_lookup_elem(&udp_xsks_map, &dport)) {
        swap_src_dst_mac(ethh);
        swap_src_dst_ip(iph);
        swap_src_dst_udp(udph);

        return XDP_TX;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
