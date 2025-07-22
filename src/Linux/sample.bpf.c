#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

#define MAX_INTERFACES 128
#define MAX_PKT_HDR_LEN 128
#define AF_INET 2
#define AF_INET6 10

struct packet_event_t {
    __u64 timestamp;
    __u32 ifindex;
    __u32 sampling_rate;
    __u32 ingress_ifindex;
    __u32 routed_ifindex;
    __u32 pkt_len;
    __u8  direction;
    __u8  hdr[MAX_PKT_HDR_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_INTERFACES);
} sampling SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} routing SEC(".maps");

static __always_inline __u32 get_route(struct __sk_buff *skb) {
    __u32 key = 0;
    __u32 *routing_enabled = bpf_map_lookup_elem(&routing, &key);
    if(!routing_enabled || !*routing_enabled)
	return 0;

    if(skb->pkt_type != PACKET_HOST)
	return 0;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    __u32 proto = bpf_ntohs(eth->h_proto);
    if(proto == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)(ip + 1) > data_end)
            return 0;
        struct bpf_fib_lookup fib = {0};
        fib.family      = AF_INET;
        fib.ipv4_src    = ip->saddr;
        fib.ipv4_dst    = ip->daddr;
        fib.tos         = ip->tos;
	fib.l4_protocol = ip->protocol;
	fib.sport       = 0;
	fib.dport       = 0;
	fib.tot_len     = bpf_ntohs(ip->tot_len);
        fib.ifindex     = skb->ifindex;
        long rc = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
        if(rc != BPF_FIB_LKUP_RET_SUCCESS)
	   return 0;
        return fib.ifindex;
    } else if(proto == ETH_P_IPV6) {
	struct ipv6hdr *ipv6 = data + sizeof(*eth);
        if ((void *)(ipv6 + 1) > data_end)
	    return 0;
        struct bpf_fib_lookup fib = {0};
        fib.family      = AF_INET6;
	__builtin_memcpy(fib.ipv6_src, &ipv6->saddr, sizeof(ipv6->saddr));
        __builtin_memcpy(fib.ipv6_dst, &ipv6->daddr, sizeof(ipv6->daddr));
	fib.flowinfo    = *(__be32 *) ipv6 & bpf_htonl(0x0FFFFFFF);
	fib.l4_protocol = ipv6->nexthdr;
	fib.sport       = 0;
	fib.dport       = 0;
	fib.tot_len     = bpf_ntohs(ipv6->payload_len);
        fib.ifindex     = skb->ifindex;
        long rc = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
        if(rc != BPF_FIB_LKUP_RET_SUCCESS)
           return 0;
        return fib.ifindex;	
    }
    return 0;
}

static __always_inline void sample_packet(struct __sk_buff *skb, __u8 direction) {
    __u32 key = skb->ifindex;
    __u32 *rate = bpf_map_lookup_elem(&sampling, &key);
    if (!rate || (*rate > 0 && bpf_get_prandom_u32() % *rate != 0))
        return;

    struct packet_event_t pkt = {};
    pkt.timestamp = bpf_ktime_get_ns();
    pkt.ifindex = skb->ifindex;
    pkt.sampling_rate = *rate;
    pkt.ingress_ifindex = skb->ingress_ifindex;
    pkt.routed_ifindex = direction ? 0 : get_route(skb);
    pkt.pkt_len = skb->len;
    pkt.direction = direction;

    __u32 hdr_len = skb->len < MAX_PKT_HDR_LEN ? skb->len : MAX_PKT_HDR_LEN;
    if (hdr_len > 0 && bpf_skb_load_bytes(skb, 0, pkt.hdr, hdr_len) < 0)
        return;
    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &pkt, sizeof(pkt));
}

SEC("tcx/ingress")
int tcx_ingress(struct __sk_buff *skb) {
    sample_packet(skb, 0);

    return TCX_NEXT;
}

SEC("tcx/egress")
int tcx_egress(struct __sk_buff *skb) {
    sample_packet(skb, 1);

    return TCX_NEXT;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
