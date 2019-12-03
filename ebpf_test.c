#define KBUILD_MODNAME "foo"
#include "someta_ebpf.h"

#define TC_ACT_OK  0
#define TC_ACT_SHOT 2
// #define XDP_PASS
// #define XDP_DROP

#define MAX_SAMPLES 4096

#if ETHER_ENCAP
#define L2_HLEN 14
#else
#define L2_HLEN 0
#endif


struct latency_sample {
    u64 seq;
    u64 origseq;
    u64 send;
    u64 recv;
    u16 sport;
    u16 dport;
    u32 responder;
    u32 target;
    u8 outttl;
    u8 recvttl;
};

// indices into vars array
#define PROBE_SEQ 0
#define LAST_PROBE 1
#define NEXT_RESULT 2
#define NUM_VARS 3

BPF_PROG_ARRAY(ingress_prog_array, 255);
BPF_PROG_ARRAY(egress_prog_array, 255);

BPF_LPM_TRIE(ip_interest, _in6_addr_t);   
BPF_ARRAY(lastprobe, u64, (NUM_HOPS+1));
BPF_HISTOGRAM(vars, u64, NUM_VARS);
BPF_HASH(seqsend);
BPF_HASH(seqttl);
BPF_HASH(seqorigseq);
BPF_ARRAY(results, struct latency_sample, MAX_SAMPLES);
#if DEBUG
BPF_HISTOGRAM(xdebug, u64, 64);
#endif


static inline int _is_packet_of_interest(void *data, void *data_end, int *offset, u8 *proto, u64 *key, int chkdst) {
#if ETHER_ENCAP
    if (data + sizeof(struct _ethhdr)  > data_end) {
        return 0;
    }

    struct _ethhdr *eth = data;
    if (eth->ether_type != htons(ETHERTYPE_IP) && eth->ether_type != htons(ETHERTYPE_IP6)) {
        return 0;
    }
#endif // ETHER_ENCAP
    *offset = L2_HLEN;

    u32 ipa[4] = {0,0,0,0};
    int l3_size = sizeof(struct _iphdr); 
    if (eth->ether_type == htons(ETHERTYPE_IP6)) {
        l3_size = sizeof(struct _ip6hdr);
    }

    if (data + *offset + l3_size > data_end) {
        return 0;
    }

    if (eth->ether_type == htons(ETHERTYPE_IP)) {
        struct _iphdr *iph = data + *offset;
        if (chkdst) {
            ipa[0] = iph->daddr;
        } else {
            ipa[0] = iph->saddr;
        }
        *proto = iph->protocol;
    } else {
        struct _ip6hdr *iph = data + *offset;
        if (chkdst) {
            ipa[0] = iph->daddr;
        } else {
            ipa[0] = iph->saddr;
        }
        *proto = iph->ip6_un1_nxt;
    }

    u64 *xkey = NULL;
    if (NULL == (xkey = ip_interest.lookup(&ipa))) {
        return 0;
    }
    *key = *xkey;

    // yup, the packet is of interest
    return 1;
}

int egress_path_icmp(struct __sk_buff *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
#if DEBUG
    xdebug.increment(101);
#endif
    return TC_ACT_OK;
}

int egress_path_tcp(struct __sk_buff *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
#if DEBUG
    xdebug.increment(106);
#endif
    return TC_ACT_OK;
}

int egress_path_udp(struct __sk_buff *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
#if DEBUG
    xdebug.increment(117);
#endif
    return TC_ACT_OK;
}

int egress_path(struct __sk_buff *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    int offset = 0;
    struct _iphdr *iphdr;
    u64 key = 0ULL;
#if DEBUG
    xdebug.increment(100);
#endif
    if (!_is_packet_of_interest(data, data_end, &offset, &iphdr, &key, 1)) {
        return TC_ACT_OK;
    }
#if DEBUG
    xdebug.increment(113);
#endif

    uint8_t proto = iphdr->protocol;
    egress_prog_array.call(ctx, proto);
    xdebug.increment(114);

    // no-op for now
    return TC_ACT_OK;
}

int ingress_path_icmp(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
#if DEBUG
    xdebug.increment(1);
#endif
    return XDP_PASS;
}

int ingress_path_tcp(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
#if DEBUG
    xdebug.increment(6);
#endif
    return XDP_PASS;
}

int ingress_path_udp(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
#if DEBUG
    xdebug.increment(17);
#endif
    return XDP_PASS;
}

int ingress_path(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    int offset = 0;
    struct _iphdr *iphdr;
    u64 key = 0ULL;
#if DEBUG
    xdebug.increment(0);
#endif
    if (!_is_packet_of_interest(data, data_end, &offset, &iphdr, &key, 0)) {
        xdebug.increment(12);
        return XDP_PASS;
    }
#if DEBUG
    xdebug.increment(13);
#endif

    uint8_t proto = iphdr->protocol;
    xdebug.increment(50+proto);
    ingress_prog_array.call(ctx, proto);
    xdebug.increment(14);
    return XDP_PASS;
}
