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

BPF_HASH(ip_interest, u32);   // should/could be BPF_LPM_TRIE
BPF_ARRAY(lastprobe, u64, (NUM_HOPS+1));
BPF_HISTOGRAM(vars, u64, NUM_VARS);
BPF_HASH(seqsend);
BPF_HASH(seqttl);
BPF_HASH(seqorigseq);
BPF_ARRAY(results, struct latency_sample, MAX_SAMPLES);
#if DEBUG
BPF_HISTOGRAM(xdebug, u64, 64);
#endif


static inline int _is_packet_of_interest(void *data, void *data_end, int *offset, struct _iphdr **iph, u64 *key) {
#if ETHER_ENCAP
    if (data + sizeof(struct _ethhdr)  > data_end) {
        return 0;
    }

    struct _ethhdr *eth = data;
    if (eth->ether_type != htons(ETHERTYPE_IP)) {
        return 0;
    }
#endif // ETHER_ENCAP
    *offset = L2_HLEN;

    // FIXME: ip6

    if (data + *offset + sizeof(struct _iphdr) > data_end) {
        return 0;
    }

    *iph = data + *offset;
    u32 dstip = (*iph)->daddr;
    u64 *xkey = NULL;
    if (NULL == (xkey = ip_interest.lookup(&dstip))) {
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
    if (!_is_packet_of_interest(data, data_end, &offset, &iphdr, &key)) {
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
    if (!_is_packet_of_interest(data, data_end, &offset, &iphdr, &key)) {
        return XDP_PASS;
    }
#if DEBUG
    xdebug.increment(13);
#endif

    uint8_t proto = iphdr->protocol;
    ingress_prog_array.call(ctx, proto);
    return XDP_PASS;
}
