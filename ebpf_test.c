#define KBUILD_MODNAME "foo"
#include "someta_ebpf.h"

BPF_PROG_ARRAY(ingress_prog_array, 255);
BPF_HASH(ip4_interest, u32);   // should/could be BPF_LPM_TRIE
BPF_ARRAY(lastprobe, u64, (NUM_HOPS+1));
BPF_HISTOGRAM(vars, u64, NUM_VARS);
BPF_HASH(seqsend);
BPF_HASH(seqttl);
BPF_HASH(seqorigseq);
BPF_ARRAY(results, struct latency_sample, MAX_SAMPLES);



int egress_path(struct __sk_buff *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    // no-op for now
    return TC_ACT_OK;
}


static inline int _is_packet_of_interest(void *data, void *data_end, int *offset, struct _iphdr **iph, u64 *key) {
#if ETHER_ENCAP
    if (data + sizeof(struct ethhdr)  > data_end) {
        return 0;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETHERTYPE_IP)) {
        return 0;
    }
#endif // ETHER_ENCAP
    *offset = L2_HLEN;

    if (data + *offset + sizeof(struct iphdr) > data_end) {
        return 0;
    }

    *iph = data + *offset;
    u32 dstip = (*iph)->daddr;
    u64 *xkey = NULL;
    if (NULL == (xkey = ip4_interest.lookup(&dstip))) {
        return 0;
    }
    key = *xkey;

    // yup, the packet is of interest
    return 1;
}

int ingress_path_icmp(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    return XDP_PASS;
}

int ingress_path_tcp(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    return XDP_PASS;
}

int ingress_path_udp(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    return XDP_PASS;
}

int ingress_path(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    int offset = 0;
    struct _iphdr *iphdr;
    u64 key = 0ULL;
    if (!_is_packet_of_interest(data, data_end, &offset, &iphdr, &key)) {
        return XDP_PASS;
    }

    uint8_t proto = iphdr->protocol;
    ingress_prog_array.call(ctx, proto);
    return XDP_PASS;
}
