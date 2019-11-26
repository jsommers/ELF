/*
 * eBPF C code for in-band measurement; 
 * relies on Python driver to set certain preprocessor symbols
 * 
 * jsommers@colgate.edu
 */
#define KBUILD_MODNAME "foo"
#define BPF_LICENSE GPL
#include "someta_ebpf.h"

#if ETHER_ENCAP
#define L2_HLEN ETH_HLEN
#else
#define L2_HLEN 0
#endif

#define IP_TTL_OFF offsetof(struct _iphdr, ttl)
#define IP_SRC_OFF offsetof(struct _iphdr, saddr)
#define IP_DST_OFF offsetof(struct _iphdr, daddr)
#define IP_LEN_OFF offsetof(struct _iphdr, tot_len)
#define IP_CSUM_OFF offsetof(struct _iphdr, check)
#define ICMP_SEQ_OFF offsetof(struct _icmphdr, un.echo.sequence)
#define ICMP_ID_OFF offsetof(struct _icmphdr, un.echo.id)
#define ICMP_CSUM_OFF offsetof(struct _icmphdr, checksum)
#define TCP_SRC_OFF offsetof(struct _tcphdr, source)
#define TCP_DST_OFF offsetof(struct _tcphdr, dest)
#define TCP_SEQ_OFF offsetof(struct _tcphdr, seq)
#define TCP_ACK_OFF offsetof(struct _tcphdr, ack_seq)
#define TCP_URG_OFF offsetof(struct _tcphdr, urg_ptr)
#define TCP_WIN_OFF offsetof(struct _tcphdr, window)
#define TCP_CSUM_OFF offsetof(struct _tcphdr, check)

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

#define MAX_SAMPLES 4096

// indices into vars array
#define PROBE_SEQ 0
#define LAST_PROBE 1
#define NEXT_RESULT 2
#define NUM_VARS 3

BPF_HASH(ip4_interest, u32);   // should/could be BPF_LPM_TRIE
BPF_ARRAY(lastprobe, u64, (NUM_HOPS+1));
BPF_HISTOGRAM(vars, u64, NUM_VARS);
BPF_HASH(seqsend);
BPF_HASH(seqttl);
BPF_HASH(seqorigseq);
BPF_ARRAY(results, struct latency_sample, MAX_SAMPLES);


int ingress_path(struct xdp_md *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

#if ETHER_ENCAP
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }
    struct ethhdr *eth = (struct ethhdr *)data;

    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }
#endif // ETHER_ENCAP
    int offset = L2_HLEN;
    if (data + offset + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }

    struct iphdr *iph = (struct iphdr*)(data + offset);
    uint8_t proto = iph->protocol;
    if (proto != IPPROTO_ICMP) {
        return XDP_PASS;
    }

    offset = offset + (iph->ihl << 2);
    if (data + offset + sizeof(struct icmphdr) > data_end) {
        return XDP_PASS;
    }

    struct icmphdr *icmph = (struct icmphdr*)(data + offset);
    // is it a time exceeded message we're dealing with?
    if (icmph->type != ICMP_TIME_EXCEEDED || icmph->code != ICMP_EXC_TTL) {
        return XDP_PASS;
    }

    // FIXME: not doing this yet, but can use this len to determine
    // whether there are any extension headers a la rfc4884 
    // (and rfc4950 extensions in particular)
    int inner_pktlen = icmph->un.reserved[1];
    if (inner_pktlen == 0) {
        inner_pktlen = 28;
    }

    offset = offset + sizeof(struct icmphdr);
    // save srcip and ttl from outer IP header
    uint32_t srcip = iph->saddr;
    uint8_t recvttl = iph->ttl;
    if (data + offset + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }

    // the *inner* v4 header returned by some router where the packet died
    iph = (struct iphdr*)(data + offset);
    u32 origdst = iph->daddr;

    if (NULL == ip4_interest.lookup(&origdst)) {
        return XDP_PASS;
    }

#if DEBUG
    bpf_trace_printk("INGRESS ttl exc from 0x%x rttl %d\n", srcip, recvttl);
#endif

    u64 seq = 0, sendts = 0, sendttl = 0, origseq = 0;
    u16 sport = 0, dport = 0;
    int ippayload_offset = offset + sizeof(struct iphdr);
    // 28 bytes is standard payload for an ICMP time exceeded message; 
    // check whether we can safely access the last 8 bytes
    if (data + ippayload_offset + 8 > data_end) {
        return XDP_DROP;
    }

#if ICMPMODE
    seq = *(u16*)(data + ippayload_offset + ICMP_SEQ_OFF);
    seq = ntohs(seq);
#elif TCPMODE
    seq = *(u32*)(data + ippayload_offset + TCP_SEQ_OFF);
    seq = ntohl(seq);
    sport = *(u16*)(data + ippayload_offset);
    dport = *(u16*)(data + ippayload_offset + 2);
#endif // MODE

#if DEBUG
    bpf_trace_printk("incoming seq %llu\n", seq);
#endif

    u64 seqkey = ((u64)ntohl(origdst) << 32) | seq;
    u64 now = bpf_ktime_get_ns();
    u64 *val = seqsend.lookup(&seqkey);
    if (val) {
        sendts = *val;
        seqsend.delete(&seqkey);
    } 

    val = seqttl.lookup(&seqkey);
    if (val) {
       sendttl = *val;
       seqttl.delete(&seqkey);
    }

    val = seqorigseq.lookup(&seqkey);
    if (val) {
        origseq = *val;
        seqorigseq.delete(&seqkey);
    }

#if DEBUG
    u64 latency = now - sendts;
    bpf_trace_printk("matched seq %llu sendttl %llu recvttl %llu\n", seq, sendttl, recvttl);
    bpf_trace_printk("matched seq %llu ip 0x%x lat %llu\n", seq, srcip, latency);
#endif

    u64 key = NEXT_RESULT;
    u64 zero = 0;
    u64 *resultidx = vars.lookup_or_init(&key, &zero);
    if (!resultidx) {
        return XDP_DROP;
    }

    int idx = *resultidx % MAX_SAMPLES;
    struct latency_sample *samp = results.lookup(&idx);
    if (!samp) {
        return XDP_DROP;
    }
    samp->seq = seq;
    samp->origseq = origseq;
    samp->send = sendts;
    samp->recv = now;
    samp->sport = htons(sport);
    samp->dport = htons(dport);
    samp->responder = srcip;
    samp->target = origdst;
    samp->outttl = sendttl;
    samp->recvttl = recvttl;
    vars.increment(NEXT_RESULT);

    return XDP_DROP; // since this code generated the ttl-limited probe that 
                     // caused the ICMP time exceeded message, just drop it 
                     // so it doesn't get processed by the OS
}

static inline int _should_make_probe() {
#if BUNCH
    u64 min_interval = 100; // 0.1 microsec
#else
    u64 min_interval = PROBE_INTERVAL;
#endif
    u64 bkey = LAST_PROBE;
    u64 bzero = 0;
    u64 *lastbunchsend = vars.lookup_or_init(&bkey, &bzero);
    if (!lastbunchsend) {
        return 0;
    } else {
        u64 btime = bpf_ktime_get_ns(); 
        u64 bdiff = (btime - *lastbunchsend) / 1000; // put in microsec
        if (bdiff < min_interval) {
            return 0;
        }
        vars.update(&bkey, &btime);
    }

    // yes, clone the packet and make a new probe
    return 1;
}

static inline int _is_packet_of_interest(void *data, void *data_end, int *offset, struct iphdr **iph) {
#if ETHER_ENCAP
    if (data + sizeof(struct ethhdr)  > data_end) {
        return 0;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP)) {
        return 0;
    }
#endif // ETHER_ENCAP
    *offset = L2_HLEN;

    if (data + *offset + sizeof(struct iphdr) > data_end) {
        return 0;
    }

    *iph = data + *offset;
    int proto = (*iph)->protocol;
#if ICMPMODE
    if (proto != IPPROTO_ICMP) {
#elif TCPMODE
    if (proto != IPPROTO_TCP) {
#endif
        return 0;
    }

    u32 dstip = (*iph)->daddr;
    if (NULL == ip4_interest.lookup(&dstip)) {
        return 0;
    }

    // yup, the packet is of interest
    return 1;
}

static inline int _decide_ttl(u8 *probehop, u64 *probeseq, u64 *now) {
    u64 key = PROBE_SEQ;
    u64 zero = 0;
    u64 *seq = vars.lookup_or_init(&key, &zero);
    if (!seq) {
        return 0;
    }
    *probehop = *seq % NUM_HOPS + 1;
    *probeseq = *seq;

    // ensure that probes aren't emitted too closely
    int probekey = *probehop;
    u64 *ts = lastprobe.lookup(&probekey);
    u64 diff = 0;
    if (0 == ts) {
        return 0;
    }
    if (ts) {
        diff = (*now - *ts) / 1000; // put in microsec
        if (diff < PROBE_INTERVAL) {
            return 0;
        }
    }

#if DEBUG
    bpf_trace_printk("ts diff hop %llu ts 0x%x now 0x%x\n", probekey, *ts, *now);
    bpf_trace_printk("probe seq %llu\n", *seq);
#endif

    lastprobe.update(&probekey, now);
    vars.increment(PROBE_SEQ);

    return 1;
}

#if ICMPMODE
int egress_path_icmp(struct __sk_buff *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    int offset = 0;
    struct iphdr *iph = 0;
    if (0 == _is_packet_of_interest(data, data_end, &offset, &iph)) {
        return TC_ACT_OK;
    }

    // at this point, we know this packet is destined toward the host
    // of interest.
    u32 iphlen = iph->ihl << 2;
    offset = offset + iphlen;
    if (data + offset + sizeof(struct icmphdr) > data_end) {
        return TC_ACT_OK;
    }

    /*
     * decide whether to force PROBE_INTERVAL microseconds between
     * probes; default to 1 microsec as closest spacing of probes 
     * ("bunch mode")
     */
    if (0 == _should_make_probe()) {
        return TC_ACT_OK;
    }

    /*
     * decide what TTL to use in probe
     */
    u8 probehop = 0;
    u64 probeseq = 0;
    u64 now = bpf_ktime_get_ns(); 
    if (0 == _decide_ttl(&probehop, &probeseq, &now)) {
        return TC_ACT_OK;
    }

    u64 pktseq = 0, hopval = probehop, origseq = 0;
    pktseq = load_half(ctx, L2_HLEN + iphlen + ICMP_SEQ_OFF);
    origseq = pktseq;

#if DEBUG
    bpf_trace_printk("outgoing seq %llu\n", pktseq);
#endif
    u64 seqkey = load_word(ctx, L2_HLEN + IP_DST_OFF);
    seqkey = (seqkey << 32) | pktseq;
    seqsend.update(&seqkey, &now);
    seqttl.update(&seqkey, &hopval);
    seqorigseq.update(&seqkey, &origseq);

    // clone and redirect the original pkt out the intended interface
    int rv = bpf_clone_redirect(ctx, IFINDEX, 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("bpf clone ifidx %d failed: %d\n", IFINDEX, rv);
#endif
        // if clone fails, just let the packet pass w/o trying to do any modifications below
        return TC_ACT_OK;
    }

    u16 old_ttl_proto = load_half(ctx, L2_HLEN + IP_TTL_OFF);
    u16 new_ttl_proto = htons(((u16)probehop) << 8 | IPPROTO_ICMP);

    rv = bpf_l3_csum_replace(ctx, L2_HLEN + IP_CSUM_OFF, htons(old_ttl_proto), new_ttl_proto, 2);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("failed to replace csum icmp path\n");
#endif
        return TC_ACT_SHOT;
    }

    rv = bpf_skb_store_bytes(ctx, L2_HLEN + IP_TTL_OFF, &new_ttl_proto, sizeof(new_ttl_proto), 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("failed to store new ttl/proto icmp path\n");
#endif
        return TC_ACT_SHOT;
    }


#if DEBUG
    bpf_trace_printk("emitting probe %llu %llu\n", probeseq, pktseq);
#endif
    return TC_ACT_OK;
} 
#endif // ICMPMODE


#if TCPMODE
int egress_path_tcp(struct __sk_buff *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    int offset = 0;
    struct iphdr *iph = 0;

    if (0 == _is_packet_of_interest(data, data_end, &offset, &iph)) {
        return TC_ACT_OK;
    }

    // at this point, we know this packet is destined toward the host
    // of interest.
    int iphlen = iph->ihl << 2;
    offset = offset + iphlen;
    if (data + offset + sizeof(struct tcphdr) > data_end) {
        return TC_ACT_OK;
    }

    /*
     * decide whether to force PROBE_INTERVAL microseconds betwen
     * probes; default to 1 microsec as closest spacing of probes 
     * ("bunch mode")
     */
    if (0 == _should_make_probe()) {
        return TC_ACT_OK;
    }

    /*
     * decide what TTL to use in probe
     */
    u8 probehop = 0;
    u64 probeseq = 0;
    u64 now = bpf_ktime_get_ns(); 
    if (0 == _decide_ttl(&probehop, &probeseq, &now)) {
        return TC_ACT_OK;
    }

    // clone and redirect the original pkt out the intended interface
    int rv = bpf_clone_redirect(ctx, IFINDEX, 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("bpf clone ifidx %d failed: %d\n", IFINDEX, rv);
#endif
        // if clone fails, just let the packet pass w/o trying to do any modifications below
        return TC_ACT_OK;
    }

    u64 oldtcpseq = htonl(load_word(ctx, L2_HLEN + iphlen + TCP_SEQ_OFF));

    // create new tcp hdr to copy into packet
    struct tcphdr newtcp;
    __builtin_memset(&newtcp, 0, sizeof(struct tcphdr));
    newtcp.source = htons(load_half(ctx, L2_HLEN + iphlen + TCP_SRC_OFF));
    newtcp.dest = htons(load_half(ctx, L2_HLEN + iphlen + TCP_DST_OFF));
    newtcp.seq = htonl(probeseq);
    newtcp.doff = 0x5;
    newtcp.ack = 1;
    
    // get current header values 
    u16 curr_ip_len = htons(load_half(ctx, L2_HLEN + IP_LEN_OFF));
    u16 new_ip_len = iphlen + sizeof(struct tcphdr);

    // truncate packet
    rv = bpf_skb_change_tail(ctx, L2_HLEN + new_ip_len, 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("bpf trunc packet failed\n");
#endif
        return TC_ACT_SHOT;
    }

    rv = bpf_skb_store_bytes(ctx, L2_HLEN + iphlen, &newtcp, sizeof(struct tcphdr), 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("bpf store new tcp hdr failed\n");
#endif
        return TC_ACT_SHOT;
    }

    // change l4csum, including pseudoheader
    // these already get included in checksum...
    // rv = bpf_l4_csum_replace(ctx, L2_HLEN + iphlen + TCP_CSUM_OFF, 0, newtcp.source, 2);
    // rv = bpf_l4_csum_replace(ctx, L2_HLEN + iphlen + TCP_CSUM_OFF, 0, newtcp.dest, 2);
    // rv = bpf_l4_csum_replace(ctx, L2_HLEN + iphlen + TCP_CSUM_OFF, 0, newtcp.seq, 4);
    // u16 new_tcp_hdrflags = htons(((u16)0x5 << 12) | 0x2);
    // rv = bpf_l4_csum_replace(ctx, L2_HLEN + iphlen + TCP_CSUM_OFF, 0, new_tcp_hdrflags, 2);

    // add in pseudoheader words for tcp checksum
    u32 cword = htonl(load_word(ctx, L2_HLEN + IP_SRC_OFF));
    rv = bpf_l4_csum_replace(ctx, L2_HLEN + iphlen + TCP_CSUM_OFF, 0, cword, 4 | BPF_F_PSEUDO_HDR);
    cword = htonl(load_word(ctx, L2_HLEN + IP_DST_OFF));
    rv = bpf_l4_csum_replace(ctx, L2_HLEN + iphlen + TCP_CSUM_OFF, 0, cword, 4 | BPF_F_PSEUDO_HDR);
    cword = htonl(((u32)0x0006 << 16) | 20);
    rv = bpf_l4_csum_replace(ctx, L2_HLEN + iphlen + TCP_CSUM_OFF, 0, cword, 4 | BPF_F_PSEUDO_HDR);

    new_ip_len = htons(new_ip_len);
    rv = bpf_l3_csum_replace(ctx, L2_HLEN + IP_CSUM_OFF, curr_ip_len, new_ip_len, 2);
    rv = bpf_skb_store_bytes(ctx, L2_HLEN + IP_LEN_OFF, &new_ip_len, sizeof(new_ip_len), 0);

    u16 old_ttl_proto = load_half(ctx, L2_HLEN + IP_TTL_OFF);
    u16 new_ttl_proto = htons(((u16)probehop) << 8 | IPPROTO_TCP);

    rv = bpf_l3_csum_replace(ctx, L2_HLEN + IP_CSUM_OFF, htons(old_ttl_proto), new_ttl_proto, 2);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("failed to replace csum icmp path\n");
#endif
        return TC_ACT_SHOT;
    }

    rv = bpf_skb_store_bytes(ctx, L2_HLEN + IP_TTL_OFF, &new_ttl_proto, sizeof(new_ttl_proto), 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("failed to store new ttl/proto icmp path\n");
#endif
        return TC_ACT_SHOT;
    }

    u64 seqkey = load_word(ctx, L2_HLEN + IP_DST_OFF);
    seqkey = (seqkey << 32) | probeseq;
    u64 hopval = probehop;
    seqsend.update(&seqkey, &now);
    seqttl.update(&seqkey, &hopval);
    seqorigseq.update(&seqkey, &oldtcpseq);

#if DEBUG
    bpf_trace_printk("emitting probe %llu\n", probeseq);
#endif
    return TC_ACT_OK;
}
#endif // TCPMODE
