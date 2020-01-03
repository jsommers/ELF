/*
 * FIXME: header for this file
 */

#define BPF_LICENSE GPL
#define KBUILD_MODNAME "foo"

// largely copies of linux header definitions.
// why?  to avoid any #includes and kernel dependencies

#define ETH_ALEN 6

typedef uint32_t _in_addr_t;
typedef struct in6_addr {
    union {
        uint32_t _addr32[4];
        uint16_t _addr16[8];
        uint8_t _addr8[16];
    } _u;
} _in6_addr_t;

struct _ethhdr {
  uint8_t  ether_dhost[ETH_ALEN];       /* destination eth addr */
  uint8_t  ether_shost[ETH_ALEN];       /* source ether addr    */
  uint16_t ether_type;                  /* packet type ID field */
} __attribute__ ((__packed__));

struct _iphdr {
    uint8_t verihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
};
    
struct _ip6hdr {
    uint32_t ip6_un1_flow;  /* 4 bits version, 8 bits TC,
                               20 bits flow-ID */
    uint16_t payload_length;/* payload length */
    uint8_t  protocol;      /* next header */
    uint8_t  hop_limit;     /* hop limit */
    _in6_addr_t saddr;      /* source address */
    _in6_addr_t daddr;      /* destination address */
};

struct _udphdr {
    uint16_t uh_sport;        /* source port */
    uint16_t uh_dport;        /* destination port */
    uint16_t uh_ulen;         /* udp length */
    uint16_t uh_sum;          /* udp checksum */
};

struct _tcphdr {
    uint16_t th_sport;      /* source port */
    uint16_t th_dport;      /* destination port */
    uint32_t th_seq;         /* sequence number */
    uint32_t th_ack;         /* acknowledgement number */
    uint8_t  th_off;
    uint8_t  th_flags;
# define TH_FIN 0x01
# define TH_SYN 0x02
# define TH_RST 0x04
# define TH_PUSH        0x08
# define TH_ACK 0x10
# define TH_URG 0x20
    uint16_t th_win;        /* window */
    uint16_t th_sum;        /* checksum */
    uint16_t th_urp;        /* urgent pointer */
};

struct _icmphdr {
    uint8_t     icmp_type;   /* type field */
    uint8_t     icmp_code;   /* code field */
    uint16_t    icmp_cksum;  /* checksum field */
    uint8_t     icmp_reserved[4];
};

#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17
#define IPPROTO_ICMP6   58

#define ETHERTYPE_IP        0x0800
#define ETHERTYPE_IP6       0x86dd 

#define ICMP6_DST_UNREACH             1
#define ICMP6_TIME_EXCEEDED           3
#define ICMP6_ECHO_REQUEST          128
#define ICMP6_ECHO_REPLY            129

#define ICMP_ECHO_REPLY         0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ICMP_ECHO_REQUEST       8       /* Echo Request                 */
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */

#ifndef TC_ACT_OK
#define TC_ACT_OK       0
#define TC_ACT_SHOT     2
#endif

#ifndef FALSE
#define FALSE 0
#define TRUE 1
#endif

#define MAXDEST     128
#define MAXRESULTS  8192
#define RESULTS_IDX 256

#define IP_TTL_OFF offsetof(struct _iphdr, ttl)
#define IP_SRC_OFF offsetof(struct _iphdr, saddr)
#define IP_DST_OFF offsetof(struct _iphdr, daddr)
#define IP_LEN_OFF offsetof(struct _iphdr, tot_len)
#define IP_CSUM_OFF offsetof(struct _iphdr, check)
#define ICMP_CSUM_OFF offsetof(struct _icmphdr, icmp_cksum)
#define ICMP_TYPE_OFF offsetof(struct _icmphdr, icmp_type)
#define ICMP_ID_OFF offsetof(struct _icmphdr, icmp_reserved[0])
#define ICMP_SEQ_OFF offsetof(struct _icmphdr, icmp_reserved[2])
#define TCP_SRC_OFF offsetof(struct _tcphdr, th_sport)
#define TCP_DST_OFF offsetof(struct _tcphdr, th_dport)
#define TCP_SEQ_OFF offsetof(struct _tcphdr, th_seq)
#define TCP_ACK_OFF offsetof(struct _tcphdr, th_ack)
#define TCP_URG_OFF offsetof(struct _tcphdr, th_urp)
#define TCP_WIN_OFF offsetof(struct _tcphdr, th_win)
#define TCP_CSUM_OFF offsetof(struct _tcphdr, th_sum)
#define UDP_SRC_OFF offsetof(struct _udphdr, uh_sport)
#define UDP_DST_OFF offsetof(struct _udphdr, uh_dport)
#define UDP_CSUM_OFF offsetof(struct _udphdr, uh_sum)

struct probe_dest {
    u32         hop_bitmap;
    u32         hop_mask;
    u16         sequence;
    u16         next_hop_to_probe;
    u16         maxttl;
    u16         pad;
    u64         last_send;
    u64         last_mttl_update;
    _in6_addr_t dest;
};

struct sent_info {
    u64         send_time;
    _in6_addr_t dest;
    u16         sport; 
    u16         dport; 
    u32         origseq;
    u8          outttl;
    u8          protocol;
    u16         pad1;
    u32         pad2;
};

struct latency_sample {
    u16         sequence;
    u16         pad1;
    u32         origseq;
    u64         send;
    u64         recv;
    u16         sport;
    u16         dport;
    u8          outttl;
    u8          recvttl;
    u8          protocol;
    u8          pad2;
    _in6_addr_t responder;
    _in6_addr_t target;
};

BPF_PROG_ARRAY(ingress_layer3, 8);
BPF_PROG_ARRAY(egress_layer3, 8);
BPF_PROG_ARRAY(egress_v4_proto, 256);
BPF_PROG_ARRAY(egress_v6_proto, 256);

BPF_HASH(trie, _in6_addr_t, u64); // key: dest address
BPF_HISTOGRAM(counters, u64, RESULTS_IDX*2);
BPF_ARRAY(destinfo, struct probe_dest, MAXDEST); // index: value in trie hash
BPF_HASH(sentinfo, u64, struct sent_info); // key: destid | sequence
BPF_ARRAY(results, struct latency_sample, MAXRESULTS); // key: index 0 in counters

static inline void _update_maxttl(int idx, int ttl) {
    struct probe_dest *pd = destinfo.lookup(&idx);

    if (pd == NULL) {
        return;
    }
    u64 now = bpf_ktime_get_ns();
    // only update maxttl at most every second
    if (now - pd->last_mttl_update < 1000000000ULL) {
        return;
    }

    int num_hops = 16; 
    if (ttl > 128) {
        num_hops = 255 - ttl + 1;
    } else if (ttl > 64) {
        num_hops = 128 - ttl + 1;
    } else if (ttl > 32) {
        num_hops = 64 - ttl + 1;
    } else {
        num_hops = 32 - ttl + 1;
    }
#ifdef DEBUG
        bpf_trace_printk("updated maxttl to %d\n", num_hops);
#endif
    pd->maxttl = num_hops;
    pd->last_mttl_update = now;
}

static inline void _decide_seq_ttl(struct probe_dest *pd, u16 *seq, u8 *ttl) {
    if (pd->sequence == 0) {
        pd->sequence++;
    }
    *seq = pd->sequence;
    pd->sequence++;

#if DEBUG
    bpf_trace_printk("EGRESS decide seqttl bitmap 0x%x mask 0x%x seq %d\n", pd->hop_bitmap, pd->hop_mask, *seq);
#endif
    
#pragma unroll
    for (u16 i = 0; i < 8; i++) {
        u16 hop = (pd->next_hop_to_probe + i) % pd->maxttl;
        if (*seq < pd->maxttl || 
            ((pd->hop_mask >> hop) & 0x1) == 0x1 ||
            ((pd->hop_bitmap >> hop) & 0x1) == 0x1) {
            *ttl = (u8)(hop + 1);
            pd->next_hop_to_probe = (hop + 1) % pd->maxttl;
            return;
        }
    }
    *ttl = (u8)((pd->next_hop_to_probe % pd->maxttl) + 1);
    pd->next_hop_to_probe = (pd->next_hop_to_probe + 1) % pd->maxttl;
}

static inline int _should_probe_dest(int idx) {
    struct probe_dest *pd = destinfo.lookup(&idx);
    if (pd == NULL) {
        return FALSE;
    }

    u64 now = bpf_ktime_get_ns();
    if ((now - pd->last_send) > MIN_PROBE) {
        return TRUE;
    }

    return FALSE;
}

int egress_v4_icmp(struct __sk_buff *ctx) {
#if DEBUG
    bpf_trace_printk("egress v4 icmp mark %d\n", ctx->mark);
#endif
    int idx = ctx->mark;
    struct probe_dest *pd = destinfo.lookup(&idx);
    if (pd == NULL) {
        return TC_ACT_OK;
    }

    //
    // boilerplate to get a pointer to icmphdr for cloning and 
    // probe generation
    //
    int offset = NHOFFSET;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    if (data + offset + sizeof(struct _iphdr) > data_end) {
        return TC_ACT_OK;
    }
    struct _iphdr *iph = (struct _iphdr*)(data + offset);
    offset = offset + ((iph->verihl&0x0f) << 2);
    struct _icmphdr *icmph = (struct _icmphdr*)(data + offset);
    if (data + offset + sizeof(struct _icmphdr) > data_end) {
        return TC_ACT_OK;
    }
    if (icmph->icmp_type != ICMP_ECHO_REQUEST) {
        return TC_ACT_OK;
    }

    // decide what TTL to use in probe
    u64 now = bpf_ktime_get_ns();
    u16 origseq = load_half(ctx, offset + ICMP_SEQ_OFF);
    u16 sequence = 0;
    u8 newttl = 0;
    u32 destaddr = load_word(ctx, NHOFFSET + IP_DST_OFF);
    _decide_seq_ttl(pd, &sequence, &newttl);
    
#if DEBUG
    bpf_trace_printk("EGRESS outgoing seq %lu\n", sequence);
#endif

    // clone and redirect the original pkt out the intended interface
    int rv = bpf_clone_redirect(ctx, IFINDEX, 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS bpf clone ifidx %d failed: %d\n", IFINDEX, rv);
#endif
        // if clone fails, just let the packet pass w/o trying to do any modifications below
        return TC_ACT_OK;
    }
#if DEBUG
    bpf_trace_printk("EGRESS after clone emit tcp4 %lu\n", sequence);
#endif

    u16 old_ttl_proto = load_half(ctx, NHOFFSET + IP_TTL_OFF);
    u16 new_ttl_proto = htons(((u16)newttl) << 8 | IPPROTO_ICMP);

    // replace the IP checksum
    rv = bpf_l3_csum_replace(ctx, NHOFFSET + IP_CSUM_OFF, htons(old_ttl_proto), new_ttl_proto, 2);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("failed to replace csum icmp path\n");
#endif
        return TC_ACT_SHOT;
    }

    // rewrite new IP ttl
    rv = bpf_skb_store_bytes(ctx, NHOFFSET + IP_TTL_OFF, &new_ttl_proto, sizeof(new_ttl_proto), 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("failed to store new ttl/proto icmp path\n");
#endif
        return TC_ACT_SHOT;
    }

    // rewrite seq in ICMP hdr
    u16 oldseq = load_half(ctx, offset + ICMP_SEQ_OFF);
    u16 newseq = htons(sequence);
    rv = bpf_skb_store_bytes(ctx, offset + ICMP_SEQ_OFF, &newseq, sizeof(newseq), 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("failed to store new icmp seq\n");
#endif
        return TC_ACT_SHOT;
    }
    newseq = ntohs(newseq);

    // fixup ICMP checksum
    u16 oldcsum = load_half(ctx, offset + ICMP_CSUM_OFF);
    u16 newcsum = oldcsum - (newseq - oldseq); 
    newcsum = htons(newcsum);
    rv = bpf_skb_store_bytes(ctx, offset + ICMP_CSUM_OFF, &newcsum, sizeof(newcsum), 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("failed to store new icmp csum\n");
#endif
        return TC_ACT_SHOT;
    }

    // save info about outgoing probe into hash
    // hashed on: idx|sequence
    pd->last_send = now;
    u64 sentkey = (u64)idx << 32 | (u64)sequence;
    _in6_addr_t destaddr6 = {{{ destaddr, 0, 0, 0 }}};
    u16 sport = load_half(ctx, offset + ICMP_TYPE_OFF);
    u16 dport = load_half(ctx, offset + ICMP_CSUM_OFF);
    struct sent_info si = {
        .send_time = now,
        .dest = destaddr6,
        .sport = sport,
        .dport = dport,
        .origseq = origseq,
        .outttl = newttl,
        .protocol = IPPROTO_ICMP,
    };
    sentinfo.update(&sentkey, &si);

#if DEBUG
    bpf_trace_printk("EGRESS emitting probe icmpv4 %lu\n", sequence);
#endif
    return TC_ACT_OK;
}

int egress_v4_tcp(struct __sk_buff *ctx) {
#if DEBUG
    bpf_trace_printk("EGRESS v4 tcp mark %d\n", ctx->mark);
#endif

    int idx = ctx->mark;
    struct probe_dest *pd = destinfo.lookup(&idx);
    if (pd == NULL) {
        return TC_ACT_OK;
    }

    //
    // boilerplate to get a pointer to tcphdr for cloning and 
    // probe generation
    //
    int offset = NHOFFSET;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    if (data + offset + sizeof(struct _iphdr) > data_end) {
        return TC_ACT_OK;
    }
    struct _iphdr *iph = (struct _iphdr*)(data + offset);
    int iphlen = (iph->verihl&0x0f) << 2;
    offset = offset + iphlen;
    /*
    struct _tcphdr *tcph = (struct _tcphdr*)(data + offset);
    if (data + offset + sizeof(struct _tcphdr) > data_end) {
        return TC_ACT_OK;
    }
    */

    // decide what TTL to use in probe
    u16 sport = load_half(ctx, offset + TCP_SRC_OFF);
    u16 dport = load_half(ctx, offset + TCP_DST_OFF);

    u64 now = bpf_ktime_get_ns();
    u32 origseq = ntohs(load_word(ctx, offset + TCP_SEQ_OFF));
    u16 sequence = 0;
    u8 newttl = 0;
    u32 destaddr = htonl(load_word(ctx, NHOFFSET + IP_DST_OFF));
    _decide_seq_ttl(pd, &sequence, &newttl);
    
#if DEBUG
    bpf_trace_printk("EGRESS outgoing seq %lu\n", sequence);
#endif

    // clone and redirect the original pkt out the intended interface
    int rv = bpf_clone_redirect(ctx, IFINDEX, 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS bpf clone ifidx %d failed: %d\n", IFINDEX, rv);
#endif
        // if clone fails, just let the packet pass w/o trying to do any modifications below
        return TC_ACT_OK;
    }
#ifdef DEBUG
    bpf_trace_printk("EGRESS after clone emit tcp4 %lu\n", sequence);
#endif

    struct _tcphdr newtcp;
    __builtin_memset(&newtcp, 0, sizeof(struct _tcphdr));
    newtcp.th_sport = htons(sport);
    newtcp.th_dport = htons(dport);
    newtcp.th_seq = htonl(sequence);
    newtcp.th_ack = htonl(load_word(ctx, NHOFFSET + iphlen + TCP_ACK_OFF));
    newtcp.th_off = 0x50;
    newtcp.th_flags = TH_ACK;

    // get current header values 
    u16 curr_ip_len = load_half(ctx, NHOFFSET + IP_LEN_OFF);
    u16 new_ip_len = iphlen + sizeof(struct _tcphdr);

#if DEBUG
    bpf_trace_printk("EGRESS tcp4 truncating pkt from %d to %d\n", curr_ip_len, new_ip_len);
#endif

    // truncate packet
    rv = bpf_skb_change_tail(ctx, NHOFFSET + new_ip_len, 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS bpf trunc packet failed\n");
#endif
        return TC_ACT_SHOT;
    }

    rv = bpf_skb_store_bytes(ctx, NHOFFSET + iphlen, &newtcp, sizeof(struct _tcphdr), 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS bpf store new tcp hdr failed\n");
#endif
        return TC_ACT_SHOT;
    }

    // add in pseudoheader words for tcp checksum
    u32 cword = htonl(load_word(ctx, NHOFFSET + IP_SRC_OFF));
    rv = bpf_l4_csum_replace(ctx, NHOFFSET + iphlen + TCP_CSUM_OFF, 0, cword, 4 | BPF_F_PSEUDO_HDR);
    cword = htonl(load_word(ctx, NHOFFSET + IP_DST_OFF));
    rv = bpf_l4_csum_replace(ctx, NHOFFSET + iphlen + TCP_CSUM_OFF, 0, cword, 4 | BPF_F_PSEUDO_HDR);
    cword = htonl(((u32)IPPROTO_TCP << 16) | 20);
    rv = bpf_l4_csum_replace(ctx, NHOFFSET + iphlen + TCP_CSUM_OFF, 0, cword, 4 | BPF_F_PSEUDO_HDR);

    new_ip_len = htons(new_ip_len);
    curr_ip_len = htons(curr_ip_len);
    rv = bpf_l3_csum_replace(ctx, NHOFFSET + IP_CSUM_OFF, curr_ip_len, new_ip_len, 2);
    rv = bpf_skb_store_bytes(ctx, NHOFFSET + IP_LEN_OFF, &new_ip_len, sizeof(new_ip_len), 0);

    u16 old_ttl_proto = load_half(ctx, NHOFFSET + IP_TTL_OFF);
    u16 new_ttl_proto = htons(((u16)newttl) << 8 | IPPROTO_TCP);

    rv = bpf_l3_csum_replace(ctx, NHOFFSET + IP_CSUM_OFF, htons(old_ttl_proto), new_ttl_proto, 2);
#if DEBUG
    bpf_trace_printk("EGRESS after replace csum tcp4 path\n");
#endif

    rv = bpf_skb_store_bytes(ctx, NHOFFSET + IP_TTL_OFF, &new_ttl_proto, sizeof(new_ttl_proto), 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS failed to store new ttl/proto tcp4 path\n");
#endif
        return TC_ACT_SHOT;
    }

    // save info about outgoing probe into hash
    // hashed on: idx|sequence
    pd->last_send = now;
    u64 sentkey = (u64)idx << 32 | (u64)sequence;
    _in6_addr_t destaddr6 = {{{ destaddr, 0, 0, 0 }}};
    struct sent_info si = {
        .send_time = now,
        .dest = destaddr6,
        .sport = sport,
        .dport = dport,
        .origseq = origseq,
        .outttl = newttl,
        .protocol = IPPROTO_TCP,
    };
    sentinfo.update(&sentkey, &si);

#if DEBUG
    bpf_trace_printk("EGRESS emitting tcpv4 probe %llu\n", sequence);
#endif
    return TC_ACT_OK;
}

int egress_v4_udp(struct __sk_buff *ctx) {
#if DEBUG
    bpf_trace_printk("EGRESS v4 udp mark %d\n", ctx->mark);
#endif

    int idx = ctx->mark;
    struct probe_dest *pd = destinfo.lookup(&idx);
    if (pd == NULL) {
        return TC_ACT_OK;
    }

    //
    // boilerplate to get a pointer to udphdr for cloning and 
    // probe generation
    //
    int offset = NHOFFSET;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    if (data + offset + sizeof(struct _iphdr) > data_end) {
        return TC_ACT_OK;
    }
    struct _iphdr *iph = (struct _iphdr*)(data + offset);
    int iphlen = (iph->verihl&0x0f) << 2;
    offset = offset + iphlen;
    /*
    struct _udphdr *udph = (struct _udphdr*)(data + offset);
    if (data + offset + sizeof(struct _udphdr) > data_end) {
        return TC_ACT_OK;
    }
    */

    // decide what TTL to use in probe
    u64 now = bpf_ktime_get_ns();
    u16 origseq = load_half(ctx, offset + UDP_CSUM_OFF);
    u16 sequence = 0;
    u8 newttl = 0;
    u32 destaddr = htonl(load_word(ctx, NHOFFSET + IP_DST_OFF));
    _decide_seq_ttl(pd, &sequence, &newttl);
    u16 sport = load_half(ctx, offset + UDP_SRC_OFF);
    u16 dport = load_half(ctx, offset + UDP_DST_OFF);
    
#if DEBUG
    bpf_trace_printk("EGRESS udp4 outgoing seq %lu\n", sequence);
#endif

    // clone and redirect the original pkt out the intended interface
    int rv = bpf_clone_redirect(ctx, IFINDEX, 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS udp4 bpf clone ifidx %d failed: %d\n", IFINDEX, rv);
#endif
        // if clone fails, just let the packet pass w/o trying to do any modifications below
        return TC_ACT_OK;
    }
#ifdef DEBUG
    bpf_trace_printk("EGRESS after clone emit udp4 %lu\n", sequence);
#endif

    struct _udphdr newudp;
    u16 uhlen = 10;
    __builtin_memset(&newudp, 0, sizeof(struct _udphdr));
    newudp.uh_sport = htons(sport);
    newudp.uh_dport = htons(dport);
    newudp.uh_ulen = htons(uhlen);

    // get current header values 
    u16 curr_ip_len = load_half(ctx, NHOFFSET + IP_LEN_OFF);
    u16 new_ip_len = iphlen + sizeof(struct _udphdr) + 2;

#if DEBUG
    bpf_trace_printk("EGRESS tcp4 truncating pkt from %d to %d\n", curr_ip_len, new_ip_len);
#endif

    // truncate packet
    rv = bpf_skb_change_tail(ctx, NHOFFSET + new_ip_len, 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS bpf trunc packet failed\n");
#endif  
        return TC_ACT_SHOT;
    }

    rv = bpf_skb_store_bytes(ctx, NHOFFSET + iphlen, &newudp, sizeof(struct _udphdr), 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS udp4 bpf store new udp hdr failed\n");
#endif
        return TC_ACT_SHOT;
    }

    // add in pseudoheader words for udp checksum
    /*
    u32 cword = htonl(load_word(ctx, NHOFFSET + IP_SRC_OFF));
    rv = bpf_l4_csum_replace(ctx, NHOFFSET + iphlen + TCP_CSUM_OFF, 0, cword, 4 | BPF_F_PSEUDO_HDR);
    cword = htonl(load_word(ctx, NHOFFSET + IP_DST_OFF));
    rv = bpf_l4_csum_replace(ctx, NHOFFSET + iphlen + TCP_CSUM_OFF, 0, cword, 4 | BPF_F_PSEUDO_HDR);
    cword = htonl(((u32)IPPROTO_UDP << 16) | 10);
    rv = bpf_l4_csum_replace(ctx, NHOFFSET + iphlen + TCP_CSUM_OFF, 0, cword, 4 | BPF_F_PSEUDO_HDR);
    */

    u32 hword_sum = htons(sport);
    hword_sum += htons(dport);
    hword_sum += htons(uhlen);
    hword_sum += htonl(load_word(ctx, NHOFFSET + IP_SRC_OFF));
    hword_sum += htonl(load_word(ctx, NHOFFSET + IP_DST_OFF));
    hword_sum += htonl(((u32)IPPROTO_UDP << 16) | uhlen);
    hword_sum += htons((u16)sequence);
    hword_sum = (hword_sum >> 16) + (hword_sum & 0xffff);
    hword_sum += (hword_sum >> 16);
    u16 extra_halfword = ntohs(~hword_sum & 0xffff);
#if DEBUG
    bpf_trace_printk("EGRESS udp4 checksum sport 0x%x dport 0x%x\n", htons(sport), htons(dport));
    bpf_trace_printk("EGRESS udp4 checksum uhlen 0x%x protolen 0x%x\n", htons(uhlen), htonl(((u32)IPPROTO_UDP << 16) | uhlen));
    bpf_trace_printk("EGRESS udp4 checksum ipsrc 0x%x ipdst 0x%x\n", htonl(load_word(ctx, NHOFFSET + IP_SRC_OFF)), htonl(load_word(ctx, NHOFFSET + IP_DST_OFF)));
    bpf_trace_printk("EGRESS udp4 checksum seq 0x%x ehalfword 0x%x\n", htons((u16)sequence), extra_halfword);
#endif

    rv = bpf_skb_store_bytes(ctx, NHOFFSET + iphlen + sizeof(struct _udphdr), &extra_halfword, 2, 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS udp4 failed to store udp payload bytes to force csum\n");
#endif
        return TC_ACT_SHOT;
    }
    sequence = htons(sequence);
    rv = bpf_skb_store_bytes(ctx, NHOFFSET + iphlen + UDP_CSUM_OFF, &sequence, sizeof(sequence), 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS udp4 failed to store udp new csum\n");
#endif
        return TC_ACT_SHOT;
    }

    new_ip_len = htons(new_ip_len);
    curr_ip_len = htons(curr_ip_len);
    rv = bpf_l3_csum_replace(ctx, NHOFFSET + IP_CSUM_OFF, curr_ip_len, new_ip_len, 2);
    rv = bpf_skb_store_bytes(ctx, NHOFFSET + IP_LEN_OFF, &new_ip_len, sizeof(new_ip_len), 0);

    u16 old_ttl_proto = load_half(ctx, NHOFFSET + IP_TTL_OFF);
    u16 new_ttl_proto = htons(((u16)newttl) << 8 | IPPROTO_UDP);

    rv = bpf_l3_csum_replace(ctx, NHOFFSET + IP_CSUM_OFF, htons(old_ttl_proto), new_ttl_proto, 2);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS failed to replace csum udp4 path\n");
#endif
        return TC_ACT_SHOT;
    }

    rv = bpf_skb_store_bytes(ctx, NHOFFSET + IP_TTL_OFF, &new_ttl_proto, sizeof(new_ttl_proto), 0);
    if (rv < 0) {
#if DEBUG
        bpf_trace_printk("EGRESS failed to store new ttl/proto udp4 path\n");
#endif
        return TC_ACT_SHOT;
    }

    // save info about outgoing probe into hash
    // hashed on: idx|sequence
    pd->last_send = now;
    u64 sentkey = (u64)idx << 32 | (u64)sequence;
    _in6_addr_t destaddr6 = {{{ destaddr, 0, 0, 0 }}};
    struct sent_info si = {
        .send_time = now,
        .dest = destaddr6,
        .sport = sport,
        .dport = dport,
        .origseq = origseq,
        .outttl = newttl,
        .protocol = IPPROTO_UDP,
    };
    sentinfo.update(&sentkey, &si);

#if DEBUG
    bpf_trace_printk("EGRESS emitting udpv4 probe %llu\n", sequence);
#endif

    return TC_ACT_OK;
}

int egress_v4(struct __sk_buff *ctx) {
    int offset = NHOFFSET;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    if (data + offset + sizeof(struct _iphdr) > data_end) {
        return TC_ACT_OK;
    }
    struct _iphdr *iph = (struct _iphdr*)(data + offset);
    _in6_addr_t dest = {{{ iph->daddr, 0, 0, 0 }}};
    u64 *val = NULL;
    if ((val = trie.lookup(&dest)) == NULL) {
        return TC_ACT_OK;
    }

    // dest addr matches a destination of interest
    int idx = (int)*val;
#ifdef DEBUG
    bpf_trace_printk("EGRESS v4 dest of interest -- idx %d, currmark %d\n", idx, ctx->mark);
#endif
    // store idx in ctx for later reference
    ctx->mark = idx;

    if (!_should_probe_dest(idx)) {
        return TC_ACT_OK;
    }
#ifdef DEBUG
    bpf_trace_printk("EGRESS v4 should probe -- idx %d proto %d\n", idx, iph->protocol);
#endif

    // jump to code to handle egress v4 for icmp/tcp/udp
    egress_v4_proto.call(ctx, iph->protocol);

    return TC_ACT_OK;
}

int egress_v6_icmp(struct __sk_buff *ctx) {
#if DEBUG
    bpf_trace_printk("egress v6 icmp mark %d\n", ctx->mark);
#endif

    return TC_ACT_OK;
}

int egress_v6_tcp(struct __sk_buff *ctx) {
#if DEBUG
    bpf_trace_printk("egress v6 tcp mark %d\n", ctx->mark);
#endif
    return TC_ACT_OK;
}

int egress_v6_udp(struct __sk_buff *ctx) {
#if DEBUG
    bpf_trace_printk("egress v6 udp mark %d\n", ctx->mark);
#endif
    return TC_ACT_OK;
}

int egress_v6(struct __sk_buff *ctx) {
    int offset = NHOFFSET;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    if (data + offset + sizeof(struct _ip6hdr) > data_end) {
        return TC_ACT_OK;
    }
    struct _ip6hdr *iph = (struct _ip6hdr*)(data + offset);
    _in6_addr_t dest = iph->daddr;
    u64 *val = NULL;
    if ((val = trie.lookup(&dest)) == NULL) {
        return TC_ACT_OK;
    }

    // dest addr matches a destination of interest
    int idx = (int)*val;
#ifdef DEBUG
    bpf_trace_printk("egress v6 dest of interest -- idx %d, currmark %d\n", idx, ctx->mark);
#endif
    // store idx in ctx for future reference
    ctx->mark = idx;

    if (!_should_probe_dest(idx)) {
        return TC_ACT_OK;
    }
#ifdef DEBUG
    bpf_trace_printk("egress v6 should probe -- idx %d\n", idx);
#endif

    // jump to code to handle egress v6 for icmp/tcp/udp
    egress_v6_proto.call(ctx, iph->protocol);

    return TC_ACT_OK;
}

int egress_path(struct __sk_buff *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    if (ctx->mark != 0) {
#if DEBUG
        bpf_trace_printk("ignoring packet that we've already cloned\n");
#endif
        return TC_ACT_OK;
    }

    int ipproto = 0;
#if TUNNEL == 4
    ipproto = 4;
#elif TUNNEL == 6
    ipproto = 6;
#else
    if (data + sizeof(struct _ethhdr) > data_end) {
        return TC_ACT_OK;
    }
    struct _ethhdr *eth = (struct _ethhdr *)data;
    if (eth->ether_type == htons(ETHERTYPE_IP)) {
        ipproto = 4;
    } else if (eth->ether_type == htons(ETHERTYPE_IP6)) {
        ipproto = 6;
    }
#endif

    egress_layer3.call(ctx, ipproto);
    return TC_ACT_OK; 
}

int ingress_path(struct xdp_md *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    int ipproto = 0;
#if TUNNEL == 4
    ipproto = 4;
#elif TUNNEL == 6
    ipproto = 6;
#else
    if (data + sizeof(struct _ethhdr) > data_end) {
        return XDP_PASS;
    }
    struct _ethhdr *eth = (struct _ethhdr *)data;
    if (eth->ether_type == htons(ETHERTYPE_IP)) {
        ipproto = 4;
    } else if (eth->ether_type == htons(ETHERTYPE_IP6)) {
        ipproto = 6;
    }
#endif

    ingress_layer3.call(ctx, ipproto);
    return XDP_PASS;
}

int ingress_v4(struct xdp_md *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    int offset = NHOFFSET;
    if (data + offset + sizeof(struct _iphdr) > data_end) {
        return XDP_PASS;
    }
    struct _iphdr *iph = (struct _iphdr*)(data + offset);

    _in6_addr_t source = {{{ iph->saddr, 0, 0, 0 }}};
    u64 *val = NULL;
    if ((val = trie.lookup(&source)) != NULL) {
        // source address matches a destination of interest.
        // update our estimate of maxttl for this destination, but
        // that's it.
        int idx = (int)*val;
        _update_maxttl(idx, iph->ttl);
        return XDP_PASS;
    } 
    counters.increment(iph->protocol); 

    // if packet is an ICMP time exceeded response, then
    // peel out inner packet and check if it is a probe response
    if (iph->protocol != IPPROTO_ICMP) {
        return XDP_PASS;
    }

    // compute hdr size + shift ahead
    offset = offset + ((iph->verihl&0x0f) << 2);
#ifdef DEBUG
    bpf_trace_printk("INGRESS ICMP4 from 0x%lx hsize %d\n", ntohl(iph->saddr), ((iph->verihl&0x0f) << 2));
#endif
    if (data + offset + sizeof(struct _icmphdr) > data_end) {
        return XDP_PASS;
    }
    struct _icmphdr *icmp = (struct _icmphdr*)(data + offset);
    if (icmp->icmp_type != ICMP_TIME_EXCEEDED) {
        return XDP_PASS;
    }

#ifdef DEBUG
    bpf_trace_printk("INGRESS icmp time exceeded from 0x%lx\n", ntohl(iph->saddr));
#endif

    // FIXME: not doing this yet, but can use this len to determine
    // whether there are any extension headers a la rfc4884 
    // (and rfc4950 extensions in particular)
    int inner_pktlen = ntohs(icmp->icmp_reserved[1]);
    if (inner_pktlen == 0) {
        inner_pktlen = sizeof(struct _iphdr) + 8;
    }

    offset = offset + sizeof(struct _icmphdr);
    // save srcip and ttl from outer IP header
    uint32_t srcip = iph->saddr;
    uint8_t recvttl = iph->ttl;
    if (data + offset + sizeof(struct _iphdr) > data_end) {
        return XDP_PASS;
    }
#ifdef DEBUG
    bpf_trace_printk("INGRESS icmp time exceeded from dest of interest\n");
#endif
    // the *inner* v4 header returned by some router where the packet died
    iph = (struct _iphdr*)(data + offset);
    _in6_addr_t origdst = {{{ iph->daddr, 0, 0, 0 }}};
    val = NULL;
    if ((val = trie.lookup(&origdst)) == NULL) {
        return XDP_PASS;
    }
    offset = offset + sizeof(struct _iphdr);

#if DEBUG
    bpf_trace_printk("INGRESS ttl exc from 0x%x rttl %d idx %d\n", srcip, recvttl, *val);
#endif

    // sequence offset if relative to end of IP header
    int sequence_offset = 0;
    if (iph->protocol == 1) {
        sequence_offset = ICMP_SEQ_OFF;
    } else if (iph->protocol == 6) {
        sequence_offset = TCP_SEQ_OFF + 2;
    } else if (iph->protocol == 17) {
        sequence_offset = UDP_CSUM_OFF;
    }
    if (data + offset + sequence_offset + 2 > data_end) {
        return XDP_DROP;
    }
    u16 seq = *(u16*)(data + offset + sequence_offset);
    seq = ntohs(seq);
    if (iph->protocol == 17 && seq == 0xffff) {
        seq = 0;
    }
#if DEBUG
    bpf_trace_printk("INGRESS seq %d proto %d from %d received\n", seq, iph->protocol, *val);
#endif

    // record received probe
    u64 reskey = RESULTS_IDX;
    u64 zero = 0ULL;
    u64 *resultsidx = counters.lookup_or_init(&reskey, &zero);
    if (resultsidx == NULL) {
#if DEBUG
        bpf_trace_printk("INGRESS failed to get results idx\n");
#endif
        return XDP_DROP;
    }
#if DEBUG
    bpf_trace_printk("INGRESS got results index %llu\n", *resultsidx);
#endif
    int new_results = (int)*resultsidx;
    new_results = new_results % MAXRESULTS;
    struct latency_sample *latsamp = results.lookup(&new_results);
    if (latsamp == NULL) {
        return XDP_DROP;
    }
#if DEBUG
    bpf_trace_printk("INGRESS got lat sample ptr\n");
#endif
    latsamp->sequence = seq;
    latsamp->recv = bpf_ktime_get_ns();
    latsamp->recvttl = recvttl;
    __builtin_memcpy(&latsamp->responder, &source, sizeof(_in6_addr_t));
    __builtin_memcpy(&latsamp->target, &origdst, sizeof(_in6_addr_t));
    counters.increment(RESULTS_IDX);

    u64 sentkey = (u64)*val << 32 | (u64)seq;
    struct sent_info *si = sentinfo.lookup(&sentkey);
    if (si == NULL) {
        return XDP_DROP;
    }
#if DEBUG
    bpf_trace_printk("INGRESS got sentinfo sample ptr\n");
#endif

    // update bitmap to show hop as responsive
    int idx = *val;
    struct probe_dest *pd = destinfo.lookup(&idx);
    if (pd != NULL) {
        u32 newbit = 1 << (si->outttl-1); 
        pd->hop_bitmap = pd->hop_bitmap | newbit;
    }

    latsamp->send = si->send_time;
    latsamp->outttl = si->outttl;
    latsamp->sport = si->sport;
    latsamp->dport = si->dport;
    latsamp->origseq = si->origseq;
    latsamp->protocol = iph->protocol;

    sentinfo.delete(&sentkey);      
#if DEBUG
    bpf_trace_printk("INGRESS recorded new latency sample idx %d\n", new_results);
#endif
    return XDP_DROP;
}

int ingress_v6(struct xdp_md *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    int offset = NHOFFSET;

    if (data + offset + sizeof(struct _ip6hdr) > data_end) {
        return XDP_PASS;
    }
    struct _ip6hdr *iph = (struct _ip6hdr*)(data + offset);
    _in6_addr_t source = iph->saddr;
    u64 *val = NULL;
    if ((val = trie.lookup(&source)) != NULL) {
        // source address matches a destination of interest.
        // update our estimate of maxttl for this destination, but
        // that's it.
        int idx = (int)*val;
        _update_maxttl(idx, iph->hop_limit);
        return XDP_PASS;
    } 
    counters.increment(iph->protocol);
    // if packet is an ICMP6 time exceeded response, then
    // peel out inner packet and check if it is a probe response
    if (iph->protocol != IPPROTO_ICMP6) {
        return XDP_PASS;
    }

#ifdef DEBUG
    bpf_trace_printk("INGRESS ICMP6 from %lx:%lx:", ntohl(source._u._addr32[0]), ntohl(source._u._addr32[1]));
    bpf_trace_printk("%lx:%lx\n", ntohl(source._u._addr32[2]), ntohl(source._u._addr32[3]));
#endif
    offset = offset + sizeof(struct _ip6hdr);
    if (data + offset + sizeof(struct _icmphdr) > data_end) {
        return XDP_PASS;
    }
    struct _icmphdr *icmp = (struct _icmphdr*)(data + offset);
    if (icmp->icmp_type != ICMP6_TIME_EXCEEDED) {
        return XDP_PASS;
    }

#ifdef DEBUG
    bpf_trace_printk("INGRESS icmp6 time exceeded\n");
#endif

    // FIXME: not doing this yet, but can use this len to determine
    // whether there are any extension headers a la rfc4884 
    // (and rfc4950 extensions in particular)
    int inner_pktlen = ntohs(icmp->icmp_reserved[1]);
    if (inner_pktlen == 0) {
        inner_pktlen = sizeof(struct _ip6hdr) + 8;
    }

    offset = offset + sizeof(struct _icmphdr);
    // save srcip and ttl from outer IP header
    _in6_addr_t srcip = iph->saddr;
    uint8_t recvttl = iph->hop_limit;
    if (data + offset + sizeof(struct _ip6hdr) > data_end) {
        return XDP_PASS;
    }
#ifdef DEBUG
    bpf_trace_printk("INGRESS icmp6 time exceeded from dest of interest\n");
#endif
    // the *inner* v6 header returned by some router where the packet died
    iph = (struct _ip6hdr*)(data + offset);
    _in6_addr_t origdst = iph->daddr;
    val = NULL;
    if ((val = trie.lookup(&origdst)) == NULL) {
        return XDP_PASS;
    }

#if DEBUG
    bpf_trace_printk("INGRESS ttl exc from 0x%x rttl %d\n", srcip._u._addr32[0], recvttl);
#endif

    return XDP_PASS;
}

