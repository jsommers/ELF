import time
from bcc import BPF
import ctypes
import ipaddress

b = BPF(text='''
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
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#endif
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
    uint16_t ip6_un1_plen;  /* payload length */
    uint8_t  ip6_un1_nxt;   /* next header */
    uint8_t  ip6_un1_hlim;  /* hop limit */
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
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t th_x2:4;        /* (unused) */
    uint8_t th_off:4;       /* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t th_off:4;       /* data offset */
    uint8_t th_x2:4;        /* (unused) */
# endif
        uint8_t th_flags;
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
};

#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

#define ETHERTYPE_IP        0x0800
#define ETHERTYPE_IP6       0x86dd 

#define ICMP6_DST_UNREACH             1
#define ICMP6_TIME_EXCEEDED           3
#define ICMP6_ECHO_REQUEST          128
#define ICMP6_ECHO_REPLY            129

#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ICMP_ECHO               8       /* Echo Request                 */
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */

#define MAXDEST     128

struct probe_dest {
    u64     hop_bitmap;
    u32     sequence;
    u16     next_hop_to_probe;
    u16     max_ttl;
    u64     last_send;
};

struct sent_info {
    u64         send_time;
    _in6_addr_t dest;
    u64         out_ttl;
};

struct latency_sample {
    u64 sequence;
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

BPF_HASH(trie, _in6_addr_t, u64); // key: dest address
BPF_HISTOGRAM(counters, u64, 255); 
BPF_ARRAY(destinfo, struct probe_dest, MAXDEST); // index: value in trie hash
BPF_HASH(hopinfo, u64, u64); // key: destid | hop
BPF_HASH(sentinfo, u64, struct sent_info); // key: destid | sequence
BPF_ARRAY(results, struct latency_sample); // key: index 0 in counters

int xdp_call(struct xdp_md *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    int ipproto = 0;
    int offset = NHOFFSET;

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

    if (ipproto == 4) {
        if (data + offset + sizeof(struct _iphdr) > data_end) {
            return XDP_PASS;
        }
        struct _iphdr *iph = (struct _iphdr*)(data + offset);
        counters.increment(iph->protocol); 
        _in6_addr_t source = { iph->saddr, 0, 0, 0 };
        u64 *val = NULL;
        if ((val = trie.lookup(&source)) == NULL) {
            u64 newval = 1;
            trie.insert(&source, &newval);
        } else {
            *val = *val + 1;
        }
    } else if (ipproto == 6) {
        if (data + offset + sizeof(struct _ip6hdr) > data_end) {
            return XDP_PASS;
        }
        struct _ip6hdr *iph = (struct _ip6hdr*)(data + offset);
        counters.increment(iph->ip6_un1_nxt);
        _in6_addr_t source;
#pragma unroll
        for (int i = 0; i < 16; i++) {
            source._u._addr8[i] = iph->saddr._u._addr8[i];
        }
        u64 *val = NULL;
        if ((val = trie.lookup(&source)) == NULL) {
            u64 newval = 1;
            trie.insert(&source, &newval);
        } else {
            *val = *val + 1;
        }
    } else {
        return XDP_PASS;
    }

    return XDP_PASS;
}
''', cflags=['-DTUNNEL=6', '-DNHOFFSET=20'])

class _u(ctypes.Union):
    _fields_ = [
        ('_addr32', ctypes.c_uint32 * 4),
        ('_addr16', ctypes.c_uint16 * 8),
        ('_addr8', ctypes.c_uint8 * 16)
    ]

class in6_addr(ctypes.Structure):
    _fields_ = [('_u', _u)]


DEVICE='he-ipv6'

# how to inject something into the table
table = b['trie']
xaddr = in6_addr()
ip4 = ipaddress.ip_address('149.43.152.10')
pstr = ip4.packed
for i in range(len(pstr)):
    xaddr._u._addr8[i] = pstr[i]
for i in range(4, 16):
    xaddr._u._addr8[i] = 0
table[xaddr] = ctypes.c_uint64(13)

xaddr = in6_addr()
ip6 = ipaddress.ip_address('2604:6000:141a:e3:8d2:dcb2:edd4:d60d')
pstr = ip6.packed
for i in range(len(pstr)):
    xaddr._u._addr8[i] = pstr[i]
table[xaddr] = ctypes.c_uint64(17)

xdp_fn = b.load_func("xdp_call", BPF.XDP)
b.attach_xdp(DEVICE, xdp_fn, 0)

print("start")
time.sleep(2)
print("ok - done")
print('counters')
for k,v in b['counters'].items():
    print("\t",k,v)

print('trie')
for k,v in b['trie'].items():
    ver = 6
    if k._u._addr32[3] == 0:
        ver = 4
    if ver == 6:
        print("\taddr6 0x", end='', sep='')
        for i in range(16):
            print("{:02x}".format(k._u._addr8[i]), end='', sep='')
    else:
        print("\taddr4 0x", end='', sep='')
        for i in range(4):
            print("{:02x}".format(k._u._addr8[i]), end='', sep='')
    print(v)

b.remove_xdp(DEVICE)
