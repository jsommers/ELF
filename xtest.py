import time
import bcc

b = bcc.BPF(text='''
typedef struct {
    union {
        uint8_t __u6_addr8[16];
        uint16_t __u6_addr16[8];
        uint32_t __u6_addr32[4];
    } __in6_u;
} _in6_addr_t;

BPF_LPM_TRIE("trie", _in6_addr_t);
BPF_HISTOGRAM("counters", int, 10);

int xdp_call(void *ctx) {
    bpf_trace_printk("Original program\n");
    counters.increment(0); 
    return 0;
}
'''

DEVICE='eth0'
xdp_fn = b.load_func("xdp_call", BPF.XDP)
b.attach_xdp(DEVICE, xdp_fn, 0)

time.sleep(1)
print('counters')
for k,v in b['counters'].items():
    print(k,v)

print('trie')
for k,v in b['trie'].items():
    print(k,v)
b.remove_xdp(DEVICE)
