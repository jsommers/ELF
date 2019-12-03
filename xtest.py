import time
from bcc import BPF

b = BPF(text='''
typedef struct _in6_addr {
    u32 addr[4];
} _in6_addr_t;

BPF_LPM_TRIE(trie, _in6_addr_t, u64);
BPF_HISTOGRAM(counters, u64, 16);

int xdp_call(void *ctx) {
    counters.increment(0); 
    _in6_addr_t x = {1, 2, 3, 4};
    u64 thirteen = 13;
    trie.lookup_or_init(&x, &thirteen);
    return XDP_PASS;
}
''')

DEVICE='eno2'
xdp_fn = b.load_func("xdp_call", BPF.XDP)
b.attach_xdp(DEVICE, xdp_fn, 0)

time.sleep(2)
print('counters')
for k,v in b['counters'].items():
    print(k,v)

print('trie')
for k,v in b['trie'].items():
    print(k,v)
b.remove_xdp(DEVICE)
