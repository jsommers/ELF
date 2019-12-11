import time
from bcc import BPF
import ctypes
import ipaddress

#b = BPF(src_file="someta_ebpf.c", cflags=['-DTUNNEL=6', '-DNHOFFSET=20', '-DDEBUG'])
#DEVICE='he-ipv6'

b = BPF(src_file="someta_ebpf.c", cflags=['-DDEBUG', '-DNHOFFSET=14'])
DEVICE='eno2'

class _u(ctypes.Union):
    _fields_ = [
        ('_addr32', ctypes.c_uint32 * 4),
        ('_addr16', ctypes.c_uint16 * 8),
        ('_addr8', ctypes.c_uint8 * 16)
    ]

class in6_addr(ctypes.Structure):
    _fields_ = [('_u', _u)]



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

xdp_fn = b.load_func("ingress_path", BPF.XDP)
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
