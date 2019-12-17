import argparse
import ctypes
import ipaddress
import sys
import time

# from bcc import BPF

class _u(ctypes.Union):
    _fields_ = [
        ('_addr32', ctypes.c_uint32 * 4),
        ('_addr16', ctypes.c_uint16 * 8),
        ('_addr8', ctypes.c_uint8 * 16)
    ]

class in6_addr(ctypes.Structure):
    _fields_ = [('_u', _u)]

def address_interest_v4(table, a):
    xaddr = in6_addr()
    ip4 = ipaddress.ip_address(a)
    pstr = ip4.packed
    for i in range(len(pstr)):
        xaddr._u._addr8[i] = pstr[i]
    for i in range(4, 16):
        xaddr._u._addr8[i] = 0
    table[xaddr] = ctypes.c_uint64(len(table))

def address_interest_v6(table, a):
    xaddr = in6_addr()
    ip6 = ipaddress.ip_address(a)
    pstr = ip6.packed
    for i in range(len(pstr)):
        xaddr._u._addr8[i] = pstr[i]
    table[xaddr] = ctypes.c_uint64(len(table))

def main(args):
    cflags = []
    if args.encapsulation == 'ipinip':
        cflags.append('-DTUNNEL=4')
        cflags.append('-DNHOFFSET=20')
    elif args.encapsulation == 'ip6inip':
        cflags.append('-DTUNNEL=6')
        cflags.append('-DNHOFFSET=20')
    elif args.encapsulation == 'ethernet':
        cflags.append('-DNHOFFSET=14')

    if args.debug:
        cflags.append('-DDEBUG')

    b = BPF(src_file='someta_ebpf.c', cflags=cflags)

    #b = BPF(src_file="someta_ebpf.c", cflags=['-DTUNNEL=6', '-DNHOFFSET=20', '-DDEBUG'])
    #DEVICE='he-ipv6'
    #b = BPF(src_file="someta_ebpf.c", cflags=['-DDEBUG', '-DNHOFFSET=14'])
    #DEVICE='eno2'
    #DEVICE='wlp4s0'

    # how to inject something into the table
    table = b['trie']

    address_interest_v4(table, '149.43.152.10')
    address_interest_v4(table, '149.43.80.25')
    address_interest_v6(table, '2604:6000:141a:e3:8d2:dcb2:edd4:d60d')
    for addr in args.addresses:
        ipaddr = ipaddress.ip_address(addr)
        if ipaddr.version == 4:
            address_interest_v4(table, addr)
        else:
            address_interest_v6(table, addr)

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

    #while True:
    #    try:
    #        task,pid,cpu,flags,ts,msg = b.trace_fields(nonblocking=True)
    #        if task is None:
    #            break
    #        print(task,pid,cpu,flags,ts,msg)
    #    except ValueError:   
    #        break
    b.remove_xdp(DEVICE)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', default=False, action='store_true', help='Turn on debug logging')
    parser.add_argument('-i', '--interface', required=True, type=str, help='Interface/device to use')
    parser.add_argument('-e', '--encapsulation', choices=('ethernet', 'ipinip', 'ip6inip'), default='ethernet', help='How packets are encapsulated on the wire')
    parser.add_argument('addresses', metavar='addresses', nargs='*', type=str, help='IP addresses of interest')
    args = parser.parse_args()
    print(args)
    sys.exit()
    main(args)