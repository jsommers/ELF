import argparse
import ctypes
import ipaddress
import logging
import sys
import time

import bcc
from bcc import BPF
import pyroute2

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

def _set_bpf_jumptable(bpf, tablename, idx, fnname, progtype):
    tail_fn = bpf.load_func(fnname, progtype)
    prog_array = bpf.get_table(tablename)
    prog_array[ctypes.c_int(idx)] = ctypes.c_int(tail_fn.fd)

def main(args):
    logging.basicConfig(level=logging.DEBUG)
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    try:
        idx = ipdb.interfaces[args.interface].index
    except KeyError:
        logging.error("Invalid device {}".format(args.interface))
        sys.exit(-1)
    logging.info("ifindex for {} is {}".format(args.interface, idx))

    cflags = ['-DMIN_PROBE=1000000'] # 1 millisec
    if args.encapsulation == 'ipinip':
        cflags.append('-DTUNNEL=4')
        cflags.append('-DNHOFFSET=20')
    elif args.encapsulation == 'ip6inip':
        cflags.append('-DTUNNEL=6')
        cflags.append('-DNHOFFSET=20')
    elif args.encapsulation == 'ethernet':
        cflags.append('-DNHOFFSET=14')

    bcc_debugflag = 0     
    if args.debug:
        cflags.append('-DDEBUG=1')
        bcc_debugflag = bcc.DEBUG_BPF_REGISTER_STATE | bcc.DEBUG_SOURCE | bcc.DEBUG_BPF | bcc.DEBUG_LLVM_IR

    b = BPF(src_file='someta_ebpf.c', debug=bcc_debugflag, cflags=cflags)

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

    egress_fn = b.load_func('egress_path', BPF.SCHED_CLS)
    ingress_fn = b.load_func("ingress_path", BPF.XDP)
    b.attach_xdp(args.interface, ingress_fn, 0)

    try:
        ip.tc('del', 'clsact', idx)
    except pyroute2.netlink.exceptions.NetlinkError:
        pass

    ip.tc('add', 'clsact', idx)
    ip.tc('add-filter', 'bpf', idx, ':1', fd=egress_fn.fd, name=egress_fn.name,
            parent='ffff:fff3', classid=1, direct_action=True)

    # set up jump tables for v4/v6 processing on ingress + egress
    for idx,fnname in [(4,'ingress_v4'), (6, 'ingress_v6')]:
        _set_bpf_jumptable(b, 'ingress_layer3', idx, fnname, BPF.XDP)
        
    for idx,fnname in [(4,'egress_v4'), (6, 'egress_v6')]:
        _set_bpf_jumptable(b, 'egress_layer3', idx, fnname, BPF.SCHED_CLS)

    for idx,fnname in [(1, 'egress_v4_icmp'), (6, 'egress_v4_tcp'), (17, 'egress_v4_udp')]:
        _set_bpf_jumptable(b, 'egress_v4_proto', idx, fnname, BPF.SCHED_CLS)

    for idx,fnname in [(1, 'egress_v6_icmp'), (6, 'egress_v6_tcp'), (17, 'egress_v6_udp')]:
        _set_bpf_jumptable(b, 'egress_v6_proto', idx, fnname, BPF.SCHED_CLS)

    logging.info("start")
    time.sleep(2)
    logging.info("ok - done")

    logging.info("Waiting 0.5s for any stray responses")
    time.sleep(0.5)
    logging.info("removing filters and shutting down")

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

    if args.debug:
        logging.debug("kernel debug messages: ")
        while True:
            try:
                task,pid,cpu,flags,ts,msg = b.trace_fields(nonblocking=True)
                if task is None:
                    break
                logging.debug("{} {} {} {} {} {}".format(task,pid,cpu,flags,ts,msg))
            except ValueError:   
                break

    try:
        b.remove_xdp(args.interface)
    except Exception as e:
        print("Failed to remove xdp fn: ", str(e))

    try:
        ip.tc('del', 'clsact', idx)
    except pyroute2.netlink.exceptions.NetlinkError:
        pass
    ipdb.release()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', default=False, action='store_true', help='Turn on debug logging')
    parser.add_argument('-i', '--interface', required=True, type=str, help='Interface/device to use')
    parser.add_argument('-e', '--encapsulation', choices=('ethernet', 'ipinip', 'ip6inip'), default='ethernet', help='How packets are encapsulated on the wire')
    parser.add_argument('addresses', metavar='addresses', nargs='*', type=str, help='IP addresses of interest')
    args = parser.parse_args()
    main(args)
