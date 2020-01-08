#!/usr/bin/env python3

import argparse
import json
import ctypes
import ipaddress
import logging
import socket
import sys
import time

import bcc
from bcc import BPF
import pyroute2

# constants that mirror bpf C
RESULTS_IDX = 256
MAX_RESULTS = 8192

class _u(ctypes.Union):
    _fields_ = [
        ('_addr32', ctypes.c_uint32 * 4),
        ('_addr16', ctypes.c_uint16 * 8),
        ('_addr8', ctypes.c_uint8 * 16)
    ]

class in6_addr(ctypes.Structure):
    '''
    Mirror struct of in6_addr in bpf C
    '''
    _fields_ = [('_u', _u)]


def to_ipaddr(obj):
    '''
    bytes -> ipaddr
    Convert raw bytes into an ipaddress object.
    '''
    if obj._u._addr32[3] == 0:
        # ip4
        return ipaddress.IPv4Address(socket.ntohl(obj._u._addr32[0]))
    else:
        i = obj._u._addr32[0]
        for j in range(1, 4):
            i = i << 32 | socket.ntohl(obj._u._addr32[j])
        return ipaddress.IPv6Address(i)

def new_address_of_interest(table, a, dinfo):
    '''
    (bpftable, ipaddr, bpftable) -> None
    Add a new address of interest to bpf tables
    (and initialize table structures)
    '''
    xaddr = in6_addr()
    ip = ipaddress.ip_address(a)
    pstr = ip.packed
    idx = len(table) + 1
    for i in range(len(pstr)):
        xaddr._u._addr8[i] = pstr[i]
        dinfo[idx].dest._u._addr8[i] = pstr[i]
    if ip.version == 4:
        for i in range(4, 16):
            xaddr._u._addr8[i] = 0
            dinfo[idx].dest._u._addr8[i] = 0
    table[xaddr] = ctypes.c_uint64(idx)
    dinfo[idx].hop_bitmap = 0
    dinfo[idx].max_ttl = 16

def _set_bpf_jumptable(bpf, tablename, idx, fnname, progtype):
    '''
    (bccobj, str, int, str, int) -> None
    Set up one entry in a bpf jump table to enable chaining
    bpf function calls.
    '''
    tail_fn = bpf.load_func(fnname, progtype)
    prog_array = bpf.get_table(tablename)
    prog_array[ctypes.c_int(idx)] = ctypes.c_int(tail_fn.fd)

def main(args):
    metadata = {}
    if args.logfile:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)-15s %(levelname)s %(message)s', filename=args.filebase + '.log', filemode='w')
    else:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)-15s %(levelname)s %(message)s')

    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    try:
        idx = ipdb.interfaces[args.interface].index
    except KeyError:
        logging.error("Invalid device {}".format(args.interface))
        sys.exit(-1)
    logging.info("ifindex for {} is {}".format(args.interface, idx))

    cflags = ['-Wall', '-DMIN_PROBE={}'.format(1000000 * args.probeint)] # 1 millisec default
    cflags.append('-DIFINDEX={}'.format(idx))
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

    destinfo = b['destinfo']
    metadata['timestamp'] = time.asctime()
    metadata['interface'] = args.interface
    metadata['interface_idx'] = idx
    metadata['hosts'] = {}
    for name in args.addresses:
        for family,_,_,_,sockaddr in socket.getaddrinfo(name, None):
            addr = sockaddr[0]
            metadata['hosts'][addr] = name
            new_address_of_interest(b['trie'], addr, destinfo)

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

    for idx,fnname in [(socket.IPPROTO_ICMP, 'egress_v4_icmp'), (socket.IPPROTO_TCP, 'egress_v4_tcp'), (socket.IPPROTO_UDP, 'egress_v4_udp')]:
        _set_bpf_jumptable(b, 'egress_v4_proto', idx, fnname, BPF.SCHED_CLS)

    for idx,fnname in [(socket.IPPROTO_ICMPV6, 'egress_v6_icmp'), (socket.IPPROTO_TCP, 'egress_v6_tcp'), (socket.IPPROTO_UDP, 'egress_v6_udp')]:
        _set_bpf_jumptable(b, 'egress_v6_proto', idx, fnname, BPF.SCHED_CLS)

    logging.info("start")
    metadata['results'] = []
    resultcount = 0
    while True:
        try:
            time.sleep(1)
            resultval = -1
            for k,v in b['counters'].items():
                if k.value == RESULTS_IDX:
                    rc = v.value
            if resultval > -1:
                while resultcount < rc:
                    resultidx = resultcount % MAX_RESULTS
                    res = b['results'][resultidx]
                    print("latsamp", resultidx, res.sequence, res.origseq, res.recv-res.send, res.send, res.recv, res.sport, res.dport, res.outttl, res.recvttl, to_ipaddr(res.responder), to_ipaddr(res.target), res.protocol, res.outipid, res.inipid)
                    d = {'seq':res.sequence, 'origseq':res.origseq, 'latency':(res.recv-res.send), 'sendtime':res.send, 'recvtime':res.recv, 'dest':str(to_ipaddr(res.target)), 'responder':str(to_ipaddr(res.responder)), 'outttl':res.outttl, 'recvttl':res.recvttl, 'sport':res.sport, 'dport':res.dport, 'protocol':res.protocol, 'outipid':res.outipid, 'inipid':res.inipid}
                    metadata['results'].append(d)
                    resultcount += 1

        except KeyboardInterrupt:
            break
            
    logging.info("ok - done")

    logging.info("Waiting 0.5s for any stray responses")
    time.sleep(0.5)
    logging.info("removing filters and shutting down")

    print('counters')
    rc = resultcount
    for k,v in b['counters'].items():
        print("\t",k,v)
        if k.value == RESULTS_IDX:
            rc = v.value

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

    for k,v in b['sentinfo'].items():
        idx = k.value >> 32 & 0xffffffff
        seq = k.value & 0xffffffff
        print("sent", idx, seq, v.origseq, v.send_time, to_ipaddr(v.dest), v.outttl, v.sport, v.dport, v.protocol, v.outipid)
        d = {'seq':seq, 'origseq':v.origseq, 'sendtime':v.send_time, 'dest':str(to_ipaddr(v.dest)), 'outttl':v.outttl, 'sport':v.sport, 'dport':v.dport, 'recvtime':0, 'responder':'', 'recvttl':-1, 'latency':-1, 'protocol':v.protocol, 'outipid':v.outipid}
        metadata['results'].append(d)

    while resultcount < rc:
        resultidx = resultcount % MAX_RESULTS
        res = b['results'][resultidx]
        print("latsamp", resultidx, res.sequence, res.origseq, res.recv-res.send, res.send, res.recv, res.sport, res.dport, res.outttl, res.recvttl, to_ipaddr(res.responder), to_ipaddr(res.target), res.protocol, res.outipid, res.inipid)
        d = {'seq':res.sequence, 'origseq':res.origseq, 'latency':(res.recv-res.send), 'sendtime':res.send, 'recvtime':res.recv, 'dest':str(to_ipaddr(res.target)), 'responder':str(to_ipaddr(res.responder)), 'outttl':res.outttl, 'recvttl':res.recvttl, 'sport':res.sport, 'dport':res.dport, 'protocol':res.protocol, 'outipid':res.outipid, 'inipid':res.inipid}
        metadata['results'].append(d)
        resultcount += 1

    if args.debug:
        logging.debug("kernel debug messages: ")
        while True:
            try:
                task,pid,cpu,flags,ts,msg = b.trace_fields(nonblocking=True)
                if task is None:
                    break
                logging.debug("ktime {} cpu{} {} flags:{} {}".format(ts, cpu, task.decode(errors='ignore'), flags.decode(errors='ignore'), msg.decode(errors='ignore')).replace('%',''))
            except ValueError:   
                break

    with open("{}_meta.json".format(args.filebase), 'w') as outfile:
        json.dump(metadata, outfile)

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
    parser.add_argument('-x', '--on', default=60, type=int, help='Amount of time (seconds) to be "on" for probing non-responsive hops')
    parser.add_argument('-y', '--off', default=1, type=int, help='Amount of time (seconds) to be "off" for probing non-responsive hops')
    parser.add_argument('-l', '--logfile', default=False, action='store_true', help='Turn on logfile output')
    parser.add_argument('-f', '--filebase', default='ebpf_probe', help='Configure base name for log and data output files')
    parser.add_argument('-d', '--debug', default=False, action='store_true', help='Turn on debug logging')
    parser.add_argument('-p', '--probeint', default=1, type=int, help='Minimum probe interval (milliseconds)')
    parser.add_argument('-i', '--interface', required=True, type=str, help='Interface/device to use')
    parser.add_argument('-e', '--encapsulation', choices=('ethernet', 'ipinip', 'ip6inip'), default='ethernet', help='How packets are encapsulated on the wire')
    parser.add_argument('addresses', metavar='addresses', nargs='*', type=str, help='IP addresses of interest')
    args = parser.parse_args()
    main(args)
