#!/usr/bin/env python3

from __future__ import print_function

import argparse
from contextlib import contextmanager
import csv
import ctypes
import ipaddress
import logging
import os
import signal
import socket
import sys
import time

import bcc
from bcc import BPF
import pyroute2

# constants that mirror bpf C
RESULTS_IDX = 256
MAX_RESULTS = 16384
CPU_COUNT = os.cpu_count()

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
        return ipaddress.IPv4Address(obj._u._addr32[0])
    else:
        i = obj._u._addr32[0]
        for j in range(1, 4):
            i = i << 32 | obj._u._addr32[j]
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

def _set_bpf_jumptable(bpf, tablename, idx, fnname, progtype):
    '''
    (bccobj, str, int, str, int) -> None
    Set up one entry in a bpf jump table to enable chaining
    bpf function calls.
    '''
    tail_fn = bpf.load_func(fnname, progtype)
    prog_array = bpf.get_table(tablename)
    prog_array[ctypes.c_int(idx)] = ctypes.c_int(tail_fn.fd)


class RunState(object):
    def __init__(self, args):
        self._args = args
    
    def setup(self):
        '''
        Do some basic setup for logging, bpf, etc.
        '''
        fmt = '%(asctime)-15s %(levelname)s %(message)s'
        loglevel = logging.INFO
        if self._args.debug:
            loglevel = logging.DEBUG
        if self._args.logfile:
            logging.basicConfig(level=loglevel, format=fmt, filename=self._args.filebase + '.log', filemode='w')
            sh = logging.StreamHandler()
            sh.setLevel(loglevel)
            sh.setFormatter(logging.Formatter(fmt=fmt))
            logging.getLogger().addHandler(sh)
        else:
            logging.basicConfig(level=loglevel, format='%(asctime)-15s %(levelname)s %(message)s')

    def _open_pyroute2(self):
        '''
        open pyroute2 for eventual installation of CLS_SCHED ebpf code
        '''
        ip = pyroute2.IPRoute()
        ipdb = pyroute2.IPDB(nl=ip)
        try:
            idx = ipdb.interfaces[self._args.interface].index
        except KeyError:
            logging.error("Invalid device {}".format(self._args.interface))
            sys.exit(-1)
        logging.info("ifindex for {} is {}".format(self._args.interface, idx))
        self._idx = idx
        self._ip = ip
        self._ipdb = ipdb

        try:
            ip.tc('del', 'clsact', idx)
        except pyroute2.netlink.exceptions.NetlinkError:
            pass

    @property
    def idx(self):
        return self._idx

    def _build_bpf_cflags(self):
        '''
        build CFLAGS for BCC based on command-line configuration.
        NB: this must be done *after* open ipdb, since we get the 
        interface index from pyroute2.
        '''
        cflags = ['-Wall', '-DPROBE_INT={}'.format(1000000 * self._args.probeint)] # 1 millisec default
        if self._args.ratetype in ['h','perhop']:
            cflags.append('-DPERHOPRATE=1')
        cflags.append('-DIFINDEX={}'.format(self._idx))
        if self._args.encapsulation == 'ipinip':
            cflags.append('-DTUNNEL=4')
            cflags.append('-DNHOFFSET=20')
        elif self._args.encapsulation == 'ip6inip':
            cflags.append('-DTUNNEL=6')
            cflags.append('-DNHOFFSET=20')
        elif self._args.encapsulation == 'ethernet':
            cflags.append('-DNHOFFSET=14')

        if self._args.ingress == 'pass':
            cflags.append('-DINGRESS_ACTION=XDP_PASS')
        elif self._args.ingress == 'drop':
            cflags.append('-DINGRESS_ACTION=XDP_DROP')

        self._bcc_debugflag = bcc.DEBUG_SOURCE
        if self._args.debug:
            cflags.append('-DDEBUG=1')
            bcc_debugflag = bcc.DEBUG_BPF_REGISTER_STATE | bcc.DEBUG_SOURCE | bcc.DEBUG_BPF | bcc.DEBUG_LLVM_IR 

        self._cflags = cflags

    @contextmanager
    def open_ebpf(self):
        '''
        context manager that opens and configures BCC ebpf object, and closes/releases
        ebpf + ipdb resources when done
        '''
        self._open_pyroute2()
        self._build_bpf_cflags()
        b = BPF(src_file='someta_ebpf.c', debug=self._bcc_debugflag, cflags=self._cflags)
        self._register_addresses_of_interest(b)

        b['counters'][ctypes.c_int(RESULTS_IDX)] = ctypes.c_int(0)

        egress_fn = b.load_func('egress_path', BPF.SCHED_CLS)
        ingress_fn = b.load_func("ingress_path", BPF.XDP)
        b.attach_xdp(self._args.interface, ingress_fn, 0)

        self._ip.tc('add', 'clsact', self._idx)
        self._ip.tc('add-filter', 'bpf', self._idx, ':1', fd=egress_fn.fd, name=egress_fn.name,
            parent='ffff:fff3', classid=1, direct_action=True)

        # set up jump tables for v4/v6 processing on ingress + egress
        for i,fnname in [(4,'ingress_v4'), (6, 'ingress_v6')]:
            _set_bpf_jumptable(b, 'ingress_layer3', i, fnname, BPF.XDP)

        for i,fnname in [(4,'egress_v4'), (6, 'egress_v6')]:
            _set_bpf_jumptable(b, 'egress_layer3', i, fnname, BPF.SCHED_CLS)

        for i,fnname in [(socket.IPPROTO_ICMP, 'egress_v4_icmp'), (socket.IPPROTO_TCP, 'egress_v4_tcp'), (socket.IPPROTO_UDP, 'egress_v4_udp')]:
            _set_bpf_jumptable(b, 'egress_v4_proto', i, fnname, BPF.SCHED_CLS)

        for i,fnname in [(socket.IPPROTO_ICMPV6, 'egress_v6_icmp'), (socket.IPPROTO_TCP, 'egress_v6_tcp'), (socket.IPPROTO_UDP, 'egress_v6_udp')]:
            _set_bpf_jumptable(b, 'egress_v6_proto', i, fnname, BPF.SCHED_CLS)
        
        try:
            yield b
        finally:
            b.remove_xdp(self._args.interface)
            self._ip.tc('del', 'clsact', self._idx)
            self._ipdb.release()

    def _register_addresses_of_interest(self, b):
        '''
        (bpf) -> None
        add IP addresses corresponding to all DNS names given on command line to
        internal address hash.
        '''
        destinfo = b['destinfo']
        for name in self._args.addresses:
            for family,_,_,_,sockaddr in socket.getaddrinfo(name, None):
                addr = sockaddr[0]
                logging.info("host of interest: address {} name {}".format(addr, name))
                new_address_of_interest(b['trie'], addr, destinfo)

def _write_results(b, rcounts, csvout, config, dumpall=False):
    xcount = 0
    rc  = b['resultscount'][0]
    results = b['results']
    for cpu in range(CPU_COUNT):
        if rc[cpu] > rcounts[cpu] and config.debug:
            logging.debug("Got {} results on cpu {}".format(rc[cpu] - rcounts[cpu], cpu))
        while rcounts[cpu] < rc[cpu]:
            resultidx = rcounts[cpu] % MAX_RESULTS
            res = results[resultidx][cpu]
            rcounts[cpu] += 1
            xcount += 1
            if config.debug:
                print("latsamp", cpu, resultidx, res.sequence, res.origseq, res.recv-res.send, res.send, res.recv, res.sport, res.dport, res.outttl, res.recvttl, to_ipaddr(res.responder), to_ipaddr(res.target), res.protocol, res.outipid, res.inipid)
            csvout.writerow([cpu, res.sequence, res.origseq, (res.recv-res.send), res.send, res.recv, str(to_ipaddr(res.target)), str(to_ipaddr(res.responder)), res.outttl, res.recvttl, res.sport, res.dport, res.protocol, res.outipid, res.inipid])
    if dumpall:
        for k,v in b['sentinfo'].items():
            idx = k.value >> 32 & 0xffffffff
            seq = k.value & 0xffffffff
            if config.debug:
                print("sent", idx, seq, v.origseq, v.send_time, to_ipaddr(v.dest), v.outttl, v.sport, v.dport, v.protocol, v.outipid)
            csvout.writerow([0, seq, v.origseq, -1, v.send_time, -1, str(to_ipaddr(v.dest)), '', v.outttl, -1, v.sport, v.dport, v.protocol, v.outipid, -1])
            xcount += 1

    return xcount

def _print_debug_counters(b):
    if not len(b['counters']):
        return
    logging.debug('counters')
    for k,v in b['counters'].items():
        logging.debug("\t{}->{}".format(k,v))

def _print_debug_info(b):
    _print_debug_counters(b)

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

    logging.debug("kernel debug messages: ")
    while True:
        try:
            task,pid,cpu,flags,ts,msg = b.trace_fields(nonblocking=True)
            if task is None:
                break
            logging.debug("ktime {} cpu{} {} flags:{} {}".format(ts, cpu, task.decode(errors='ignore'), flags.decode(errors='ignore'), msg.decode(errors='ignore')).replace('%',''))
        except ValueError:   
            break

done = False

def sighandler(*args):
    logging.info("Got termination signal")
    global done
    done = True

def main(config):
    state = RunState(config)
    state.setup()
    global done
    signal.signal(signal.SIGINT, sighandler)
    signal.signal(signal.SIGTERM, sighandler)
    signal.signal(signal.SIGHUP, sighandler)

    logging.info("Start time {}".format(time.asctime()))
    logging.info("Interface {}".format(config.interface))

    with open("{}.csv".format(config.filebase), 'w') as csvfile:
        csvout = csv.writer(csvfile)
        csvout.writerow(['recvcpu','seq','origseq','latency','sendtime','recvtime','dest','responder','outttl','recvttl','sport','dport','protocol','outipid','inipid'])
        with state.open_ebpf() as b:
            logging.info("Interface index {}".format(state.idx))
            rc = 0
            resultcounts = [0]*CPU_COUNT
            while not done:
                try:
                    time.sleep(1)
                    logging.debug("wakeup resultcount {}".format(rc))
                    _print_debug_counters(b)
                    newrc = _write_results(b, resultcounts, csvout, config)
                    rc += newrc
                    if newrc > 0:
                        logging.info("New results written: {}, total: {}".format(newrc, rc))
                except KeyboardInterrupt:
                    break
                
            logging.info("done; waiting 0.5s for any stray responses")
            time.sleep(0.5)
            logging.info("removing filters and shutting down")
    
            rc += _write_results(b, resultcounts, csvout, config, dumpall=True)
            logging.info("final result count: {}".format(rc))
            if config.debug:
                _print_debug_info(b)


def arg_sanity_checks(args):
    if args.probeint < 0 or args.probeint > 1000:
        print("Invalid probe interval (0-1000 is allowed)")
        sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-I', '--ingress', choices=('pass','drop'), default='drop', help='Specify how ingress ICMP time exceeded messages should be handled: pass through to OS or drop in XDP')
    parser.add_argument('-l', '--logfile', default=False, action='store_true', help='Turn on logfile output')
    parser.add_argument('-f', '--filebase', default='ebpf_probe', help='Configure base name for log and data output files')
    parser.add_argument('-d', '--debug', default=False, action='store_true', help='Turn on debug logging')
    parser.add_argument('-p', '--probeint', default=10, type=int, help='Minimum probe interval (milliseconds)')
    parser.add_argument('-r', '--ratetype', choices=('g','global','h','perhop'), help='Probe rate type: global or per hop; default is per hop => longer path for per-hop type implies higher measurement probe rate')
    parser.add_argument('-i', '--interface', required=True, type=str, help='Interface/device to use')
    parser.add_argument('-e', '--encapsulation', choices=('ethernet', 'ipinip', 'ip6inip'), default='ethernet', help='How packets are encapsulated on the wire')
    parser.add_argument('addresses', metavar='addresses', nargs='*', type=str, help='IP addresses of interest')
    args = parser.parse_args()
    arg_sanity_checks(args)
    main(args)
