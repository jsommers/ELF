#!/usr/bin/python

from __future__ import print_function

import argparse
import csv
import ctypes
import logging
import re
import socket
import struct
import subprocess
import sys
import time

import bcc
import pyroute2

class InvalidConfiguration(Exception):
    pass

class ProbeConfig(object):
    def __init__(self, args):
        self.bunch = args.bunch
        self.debug = args.debug
        self.interval = args.spacing
        self.device = args.device
        self.maxttl = args.maxttl
        self.hostnames = args.hostnames
        self.status = 1.0
        self.ether = args.noether
        self.outfile = args.outfile
        self.code = args.ebpfcode
        self.timeout = int(args.timeout)
        self._sanitycheck()

    def _sanitycheck(self):
        if self.interval < 10:
            raise InvalidConfiguation("fail: interval is less than 10 microsec")
        if self.device is None:
            raise InvalidConfiguation("Need a device")
        if not self.code:
            raise InvalidConfiguration("No eBPF code file specified")
        if not self.hostnames:
            raise InvalidConfiguration("No hosts specified for tracing")
        if self.maxttl < 1 or self.maxttl > 64:
            raise InvalidConfiguration("Invalid maxttl setting")

    def cflags(self):
        return ["-DDEBUG={}".format(int(self.debug)), "-DPROBE_INTERVAL={}".format(self.interval), "-DBUNCH={}".format(int(self.bunch)), "-DETHER_ENCAP={}".format(int(self.ether))]


def lookup_host(host, alllist):
    try:
        hname, _, iplist = socket.gethostbyname_ex(host)
    except socket.gaierror:
        logging.error("Error looking up hostname {}".format(host))
        sys.exit(-1)
    for ipstr in iplist:
        packed_ip = socket.inet_aton(ipstr)
        alllist.append((ipstr, struct.unpack("!I", packed_ip)[0]))

def _unpack_ip(i):
    vals = []
    for shift in (0, 8, 16, 24):
        vals.append(str((i >> shift) & 0xff))
    return '.'.join(vals)

def main(config):
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    try:
        idx = ipdb.interfaces[config.device].index
    except KeyError:
        logging.error("Invalid device {}".format(config.device))
        sys.exit(-1)

    logging.info("ifindex for {} is {}".format(config.device, idx))

    iplist = []
    for h in config.hostnames:
        lookup_host(h, iplist)
    logging.info("Tracing hosts: ", ','.join([str(i) for i in iplist]))
    if config.maxttl > 0:
        numhops = config.maxttl

    debugflag = 0     
    if config.debug:
        debugflag = bcc.DEBUG_BPF_REGISTER_STATE | bcc.DEBUG_SOURCE | bcc.DEBUG_BPF | bcc.DEBUG_LLVM_IR

    cflags=["-Wall", "-DIFINDEX={}".format(idx), "-DNUM_HOPS={}".format(numhops-1)]
    cflags += config.cflags()

    ibpf = bcc.BPF(src_file=config.code, debug=debugflag, cflags=cflags)

    # set up ingress path
    ingress_fn = ibpf.load_func("ingress_path", bcc.BPF.XDP)
    ibpf.attach_xdp(config.device, ingress_fn)
    iprog_array = ibpf.get_table("ingress_prog_array")
    icmp_ingress = ibpf.load_func("ingress_path_icmp", bcc.BPF.XDP)
    tcp_ingress = ibpf.load_func("ingress_path_tcp", bcc.BPF.XDP)
    udp_ingress = ibpf.load_func("ingress_path_udp", bcc.BPF.XDP)
    iprog_array[c_int(1)] = c_int(icmp_ingress.fd)
    iprog_array[c_int(6)] = c_int(tcp_ingress.fd)
    iprog_array[c_int(17)] = c_int(udp_ingress.fd)

    egress_fn = ibpf.load_func('egress_path'.format(config.mode), bcc.BPF.SCHED_CLS)


    try:
        ip.tc('del', 'clsact', idx)
    except pyroute2.netlink.exceptions.NetlinkError:
        pass

    ip.tc('add', 'clsact', idx)
    ip.tc('add-filter', 'bpf', idx, ':1', fd=egress_fn.fd, name=egress_fn.name,
            parent='ffff:fff3', classid=1, direct_action=True)

    # register the ipaddress of interest
    ibpf['ip_interest'].clear()
    key = 0
    for ipstr, taddr in iplist:
        logging.info("Adding {} to ip interest hash".format(ipstr))
        ibpf['ip_interest'][ctypes.c_ulong(socket.htonl(taddr))] = ctypes.c_ulonglong(key)
        key += 1

    logging.info("Installed ebpf code;{} ctrl+c to interrupt".format(running))

    outfile = open(config.outfile + ".csv", 'wb')
    csvwriter = csv.writer(outfile)
    csvwriter.writerow(['seq','origseq','latency','send','recv','outttl','recvttl','sport','dport','target','responder'])

    def _print_status():
        try:
            currprobeseq = ibpf['vars'][ctypes.c_ulong(0)].value
        except KeyError:
            currprobeseq = -1
        logging.info("{:.3f}   probeseq {}".format(time.time() - start, currprobeseq))

    def _get_nextresult():
        try:
            nextresult = ibpf['vars'][ctypes.c_ulong(2)].value
            return nextresult
        except KeyError:
            logging.warning("No vars idx 2 val for results???")
            return -1

    start = time.time()
    resultidx = 0
    laststatus = 0
    killit = False
    while True:
        try:
            now = time.time()
            if now - laststatus > config.status:
                _print_status()
                laststatus = now

            if config.timeout > 0 and now > start + config.timeout:
                logging.info("external program timeout exceeded")
                killit = True
                break

            nextresult = _get_nextresult()
            if nextresult != -1:
                while resultidx != nextresult:
                    result = ibpf['results'][resultidx]
                    csvwriter.writerow([result.seq, result.origseq, result.recv-result.send, result.send, result.recv, result.outttl, result.recvttl, result.sport, result.dport, _unpack_ip(result.target), _unpack_ip(result.responder)])

                    resultidx += 1
                    if resultidx == len(ibpf['results']):
                        resultidx = 0

            time.sleep((config.status - (time.time() - now))/2)

        except KeyboardInterrupt:
            killit = True
            logging.info("ctrl+c received; exiting")
            break

    logging.info("Waiting 1s for any stray responses")
    time.sleep(1.0)
    logging.info("removing filters and shutting down")

    # take care of left-over data from sending 
    # (probes that got sent, but for which we didn't receive any response)
    seqsend = {}
    for k,v in ibpf['seqsend'].items():
        seq = k.value & 0xffffffff
        seqsend[seq] = v.value
    
    seqorig = {}
    for k,v in ibpf['seqorigseq'].items():
        seq = k.value & 0xffffffff
        seqorig[seq] = v.value

    for k,v in ibpf['seqttl'].items():
        seq = k.value & 0xffffffff
        dstip = _unpack_ip(socket.ntohl(k.value >> 32))
        csvwriter.writerow([seq, seqorig.get(seq, 0), seqsend.get(seq, 0), seqsend.get(seq, 0), 0, v.value, 0, 0, 0, dstip, '0.0.0.0'])

    ibpf.remove_xdp(config.device)
    ip.tc('del', 'clsact', idx)
    ipdb.release()
    outfile.close()
    logging.info("Done.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser('In-band measurement')
    parser.add_argument('-c', '--ebpfcode', default='someta_ebpf.c',
                        help='File containing eBPF code to install')
    parser.add_argument('-d', '--debug', 
                        action='store_true', default=False,
                        help="Turning on some debugging output (incl. bpf_trace_printk messages")
    parser.add_argument('-b', '--bunch', default=False, action='store_true',
                        help="Turn on 'bunch' mode (default: off)")
    parser.add_argument('-e', '--noether', default=True, action='store_false',
                        help="No ethernet encapsulation (assume raw IP)")
    parser.add_argument('-s', '--spacing', default=10000,
                        help="Spacing between probes (or probe bunches) to each hop, in microseconds (default 10 millisec/10000 microsec)")
    parser.add_argument('-o', '--outfile', default='inband', 
                        help='File (basename) to write probe output data')
    parser.add_argument('-t', '--maxttl', default=16, type=int,
                        help="Set the max TTL value explicitly; otherwise use the number of hops from a traceroute to the destination")
    parser.add_argument('-i', '--device', type=str, required=True,
                        help='Network device name, e.g., eth0 to use')
    parser.add_argument('-T', '--timeout', default=0, 
                        help='Set timeout for external command to run (default: no timeout)')
    parser.add_argument('hostnames', nargs='*',
                        help='Additional hostnames (corresponding IP addrs) to trace')
    args = parser.parse_args()

    loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG
    FORMAT = '%(asctime)-15s %(levelname)-6s %(message)s'
    logging.basicConfig(format=FORMAT, level=loglevel)

    config = ProbeConfig(args)
    main(config)
