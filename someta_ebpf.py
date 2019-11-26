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
        self.mode = args.mode
        self.device = args.device
        self.host = args.host
        self.maxttl = args.maxttl
        self.hostnames = args.hostnames
        self.status = 1.0
        self.ether = args.noether
        self.outfile = args.outfile
        self.cmd = args.cmd
        self.timeout = int(args.timeout)
        self._sanitycheck()

    def _sanitycheck(self):
        if self.interval < 10:
            raise InvalidConfiguation("fail: interval is less than 10 microsec")
        if self.device is None:
            raise InvalidConfiguation("Need a device")
        if self.cmd and not self.host:
            raise InvalidConfiguration("No host specified for command")
        if not self.host and not self.hostnames:
            raise InvalidConfiguration("No hosts specified for tracing")
        if self.mode not in ('icmp','tcp'):
            raise InvalidConfiguration("Invalid mode")

    def cflags(self):
        return ["-DDEBUG={}".format(int(self.debug)), "-DPROBE_INTERVAL={}".format(self.interval), "-DBUNCH={}".format(int(self.bunch)), "-DICMPMODE={}".format(int(self.mode=='icmp')), "-DTCPMODE={}".format(int(self.mode=='tcp')), "-DETHER_ENCAP={}".format(int(self.ether))]


def get_hops(host):
    cmd = ['/usr/sbin/traceroute', '-n', host]
    p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = p.communicate()
    lines = stdout.split('\n')
    for i in range(len(lines)-1, -1, -1):
        if not lines[i].strip():
            continue
        return int(lines[i].split()[0])

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
    lookup_host(config.host, iplist)
    for h in config.hostnames:
        lookup_host(h, iplist)
    if config.maxttl > 0:
        numhops = config.maxttl
    else:
        numhops = get_hops(iplist[0][0])
    logging.info("{} is {} hops away".format(config.host, numhops))

    debugflag = 0     
    if config.debug:
        debugflag = bcc.DEBUG_BPF_REGISTER_STATE | bcc.DEBUG_SOURCE | bcc.DEBUG_BPF | bcc.DEBUG_LLVM_IR

    cflags=["-Wall", "-DIFINDEX={}".format(idx), "-DNUM_HOPS={}".format(numhops-1)]
    cflags += config.cflags()

    ibpf = bcc.BPF(src_file='inband_test.c', debug=debugflag, cflags=cflags)
    ingress_fn = ibpf.load_func("ingress_path", bcc.BPF.XDP)
    egress_fn = ibpf.load_func('egress_path_{}'.format(config.mode), bcc.BPF.SCHED_CLS)
    ibpf.attach_xdp(config.device, ingress_fn)

    try:
        ip.tc('del', 'clsact', idx)
    except pyroute2.netlink.exceptions.NetlinkError:
        pass

    ip.tc('add', 'clsact', idx)
    ip.tc('add-filter', 'bpf', idx, ':1', fd=egress_fn.fd, name=egress_fn.name,
            parent='ffff:fff3', classid=1, direct_action=True)

    # register the ipaddress of interest
    ibpf['ip4_interest'].clear()
    for ipstr, taddr in iplist:
        logging.info("Adding {} to ip interest hash".format(ipstr))
        ibpf['ip4_interest'][ctypes.c_ulong(socket.htonl(taddr))] = ctypes.c_bool(1)

    if config.cmd:
        cmd = config.cmd.format(config.host)
        running = ' running {} ({});'.format(config.mode, cmd)
        proc = subprocess.Popen(cmd.split(), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    else:
        cmd = ''
        running = ''
        proc = None
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

            if proc is not None and proc.poll() is not None:
                logging.info("{} done; exiting".format(config.mode))
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

    program_output = ""
    if proc is not None:
        if killit:
            logging.info("killing process {} and waiting for it".format(proc.pid))
            proc.kill()
            proc.wait()
        program_output = proc.stdout.read()

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

    extra = ""
    if proc is not None:
        logging.info("{} output: ".format(program_output))
        with open(config.outfile + ".out", 'w') as outfile:
            print(cmd, file=outfile)
            outfile.write(program_output)
        extra = " and {}.out".format(config.outfile)
    logging.info("Output written to {}.csv{}".format(config.outfile, extra))


if __name__ == '__main__':
    #icmp_default = 'ping -c 10 -s 8 {}'
    #tcp_default = 'ndtclt -b 134217728 -n {}'
    #default_host = 'NDT-IUPUI-mlab1-lga03.measurement-lab.org' 

    parser = argparse.ArgumentParser('In-band measurement')
    parser.add_argument('-c', '--cmd', default='',
                        help='Command to use; no default; assumes that {} is included in the command for filling in the target host, which is specified with --host')
    parser.add_argument('-d', '--debug', 
                        action='store_true', default=False,
                        help="Turning on some debugging output (incl. bpf_trace_printk messages")
    parser.add_argument('--host', 
                        default='',
                        help='Target host for command (no default)')
    parser.add_argument('-b', '--bunch', default=False, action='store_true',
                        help="Turn on 'bunch' mode (default: off)")
    parser.add_argument('-e', '--noether', default=True, action='store_false',
                        help="No ethernet encapsulation (assume raw IP)")
    parser.add_argument('-s', '--spacing', default=10000,
                        help="Spacing between probes (or probe bunches) to each hop, in microseconds (default 10 millisec/10000 microsec)")
    parser.add_argument('-o', '--outfile', default='inband', 
                        help='File (basename) to write probe output data')
    parser.add_argument('-t', '--maxttl', default=0, type=int,
                        help="Set the max TTL value explicitly; otherwise use the number of hops from a traceroute to the destination")
    parser.add_argument('-m', '--mode', default='icmp', choices=('icmp','tcp'),
                        help='Application mode (icmp or tcp; default icmp/ping)')
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
