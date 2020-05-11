#!/usr/bin/python

from __future__ import print_function

#
# eBPF benchmark code for sink machine
#

BPF_CODE=r'''
#define KBUILD_MODNAME "foo"

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define BPF_LICENSE GPL

// offset from the beginning of the UDP header; 32 bits
#define PKTGEN_SEQ_OFF (ETH_HLEN + sizeof(struct iphdr) + 12)

struct data_t {
    unsigned int ttl;
    unsigned int seq;
    u64 ts;
};
BPF_PERF_OUTPUT(events);

int ingress_path(struct xdp_md *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }
    struct ethhdr *eth = (struct ethhdr *)data;

    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    int offset = ETH_HLEN;
    if (data + offset + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }

    struct iphdr *iph = (struct iphdr*)(data + offset);
    uint8_t proto = iph->protocol;
    if (proto != IPPROTO_UDP) {
        return XDP_PASS;
    }

    u32 iphlen = iph->ihl << 2;
    offset = offset + iphlen;
    if (data + offset + sizeof(struct udphdr) > data_end) {
        return XDP_DROP;
    }

    struct udphdr *udph = (struct udphdr*)(data + offset);
    if (ntohs(udph->dest) != 9) {
        return XDP_DROP;
    }

    if (data + PKTGEN_SEQ_OFF + sizeof(u32) > data_end) {
        return XDP_DROP;
    }

    struct data_t pdata = {};

    u32 seq = *(u32*)(data + PKTGEN_SEQ_OFF);
    u64 ts = bpf_ktime_get_ns();
    seq = ntohl(seq);
    u64 key = seq;
    bpf_trace_printk("got seq %d %x ttl %d\n", seq, seq, iph->ttl);

    pdata.ts = ts;
    pdata.ttl = iph->ttl;
    pdata.seq = seq;
    events.perf_submit(ctx, &pdata, sizeof(pdata));

#if DROP
    return XDP_DROP;
#endif

    /*
    if (iph->ttl == 3) {
        ttl3time.update(&key, &ts);
    } else {
        recvtime.update(&key, &ts);
    }
    */
    
    // sink all the traffic captured at this point
    return XDP_DROP;
}
'''

import argparse
import csv
import ctypes
import logging
import sys
import time
import csv
from collections import defaultdict

import bcc
global ibpf

dataarr = []

def collect_events(cpu, data, size):
    global dataarr
    event = ibpf["events"].event(data)
    dataarr.append([cpu,event.ts,event.seq,event.ttl])
    #print(cpu, event.ts, event.seq, event.ttl)

def main(ingressdev, outname, drop):
    global ibpf
    bccflags = bcc.DEBUG_BPF_REGISTER_STATE | bcc.DEBUG_SOURCE | bcc.DEBUG_BPF | bcc.DEBUG_LLVM_IR

    cflags = []
    if drop:
        cflags.append("-DDROP=1")
    ibpf = bcc.BPF(text=BPF_CODE, debug=bccflags, cflags=cflags)
    ingress_fn = ibpf.load_func('ingress_path', bcc.BPF.XDP)
    ibpf.attach_xdp(ingressdev, ingress_fn)

    logging.info("Installed ebpf code; ctrl+c to interrupt")
    start = time.time()
    laststatus = start
    status_interval = 1.0

    ibpf['events'].open_perf_buffer(collect_events)
    while True:
        try:
            ibpf.perf_buffer_poll();
            now = time.time()
            if now - laststatus > status_interval:
                logging.info("tick") 
                laststatus = now

            #for x,y in ibpf['recvtime'].items():
            #    if y.value > 0:
            #        print("dbg recv", x, y)
            #for x,y in ibpf['ttl3time'].items():
            #    if y.value > 0:
            #        print("dbg ttl3", x, y)
            # print("dbg recvsize: ", len(ibpf['recvtime']))
            # print("dbg ttl3size: ", len(ibpf['ttl3time']))

        except KeyboardInterrupt:
            logging.info("ctrl+c received; exiting")
            break

    logging.info("removing filters and shutting down")
    ibpf.remove_xdp(ingressdev)

    #d = defaultdict(list)
    #for x,y in ibpf['recvtime'].items():
    #    d[x.value].append(y.value)
    #for x,y in ibpf['ttl3time'].items():
    #    d[x.value].append(y.value)

    with open(outname, 'w') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(['cpu','seq','recvorig','recvclone'])
        for xli in dataarr:
            writer.writerow(xli)

if __name__ == '__main__':
    parser = argparse.ArgumentParser('In-band measurement')
    parser.add_argument('-o', '--outfile', default='benchmark.csv',
                        help='Output file name')
    parser.add_argument('-i', '--ingress', default='eno3', 
                        help='Device for attaching XDP ingress program')
    parser.add_argument('-d', '--drop', action='store_true',
                        help='Drop all traffic (don\'t save anything)')
    args = parser.parse_args()

    if not args.outfile.endswith('.csv'):
        args.outfile += ".csv"

    FORMAT = '%(asctime)-15s %(levelname)-6s %(message)s'
    logging.basicConfig(format=FORMAT, level=logging.DEBUG)
    main(args.ingress, args.outfile, args.drop)
