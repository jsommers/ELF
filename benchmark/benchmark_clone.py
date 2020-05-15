#!/usr/bin/python

from __future__ import print_function

# https://web.physics.ucsb.edu/~lecturedemonstrations/Composer/Pages/76.18.html
# about 8 inches/nanosec -> about 15 nanosec per 10ft cable

#
# ebpf clone benchmark code for host2 (cml1) 
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

#define IP_TTL_OFF offsetof(struct iphdr, ttl)
#define IP_CSUM_OFF offsetof(struct iphdr, check)
#define PKTGEN_SEQ_OFF (ETH_HLEN + sizeof(struct iphdr) + 12)

BPF_HISTOGRAM(dbgevent);
BPF_ARRAY(lastsend, u64, 1);

int egress_path(struct __sk_buff *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    // ignore already-cloned
    if (ctx->mark) {
        return TC_ACT_OK;
    }

    int offset = ETH_HLEN;
    struct iphdr *iph = 0;

    if (data + offset  > data_end) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    if (data + offset + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }

    iph = data + offset;
    int proto = iph->protocol;
    if (proto != IPPROTO_UDP) {
        return TC_ACT_OK;
    }

    u32 iphlen = iph->ihl << 2;
    offset = offset + iphlen;
    if (data + offset + sizeof(struct udphdr) > data_end) {
        return TC_ACT_OK;
    }

    struct udphdr *udph = data + offset;
    if (ntohs(udph->dest) != 9) {
        return TC_ACT_OK;
    }

    if (data + PKTGEN_SEQ_OFF + sizeof(u32) > data_end) {
        return XDP_DROP;
    }

    u32 seq = *(u32*)(data + PKTGEN_SEQ_OFF);
    seq = ntohl(seq);
    if (seq % 100 != 0) {
        return TC_ACT_OK;
    }

#if 0
    u64 now = bpf_ktime_get_ns(); 
    int key = 0;
    u64 *ls = lastsend.lookup(&key);
    if (!ls) {
        return TC_ACT_OK;
    }

    // clone every millisecond
    u64 diff = now - *ls;
    if (diff < 1000000) {
        return TC_ACT_OK;
    }
    *ls = now;
#endif

    ctx->mark = 1;

    // clone pkt and emit
    int rv = bpf_clone_redirect(ctx, IFINDEX, 0);
    if (rv < 0) {
        bpf_trace_printk("bpf clone ifidx %d failed: %d\n", IFINDEX, rv);
        // if clone fails, just let the packet pass w/o trying to do any modifications below
        return TC_ACT_OK;
    }

    // change ttl, recompute csum and emit
    u16 old_ttl_proto = load_half(ctx, ETH_HLEN + IP_TTL_OFF);
    u16 new_ttl_proto = htons(((u16)3) << 8 | IPPROTO_UDP);

    rv = bpf_l3_csum_replace(ctx, ETH_HLEN + IP_CSUM_OFF, htons(old_ttl_proto), new_ttl_proto, 2);
    if (rv < 0) {
        bpf_trace_printk("failed to replace csum udp path\n");
        return TC_ACT_SHOT;
    }
    rv = bpf_skb_store_bytes(ctx, ETH_HLEN + IP_TTL_OFF, &new_ttl_proto, sizeof(new_ttl_proto), 0);
    if (rv < 0) {
        bpf_trace_printk("failed to store new ttl/proto udp path\n");
        return TC_ACT_SHOT;
    }

    dbgevent.increment(1);

    return TC_ACT_OK;
} 
'''

import argparse
import csv
import ctypes
import logging
import socket
import struct
import subprocess
import sys
import time

import bcc
import pyroute2

def _getifidx(devname, ipdb):
    try:
        idx = ipdb.interfaces[devname].index
    except:
        logging.error("Invalid device name {}".format(devname))
        sys.exit(-1)
    return idx

def main(egressdev):
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = _getifidx(egressdev, ipdb)
    logging.info("ifindex for {} is {}".format(egressdev, idx))

    bccflags = bcc.DEBUG_BPF_REGISTER_STATE | bcc.DEBUG_SOURCE | bcc.DEBUG_BPF | bcc.DEBUG_LLVM_IR
    ibpf = bcc.BPF(text=BPF_CODE, debug=bccflags, cflags=["-DIFINDEX={}".format(idx)])
    egress_fn = ibpf.load_func('egress_path', bcc.BPF.SCHED_CLS)

    try:
        ip.tc('del', 'clsact', idx)
    except pyroute2.netlink.exceptions.NetlinkError:
        pass

    ip.tc('add', 'clsact', idx)
    ip.tc('add-filter', 'bpf', idx, ':1', fd=egress_fn.fd, name=egress_fn.name,
            parent='ffff:fff3', classid=1, direct_action=True)

    # register the ipaddress of interest
    logging.info("Installed ebpf code; running until ctrl+c")

    start = time.time()
    laststatus = start
    status_interval = 1.0
    while True:
        for x,y in ibpf['dbgevent'].items():
            if y.value > 0:
                print("dbg",x,y)
        try:
            now = time.time()
            if now - laststatus > status_interval:
                logging.info("tick") 
                laststatus = now
            time.sleep((status_interval - (time.time() - now))/2)

        except KeyboardInterrupt:
            logging.info("ctrl+c received; exiting")
            break

    logging.info("removing filters and shutting down")
    ip.tc('del', 'clsact', idx)
    ipdb.release()

if __name__ == '__main__':
    parser = argparse.ArgumentParser('In-band measurement')
    parser.add_argument('-e', '--egress', default='eno3', 
                        help='Device for emitting packets (default: eno3)')
    args = parser.parse_args()

    FORMAT = '%(asctime)-15s %(levelname)-6s %(message)s'
    logging.basicConfig(format=FORMAT, level=logging.DEBUG)
    main(args.egress)
