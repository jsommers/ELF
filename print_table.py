#!/usr/bin/env python3

import argparse
import csv
import ipaddress
import os
import re
import sys
import time
from collections import defaultdict

import pandas as pd
import numpy as np
import matplotlib 
matplotlib.use('Agg')
import matplotlib.pyplot as plt

newres = re.compile('^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}),(\d{3}) INFO New results written')
hostpat = re.compile('INFO host of interest[ \w\)\(-]*: address (?P<addr>\S+) name (?P<name>\S+)\s*$')

def readlog(fname):
    firstwrite = None
    base,_ = os.path.splitext(fname)
    hostmap = defaultdict(set)
    with open("{}.log".format(base)) as infile:
        for line in infile:
            mobj = newres.search(line)
            if mobj and firstwrite is None:
                t = time.strptime(line[:19], '%Y-%m-%d %H:%M:%S')
                firstwrite = time.mktime(t)+int(mobj[7])/1000
                firstwrite = pd.Timestamp(ts_input=firstwrite, unit='s')
            mobj = hostpat.search(line)
            if mobj:
                addr = ipaddress.ip_address(mobj['addr'])
                loc = mobj['name']
                if loc == 'nonamefound':
                    loc = str(addr)
                hostmap[str(addr)].add(str(loc))
    return firstwrite, hostmap

def readdata(fname, starttime, absx, tsadj=0):
    df = pd.read_csv(fname)
    df = df.sort_values('sendtime', axis=0)
    series = (df.loc[:, 'sendtime'] - df.loc[:, 'sendtime'].min())/1000000000
    if absx:
        series = series.sub(tsadj).apply(lambda x: starttime + pd.Timedelta(x, unit='sec'))
    df = df.assign(send=series)
    return df

def plotone(ax, df, ttl, smooth):
    '''
    plot one hop of data inband measurement dataframe
    at one particular out ttl
    '''
    onehop = df[df['outttl'] == ttl].copy() 
    if len(onehop) < 10:
        return
    if smooth == 'window':
        onehop['latency'] = (onehop['latency'] / 1000000).rolling(2).mean()
    elif smooth == 'ewma':
        onehop['latency'] = (onehop['latency'] / 1000000).ewm(alpha=0.9).mean()
    elif smooth == 'none' or smooth is None:
        onehop['latency'] = onehop['latency'] / 1000000
    ax = onehop.plot.line(x='send', y='latency', marker='.', c='C{}'.format(ttl-1), ax=ax, grid=True, label="hop {}".format(ttl))
    ax.set_ylabel('latency (millisec)')
    ax.set_xlabel('time (seconds)')
    return ax

def doplot(df, outname, dest, idx, hops, cols, xlim, ylim, smooth):
    plt.figure(figsize=(6,4))
    ax = plt.subplot(1,1,1)
    plt.title(f"{dest}")

    for i in hops:
        plotone(ax, df, i, smooth)

    maxlat = df['latency'].max() / 1000000

    if ylim is None:
        ax.set_ylim(0, maxlat*1.15)
    else:
        ylim = [int(x) for x in ylim.split(',')]
        ax.set_ylim(*ylim)

    if xlim is not None:
        xlim = [int(x) for x in xlim.split(',')]
        ax.set_xlim(*xlim)

    plt.legend(ncol=cols, loc='upper left', fontsize=8)
    plt.savefig(f'{outname}{idx}.png', dpi=400)

def main(df, args, flowinfo, desthost, idx):
    if args.hop is None:
        hops = [int(x) for x in range(1, int(df.outttl.max())+1) ]
    else:
        hops = args.hop

    if args.aggbyresponder:
        print(f"\nFlow {idx+1} responder {flowinfo.responder} hop {df['outttl'].unique()} dest {flowinfo.dest} records {len(df)}")
    elif args.aggflows:
        print(f"\nFlow {idx+1} dest {flowinfo.dest} records {len(df)}")
    else:
        print(f"\nFlow {idx+1} dest {flowinfo.dest} sport {flowinfo.sport} dport {flowinfo.dport} protocol {flowinfo.protocol} records {len(df)}")

    for h in hops:
        onehop = df[df['outttl'] == h]
        responses = onehop.query('outttl>0&latency>0').copy()
        if len(onehop) == 0:
            continue

        respip = responses.responder.value_counts().to_string()
        print(f"Hop {h} total {len(onehop)} responses {len(responses)}")
        if len(responses) > 0:
            print("recvttl:", responses['recvttl'].value_counts().to_string())
            lats = responses['latency'].div(1000000)
            print("latency millisec")
            print(lats.quantile([0.25, 0.5, 0.75, 0.99]).to_string())

        if args.all:
            cols = ['seq','sendtime','latency','outttl','recvttl','protocol']
            print(df.to_string(columns=cols))
            print()
            print(df[cols].describe().to_string())
            print("\n")

    for seq in args.seq:
        print("seq", seq, df[df['seq']==int(seq)][cols])
        print()

    if args.plot:
        if df.groupby('outttl').count().max().max() <= 2:
            print(f"\nFlow {idx+1} dest {flowinfo.dest} not enough data to plot")
            return
        df = df[df['outttl']>0]
        doplot(df, args.outname, desthost, idx, hops=hops, cols=args.cols, xlim=args.xlim, ylim=args.ylim, smooth=args.smooth)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hop', nargs='*', type=int, help='Indicate which hops should be plotted (default: all)')
    parser.add_argument('--smooth', '-s', choices=('none','ewma','window'), help='Indicate how latency measurements should be smoothed for plotting')
    parser.add_argument('--seq', '-q', nargs='*', type=int, help='Indicate sequence numbers for which detail should be printed')
    parser.add_argument('--head', type=int, help='Indicate the number of rows to be printed from latency measurements')
    parser.add_argument('--xlim', '-x', default=None, help='xlim for ts plot')
    parser.add_argument('--ylim', '-y', default=None, help='ylim for ts plot')
    parser.add_argument('--absx', action='store_true', default=False, help='set xaxis to be abs UTC time, not seconds relative to trace begin')
    parser.add_argument('inputfiles', metavar='inputfiles', nargs='+', type=str,
            help='Data files')
    parser.add_argument('--plot', default=False, action='store_true', help='Whether to plot time series or not')
    parser.add_argument('--aggflows', default=False, action='store_true', help='Aggregate flows by destination in plots')
    parser.add_argument('--aggbyresponder', default=False, action='store_true', help='Aggregate results by responder (intermediate router), not destination')
    parser.add_argument('--all', default=False, action='store_true', help='Print all data lines')
    parser.add_argument('--outname', '-o', default='tsplot', type=str, help='Output file name for timeseries plot')
    parser.add_argument('--cols', default=2, type=int, help='Number of columns in legend on plot')
    args = parser.parse_args()
    if args.seq is None:
        args.seq = []
    idx = 1
    for f in args.inputfiles:
        firstwrite, hostmap = readlog(f)
        df = readdata(f, firstwrite, args.absx)
        if args.aggbyresponder:
            flows = df[['responder']].dropna().drop_duplicates()
            args.hop = None
        elif args.aggflows:
            flows = df[['dest']].drop_duplicates()
        else:
            flows = df[['protocol','sport','dport','dest']].drop_duplicates()

        for i in range(len(flows)):
            fid = flows.iloc[i,:]
            if args.aggbyresponder:
                flowdata = df[df['responder']==fid.responder]
                fid.dest = ','.join(flowdata['dest'].drop_duplicates().to_list())
            elif args.aggflows:
                flowdata = df[df['dest']==fid.dest]
            else:
                flowdata = df.query('dest==@fid.dest&protocol==@fid.protocol&sport==@fid.sport&dport==@fid.dport').copy()
            main(flowdata, args, fid, f"{fid.dest}: {','.join(hostmap.get(fid.dest, []))}", i)