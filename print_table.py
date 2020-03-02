#!/usr/bin/env python3

import argparse
import csv
import ipaddress
import os
import re
import sys
import time

import pandas as pd
import numpy as np
import matplotlib 
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def readlog(fname):
    firstwrite = None
    base,_ = os.path.splitext(fname)
    startpat = re.compile('^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}),(\d{3}) INFO New results written')
    hostpat = re.compile('^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} INFO host of interest: address (?P<addr>\S+) name (?P<name>\S+)')
    hostmap = {}
    with open("{}.log".format(base)) as infile:
        for line in infile:
            mobj = startpat.match(line)
            if mobj and firstwrite is None:
                t = time.strptime(line[:19], '%Y-%m-%d %H:%M:%S')
                firstwrite = time.mktime(t)+int(mobj[7])/1000
                firstwrite = pd.Timestamp(ts_input=firstwrite, unit='s', tz='EST')
                # print("firstwrite", t, firstwrite)
            mobj = hostpat.match(line)
            if mobj:
                addr = ipaddress.ip_address(mobj['addr'])
                # ndt-iupui-mlab1-lga03.measurement-lab.org
                loc = mobj['name'].split('.')[0][-5:][:3]
                # print(mobj['addr'],mobj['name'])
                if addr.version == 4:
                    hostmap[loc] = addr
    return firstwrite, hostmap

def readdata(fname, starttime, tsadj=0):
    df = pd.read_csv(fname)
    df = df.sort_values('sendtime', axis=0)
    series = (df.loc[:, 'sendtime'] - df.loc[:, 'sendtime'].min())/1000000000
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
    ax = onehop.plot.line(x='sendtime', y='latency', marker='.', c='C{}'.format(ttl-1), ax=ax, grid=True, label="hop {}".format(ttl))
    ax.set_ylabel('latency (millisec)')
    ax.set_xlabel('time (seconds)')
    return ax

def doplot(df, outname, cols, xlim, ylim, smooth):
    plt.figure(figsize=(6,4))
    ax = plt.subplot(1,1,1)
    print("max outttl", df.outttl.max())
    if args.hop is None:
        hops = list(range(1, df.outttl.max()+1))
    else:
        hops = args.hop
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
    plt.savefig('{}.pdf'.format(outname), layout='tight')

def main(df, args, dest):
    if args.hop is None:
        hops = list(range(1, df.outttl.max()+1))
    else:
        hops = args.hop

    for h in hops:
        onehop = df[df['outttl'] == h]
        responses = onehop.query('latency > 0 & dest == @dest')
        print(f"Hop {h} total {len(onehop)} responses {len(responses)} fracresponse {round(len(responses)/len(onehop), 3)}")
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
        df = df.query('latency > 0 & dest == @dest')
        doplot(df, args.outname, cols=args.cols, xlim=args.xlim, ylim=args.ylim, smooth=args.smooth)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hop', nargs='*', type=int, help='Indicate which hops should be plotted (default: all)')
    parser.add_argument('--smooth', '-s', choices=('none','ewma','window'), help='Indicate how latency measurements should be smoothed for plotting')
    parser.add_argument('--seq', '-q', nargs='*', type=int, help='Indicate sequence numbers for which detail should be printed')
    parser.add_argument('--head', type=int, help='Indicate the number of rows to be printed from latency measurements')
    parser.add_argument('--xlim', '-x', default=None, help='xlim for ts plot')
    parser.add_argument('--ylim', '-y', default=None, help='ylim for ts plot')
    parser.add_argument('inputfiles', metavar='inputfiles', nargs='+', type=str,
            help='Data files')
    parser.add_argument('--plot', default=False, action='store_true', help='Whether to plot time series or not')
    parser.add_argument('--all', default=False, action='store_true', help='Print all data lines')
    parser.add_argument('--outname', '-o', default='tsplot', type=str, help='Output file name for timeseries plot')
    parser.add_argument('--cols', default=2, type=int, help='Number of columns in legend on plot')
    args = parser.parse_args()
    if args.seq is None:
        args.seq = []
    for f in args.inputfiles:
        firstwrite, hostmap = readlog(f)
        for loc,addr in sorted(hostmap.items()):
            print(f"Processing results for {loc} ({addr}) in {f}")
            df = readdata(f, firstwrite)
            main(df, args, str(addr))
