#!/usr/bin/env python3

import argparse
import csv
import sys

import pandas as pd
import numpy as np
import matplotlib 
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def main(fname, args):
    df = pd.read_csv(fname)
    nolat = len(df[df['latency'] == -1])
    print("No-latency rows: ", nolat, len(df), nolat/len(df), end="\n\n")
    df = df[df['latency'] != -1]
    df = df.sort_values(by='sendtime') 
    print("recvttl value counts:", df['recvttl'].value_counts(), end="\n\n")
    print("outttl value counts:", df['outttl'].value_counts(), end="\n\n")
    cols = ['seq','sendtime','latency','outttl','recvttl','protocol']
    print()
    print(df.to_string(columns=cols))
    print()
    print(df[cols].describe().to_string())
    print("\n")
    for seq in args.seq:
        print("seq", seq, df[df['seq']==int(seq)][cols])
        print()
    if args.plot:
        doplot(df, args.outname, cols=args.cols, xlim=args.xlim, ylim=args.ylim, smooth=args.smooth)

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


def doplot(df, outname, cols=2, xlim=None, ylim=None, smooth='none'):
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
    parser.add_argument('--outname', '-o', default='tsplot', type=str, help='Output file name for timeseries plot')
    parser.add_argument('--cols', default=2, type=int, help='Number of columns in legend on plot')
    args = parser.parse_args()
    for f in args.inputfiles:
        main(f, args)
