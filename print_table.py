#!/usr/bin/env python3

import argparse
import json
import sys

import pandas as pd
import numpy as np
import matplotlib 
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def main(d):
    df = pd.read_json(json.dumps(d['results']))
    nolat = len(df[df['latency'] == -1])
    print("No-latency rows: ", nolat, len(df), nolat/len(df), end="\n\n")
    df = df[df['latency'] != -1]
    df = df.sort_values(by='sendtime') # , axis=1)
    print("recvttl value counts:", df['recvttl'].value_counts(), end="\n\n")
    print("outttl value counts:", df['outttl'].value_counts(), end="\n\n")
    cols = ['seq','sendtime','latency','outttl','recvttl','protocol']
    print()
    #print(df.head(20).to_string(columns=cols))
    print(df.to_string(columns=cols))
    print()
    print(df[cols].describe().to_string())
    print("\n")
    for seq in sys.argv[2:]:
        print("seq", seq, df[df['seq']==int(seq)][cols])
        print()
    doplot(df, 'stuff')

def plotone(ax, df, ttl, smooth):
    '''
    plot one hop of data inband measurement dataframe
    at one particular out ttl
    '''
    onehop = df[df['outttl'] == ttl].copy() 
    if len(onehop) < 10:
        return
    if smooth == 'roll':
        onehop['latency'] = (onehop['latency'] / 1000000).rolling(2).mean()
    elif smooth == 'ewm':
        onehop['latency'] = (onehop['latency'] / 1000000).ewm(alpha=0.9).mean()
    else:
        onehop['latency'] = onehop['latency'] / 1000000
    ax = onehop.plot.line(x='sendtime', y='latency', marker='.', c='C{}'.format(ttl-1), ax=ax, grid=True, label="hop {}".format(ttl))
    ax.set_ylabel('latency (millisec)')
    ax.set_xlabel('time (seconds)')
    return ax


def doplot(df, outname, cols=2, xlim=None, ylim=None, smooth=''):
    plt.figure(figsize=(6,4))
    ax = plt.subplot(1,1,1)
    print("max outttl", df.outttl.max())
    for i in range(1, df.outttl.max()+1):
        plotone(ax, df, i, smooth)
    maxlat = df['latency'].max() / 1000000

    if ylim is None:
        ax.set_ylim(0, maxlat*1.15)
    else:
        ax.set_ylim(*ylim)

    if xlim is not None:
        ax.set_xlim(*xlim)

    plt.legend(ncol=cols, loc='upper left', fontsize=8)
    plt.savefig('{}.pdf'.format(outname), layout='tight')

if __name__ == '__main__':
    with open(sys.argv[1]) as infile:
        d = json.load(infile)
    main(d)

