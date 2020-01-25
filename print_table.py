#!/usr/bin/env python3

import json
import sys
import pandas as pd

with open(sys.argv[1]) as infile:
    d = json.load(infile)
df = pd.read_json(json.dumps(d['results']))
nolat = len(df[df['latency'] == -1])
print("No-latency rows: ", nolat, len(df), nolat/len(df), end="\n\n")
df = df[df['latency'] != -1]
df = df.sort_values(by='sendtime') # , axis=1)
print("recvttl value counts:", df['recvttl'].value_counts(), end="\n\n")
print("outttl value counts:", df['outttl'].value_counts(), end="\n\n")
cols = ['seq','sendtime','latency','outttl','recvttl','protocol']
print()
print(df.head(10).to_string(columns=cols))
print()
print(df[cols].describe().to_string())
print("\n")
for seq in sys.argv[2:]:
    print("seq", seq, df[df['seq']==int(seq)][cols])
    print()
    
