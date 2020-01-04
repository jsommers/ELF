#!/usr/bin/env python3

import json
import sys
import pandas as pd

with open(sys.argv[-1]) as infile:
    d = json.load(infile)
df = pd.read_json(json.dumps(d['results']))
print(df['recvttl'].value_counts())
print(df['outttl'].value_counts())
print(df['protocol'].value_counts())
print(df)
