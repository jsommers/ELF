import urllib.parse as up
import json
import sys
hresult = []
for host in eval(sys.stdin.read()):
    result = up.urlparse(host)
    hresult.append(result.netloc)
print(' '.join(hresult), end='')
