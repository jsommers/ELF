import array
import sys
import struct
from socket import ntohs, htons

def checksum (data, start = 0, skip_word = None):
  """
  Calculate standard internet checksum over data starting at start'th byte

  skip_word: If specified, it's the word offset of a word in data to "skip"
             (as if it were zero).  The purpose is when data is received
             data which contains a computed checksum that you are trying to
             verify -- you want to skip that word since it was zero when
             the checksum was initially calculated.
  """
  if len(data) % 2 != 0:
    arr = array.array('H', data[:-1])
  else:
    arr = array.array('H', data)

  if skip_word is not None:
    for i in range(0, len(arr)):
      if i == skip_word:
        continue
      start +=  arr[i]
  else:
    for i in range(0, len(arr)):
      start +=  arr[i]

  if len(data) % 2 != 0:
    start += struct.unpack('H', data[-1:]+b'\x00')[0] # Specify order?

  start  = (start >> 16) + (start & 0xffff)
  start += (start >> 16)
  #while start >> 16:
  #  start = (start >> 16) + (start & 0xffff)

  return ntohs(~start & 0xffff)

def _halfconv(hstr):
    hwords = [ '0x' + hw for hw in hstr.split()]
    hwords = [ int(hw, base=16).to_bytes(2, 'big') for hw in hwords ]
    bstr = b''.join(hwords)

    hwx = [ '0x' + hw for hw in hstr.split()]
    hwx = [ int(hw, base=16).to_bytes(2, 'big') for hw in hwx ]
    hwsum = sum([struct.unpack('H', hw)[0] for hw in hwx])
    hwsum  = (hwsum >> 16) + (hwsum & 0xffff)
    hwsum += (hwsum >> 16)
    hwsum = ntohs(~hwsum & 0xffff)
    print('cs', hex(hwsum))

    return bstr

def _halfword_sum(bs):
    arr = array.array('H', bs)
    return sum(arr)

# c2d5
halfwords = '952b 38b6  0808 0404 ' '0011 0014 ' 'bddd 0035 0014 0003 '
# 53d7 0000  0000 0000 0000 0000

halfwords = _halfconv(halfwords)
print("dstaddr",hex(_halfword_sum(halfwords[4:8])))
print("addrs",hex(_halfword_sum(halfwords[:8])))
print("pseudo",hex(_halfword_sum(halfwords[:12])))
# print("hdr",hex(_halfword_sum(halfwords[:44])))
print(hex(checksum(halfwords)))


