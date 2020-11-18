#!/usr/bin/env python3

from chipwhisperer.analyzer.attacks.models.aes.funcs import subbytes, shiftrows, mixcolumns
from chipwhisperer.analyzer.attacks.models.aes.key_schedule import key_schedule_rounds

import numpy as np
import matplotlib.pyplot as plt
import binascii
from Crypto.Cipher import AES

TARGET_ROUND = 13

pts = np.load("glitch/in.npy",mmap_mode="r")
cts = np.load("glitch/out.npy",mmap_mode="r")
traces = np.load("glitch/traces.npy",mmap_mode="r")# [:,TARGET_ROUND * 120 + 20 - 60:TARGET_ROUND * 120 + 20 + 60]

cacheHit = 0
cacheMiss = 0

key_first = binascii.unhexlify("4b596315d21df5a531079c838e11eee6")
key_back = binascii.unhexlify("c95c9f4d0054e0376518b43e6e4eb7ab")
key_back_resolved = binascii.unhexlify("524a41541c0bc85272ef31c0ddc22943")
aesCache = {}
for i in range(0,30):
  aesCache[i] = {}

class AESModified:
  def __init__(self,key):
    self.key = key

  def encryptToRound(self,data,round,keyModification,tnum):
    global cacheHit,cacheMiss
    state = data
    roundKey = self.key
    state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
    for rnum in range(1,round):
      if (rnum != round) and (tnum in aesCache[rnum].keys()):
        state = aesCache[rnum][tnum]
        cacheHit += 1
      else:
        if rnum in keyModification.keys():
          localStateModify = keyModification[rnum]
          state = [state[bnum] ^ localStateModify[bnum] for bnum in range(0,16)]
        state = subbytes(state)
        state = shiftrows(state)
        state = mixcolumns(state)
        # adding a round key
        roundKey = key_schedule_rounds(self.key,0,rnum )
        state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
        if rnum == TARGET_ROUND:
          return state
        if rnum == 14:
          return state
        aesCache[rnum][tnum] = state
        cacheMiss += 1

aes = AESModified(key_first)

import sys
if len(sys.argv) < 2:
  print("usage: ./8ball [bytepos-to-modify] [bytepos-to-test]")
bytepos = int(sys.argv[1])
if len(sys.argv) == 3:
  testpos = int(sys.argv[2])
else:
  testpos = bytepos

maxQDiffs = []

import keymod
keyModification = keymod.keyModification

print("Testing effect if byte %d in round %d on post-mix byte %d" % (bytepos, TARGET_ROUND,testpos))

for i in range(0,256):
  keyModification[TARGET_ROUND][bytepos] = i
  num_g1 = 0
  num_g2 = 0
  g1 = np.zeros(len(traces[0]),np.float32)
  g2 = np.zeros(len(traces[0]),np.float32)
  for tnum in range(0,2500):
    s = aes.encryptToRound(pts[tnum],TARGET_ROUND + 1,keyModification,tnum)
    if bin(s[testpos]).count("1") >= 4:
      num_g1 += 1
      g1 += traces[tnum]
    else:
      num_g2 += 1
      g2 += traces[tnum]
  g1 /= num_g1
  g2 /= num_g2
  qdiffs = abs(g1-g2)
  print("Byte test %d (%02x), max %f, mean %f, posn %d" % (bytepos,i,max(qdiffs),np.mean(qdiffs),np.argmax(qdiffs)))
  maxQDiffs += [max(qdiffs)]

print(max(maxQDiffs))
print(hex(np.argmax(maxQDiffs)))

print("Hit: %d Miss: %d" % (cacheHit, cacheMiss))
plt.plot(maxQDiffs)
plt.show()
