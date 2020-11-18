#!/usr/bin/env python3

from chipwhisperer.analyzer.attacks.models.aes.funcs import subbytes, shiftrows, mixcolumns
from chipwhisperer.analyzer.attacks.models.aes.key_schedule import key_schedule_rounds

import numpy as np
import matplotlib.pyplot as plt
import binascii
from Crypto.Cipher import AES

import sys
TARGET_ROUND = int(sys.argv[1])

pts = np.load("glitch/in.npy",mmap_mode="r")
cts = np.load("glitch/out.npy",mmap_mode="r")
traces = np.load("glitch/traces.npy",mmap_mode="r")[:,1550:]

key_first = binascii.unhexlify("4b596315d21df5a531079c838e11eee6")
key_back = binascii.unhexlify("c95c9f4d0054e0376518b43e6e4eb7ab")
key_back_resolved = binascii.unhexlify("524a41541c0bc85272ef31c0ddc22943")

# Try this:
# aesCache = [{}] * 10
# print(aesCache)
# aesCache[1]["lol"] = 2
# print(aesCache)
aesCache = {}
for i in range(0,TARGET_ROUND + 1):
  aesCache[i] = {}
# print(aesCache)

keyCache = {}

cacheHit = 0
cacheMiss = 0

class AESModified:
  def __init__(self,key):
    self.key = key

  def encryptToRound_fixed(self,data,round,keyModification,tnum):
    global cacheHit,cacheMiss
    state = data
    roundKey = self.key
    state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
    for rnum in range(1,round):
      if (rnum < round - 2) and (tnum in aesCache[rnum].keys()):
        state = aesCache[rnum][tnum]
        cacheHit += 1
      else:
        if rnum in keyModification.keys():
          localStateModify = keyModification[rnum]
          state = [state[bnum] ^ localStateModify[bnum] for bnum in range(0,16)]
        state = subbytes(state)
        if rnum == round - 1:
          return state
        state = shiftrows(state)
        state = mixcolumns(state)
        # adding a round key
        if rnum < 13 and rnum in keyCache.keys():
          roundKey = keyCache[rnum]  
        else:
          roundKey = key_schedule_rounds(self.key,0,rnum )
          keyCache[rnum] = roundKey
        state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
        aesCache[rnum][tnum] = state
        cacheMiss += 1
    rnum = 12
    if rnum in keyModification.keys():
      localStateModify = keyModification[rnum]
      state = [state[bnum] ^ localStateModify[bnum] for bnum in range(0,16)]
    state = subbytes(state)
    state = shiftrows(state)
    roundKey = key_schedule_rounds(self.key,0,rnum )
    state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
    if rnum == 10:
      return state
    return state

aes = AESModified(key_first)

import keymod
keyModification = keymod.keyModification

keyGuess = []
bytepos = 12

for keyGuessX in range(0,256):
  keyModification[13][11] = keyGuessX
  argmaxQDiffs = []
  maxQDiffs = []
  for r1mod in range(0,256):
    num_g1 = 0
    num_g2 = 0
    g1 = np.zeros(len(traces[0]),np.float32)
    g2 = np.zeros(len(traces[0]),np.float32)
    for tnum in range(0,2500):
      keyModification[TARGET_ROUND] = [r1mod] * 16
      s = aes.encryptToRound_fixed(pts[tnum],TARGET_ROUND + 1,keyModification,tnum)
      if bin(s[bytepos]).count("1") >= 4:
        num_g1 += 1
        g1 += traces[tnum]
      else:
        num_g2 += 1
        g2 += traces[tnum]
    g1 /= num_g1
    g2 /= num_g2
    qdiffs = abs(g1-g2)
    maxQDiffs += [max(qdiffs)]
    argmaxQDiffs += [np.argmax(qdiffs)]
  plt.clf()
  plt.plot(maxQDiffs)
  plt.savefig("unmask_r1/%d.png" % bytepos)
  print("Key Guess: %02x, XOR Key: %s (Pos %d, Max QDiffs %f, Avg QDiffs %f)" % (keyGuessX, hex(np.argmax(maxQDiffs)), argmaxQDiffs[np.argmax(maxQDiffs)], max(maxQDiffs),np.mean(maxQDiffs)))
  if max(maxQDiffs) > 0.2:
    print("Likely candidate: %02x" % keyGuessX)
  keyGuess += [np.argmax(maxQDiffs)]

print("Derived key:")
print(", ".join(["0x%02x" % k for k in keyGuess]))

print("Cache Hit: %d, Cache Miss: %d" % (cacheHit,cacheMiss))
