#!/usr/bin/env python3

from chipwhisperer.analyzer.attacks.models.aes.funcs import subbytes, shiftrows, mixcolumns
from chipwhisperer.analyzer.attacks.models.aes.key_schedule import key_schedule_rounds

import numpy as np
import matplotlib.pyplot as plt
import binascii
from Crypto.Cipher import AES

pts = np.load("glitch/in.npy",mmap_mode="r")
cts = np.load("glitch/out.npy",mmap_mode="r")
traces = np.load("glitch/traces.npy",mmap_mode="r")

key_first = binascii.unhexlify("4b596315d21df5a531079c838e11eee6")
key_back = binascii.unhexlify("c95c9f4d0054e0376518b43e6e4eb7ab")
key_back_resolved = binascii.unhexlify("524a41541c0bc85272ef31c0ddc22943")

class AESModified:
  def __init__(self,key):
    self.key = key

  def encryptToRound(self,data,round,keyModification={}):
    state = data
    roundKey = self.key
    # MIX IN THE INITIAL KEY
    state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
    for rnum in range(0,round):
      # modification comes before sbox, i guess?
      if rnum in keyModification.keys():
        localStateModify = keyModification[rnum]
        state = [state[bnum] ^ localStateModify[bnum] for bnum in range(0,16)]
      state = subbytes(state)
      state = shiftrows(state)
      state = mixcolumns(state)
      if rnum == round - 1:
        return state
      # print("Executing miscolumns for round %d" % rnum)
      roundKey = key_schedule_rounds(self.key,0,rnum + 1)
      state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
    return state

aes = AESModified(key_first)

import sys
bytepos = int(sys.argv[1])

import keymod
keyModification = keymod.keyModification

TARGET_ROUND = 11

num_g1 = 0
num_g2 = 0
g1 = np.zeros(len(traces[0]),np.float32)
g2 = np.zeros(len(traces[0]),np.float32)
for tnum in range(0,2500):
  s = aes.encryptToRound(pts[tnum],TARGET_ROUND,keyModification) # round 1 is 
  if bin(s[bytepos]).count("1") >= 4:
    num_g1 += 1
    g1 += traces[tnum]
  else:
    num_g2 += 1
    g2 += traces[tnum]
g1 /= num_g1
g2 /= num_g2
qdiffs = abs(g1-g2)

fig,ax = plt.subplots()
ax.plot(qdiffs)
ax.hlines(y=0.20,xmin=0,xmax=len(qdiffs),color='r')
plt.show()

