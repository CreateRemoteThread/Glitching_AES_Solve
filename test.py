#!/usr/bin/env python3

from Crypto.Cipher import AES
import numpy as np
import binascii
import aeskeyschedule
import keymod
from chipwhisperer.analyzer.attacks.models.aes.funcs import subbytes, shiftrows, mixcolumns
from chipwhisperer.analyzer.attacks.models.aes.key_schedule import key_schedule_rounds

key = binascii.unhexlify("4b596315d21df5a531079c838e11eee6") # 8-bit SBox

class AESModified:
  def __init__(self,key):
    self.key = key

  def encryptToRound(self,data,round,keyModification):
    global cacheHit,cacheMiss
    state = data
    roundKey = self.key
    state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
    for rnum in range(1,10):
      state = subbytes(state)
      state = shiftrows(state)
      state = mixcolumns(state)
      # adding a round key
      roundKey = key_schedule_rounds(self.key,0,rnum )
      state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
    state = subbytes(state)
    state = shiftrows(state)
    roundKey = key_schedule_rounds(self.key,0,rnum + 1 )
    state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
    return state

pts = np.load("glitch/in.npy",mmap_mode="r")
cts = np.load("glitch/out.npy",mmap_mode="r")

aesOrig = AES.new(key,AES.MODE_ECB)
f = aesOrig.encrypt(pts[0])
print(["%02x" % x for x in f])
aes = AESModified(key)
f = aes.encryptToRound(pts[0],10,keymod.keyModification)
print(["%02x" % x for x in f])


  


