#!/usr/bin/env python3

from Crypto.Cipher import AES
import numpy as np
import binascii
import aeskeyschedule
import keymod
from chipwhisperer.analyzer.attacks.models.aes.funcs import subbytes, shiftrows, mixcolumns, inv_subbytes,inv_mixcolumns,inv_shiftrows
from chipwhisperer.analyzer.attacks.models.aes.key_schedule import key_schedule_rounds

key = binascii.unhexlify("4b596315d21df5a531079c838e11eee6") # 8-bit SBox

aesCache = {}
for i in range(0,11):
  aesCache[i] = {}

cacheHit = 0
cacheMiss = 0

def hexArray(data):
  return ", ".join(["%02x" % x for x in data])

class AESModified:
  def __init__(self,key):
    self.key = key

  def decrypt(self,data,keyModification):
    FR = [249, 242, 222, 181, 100, 239, 39, 72, 181, 70, 142, 218, 123, 152, 23, 211]
    state = list(data)
    for bnum in range(0,16):
      state[bnum] ^= FR[bnum]
    for rnum in range(14,0,-1):
      print(rnum)
      roundKey = key_schedule_rounds(self.key,0,rnum)
      for bnum in range(0,16):
        state[bnum] ^= roundKey[bnum]
      print("Round %d inv_addroundkey %s" % (rnum,hexArray(state)))
      if rnum != 14:
        state = inv_mixcolumns(state)
      state = inv_shiftrows(state)
      print("Round %d inv_shiftrows %s" % (rnum,hexArray(state)))
      state = inv_subbytes(state)
      print("Round %d inv_subbytes %s" % (rnum,hexArray(state)))
      if rnum in keyModification.keys():
        localStateModify = keyModification[rnum]
        state = [state[bnum] ^ localStateModify[bnum] for bnum in range(0,16)]
    print("Post-loop pre-mix: %s" % hexArray(state))
    for bnum in range(0,16):
      state[bnum] ^= self.key[bnum]
    print("Post-loop post-mix: %s" % hexArray(state))
    return state

  def encryptToRound(self,data,round,keyModification):
    global cacheHit,cacheMiss
    state = data
    roundKey = self.key
    print("Pre-loop pre-mix: %s" % hexArray(state))
    state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
    print("Pre-loop: %s" % hexArray(state))
    for rnum in range(1,round):
      if 1 == 2:
        state = aesCache[rnum][tnum]
        cacheHit += 1
      else:
        print(rnum)
        if rnum in keyModification.keys():
          localStateModify = keyModification[rnum]
          state = [state[bnum] ^ localStateModify[bnum] for bnum in range(0,16)]
        print("Round %d pre_subbytes %s" % (rnum,hexArray(state)))
        state = subbytes(state)
        print("Round %d pre_shiftrows %s" % (rnum,hexArray(state)))
        state = shiftrows(state)
        if rnum != 14:
          state = mixcolumns(state)
        print("Round %d, pre-mix state %s" % (rnum,hexArray(state)))
        roundKey = key_schedule_rounds(self.key,0,rnum )
        state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
        print("Round %d, post-mixin state %s" % (rnum,hexArray(state)))
        if rnum == 14:
          return state

pts = np.load("glitch/in.npy",mmap_mode="r")
cts = np.load("glitch/out.npy",mmap_mode="r")

FINAL_ROUND = [249, 242, 222, 181, 100, 239, 39, 72, 181, 70, 142, 218, 123, 152, 23, 211]
km = keymod.keyModification

byteError = []

import sys

error = [0] * 16
byteError = []

import sys

aes = AESModified(key)

encrypt_0 = aes.encryptToRound(pts[0],15,km)
for i in range(0,16):
  encrypt_0[i] ^= FINAL_ROUND[i]

print(hexArray(encrypt_0))
print(hexArray(list(cts[0])))

decrypt_0 = list(cts[0])
# for i in range(0,16):
#   decrypt_0[i] ^= FINAL_ROUND[i]

print(hexArray(decrypt_0))


REALKEY = b"2801dd800e7ae333258224d5cbfc5420ec72a12256bdff61814972c7f93948f8"

decrypt_0 = binascii.unhexlify(REALKEY)[0:16]
fq = aes.decrypt(decrypt_0,km)
str1 = "".join([chr(f) for f in fq])
decrypt_0 = binascii.unhexlify(REALKEY)[16:]
fq2 = aes.decrypt(decrypt_0,km)
str2 = "".join([chr(f) for f in fq2])


print("------- THATS ALL SHE WROTE --------")
print(str1 + str2)
