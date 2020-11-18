#!/usr/bin/env python3

from Crypto.Cipher import AES
import numpy as np
import binascii
import aeskeyschedule
import keymod
from chipwhisperer.analyzer.attacks.models.aes.funcs import subbytes, shiftrows, mixcolumns
from chipwhisperer.analyzer.attacks.models.aes.key_schedule import key_schedule_rounds

key = binascii.unhexlify("4b596315d21df5a531079c838e11eee6") # 8-bit SBox

aesCache = {}
for i in range(0,11):
  aesCache[i] = {}

cacheHit = 0
cacheMiss = 0

class AESModified:
  def __init__(self,key):
    self.key = key

  def encryptToRound(self,data,round,keyModification):
    global cacheHit,cacheMiss
    state = data
    roundKey = self.key
    state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
    for rnum in range(1,round):
      if 1 == 2:
        state = aesCache[rnum][tnum]
        cacheHit += 1
      else:
        if rnum in keyModification.keys():
          localStateModify = keyModification[rnum]
          state = [state[bnum] ^ localStateModify[bnum] for bnum in range(0,16)]
        state = subbytes(state)
        state = shiftrows(state)
        if rnum != 14:
          state = mixcolumns(state)
        roundKey = key_schedule_rounds(self.key,0,rnum )
        state = [state[bnum] ^ roundKey[bnum] for bnum in range(0,16)]
        if rnum == 14:
          return state

pts = np.load("glitch/in.npy",mmap_mode="r")
cts = np.load("glitch/out.npy",mmap_mode="r")

FINAL_ROUND = [0xf9, 0xf2, 0xde, 0xf1, 0x64, 0xef, 0xc2, 0x48, 0xb5, 0x59, 0x8e, 0xda, 0b11011110, 0x98, 0x17, 0xd3]
km = keymod.keyModification

byteError = []

import sys

error = [0] * 16
byteError = []
import sys

aes = AESModified(key)

# XOR ERROR
# [0, 0, 0, 99, 0, 0, 99, 0, 0, 98, 0, 0, 99, 0, 0, 0]

# INV BYTE:
# Result 12, Key byte 12
# Result 9, Key byte 13
# Result 6, Key 14
# result 3, Key 15

# Bytes impacting Keys 12, 13, 14, 15:
# 1, 6, 11, 12

def tryTarget():
  MOD_BYTE = 15
  TARGET_BYTE = 12
  for Round13Guess in range(0,256):
    km[13][6] = Round13Guess
    for Round14Guess in range(0,256):
      km[14][12] = Round14Guess
      print("Testing: %02x %02x" % (Round13Guess, Round14Guess))
      encrypt_0 = aes.encryptToRound(pts[0],15,km)
      encrypt_1 = aes.encryptToRound(pts[1],15,km)
      if encrypt_0[TARGET_BYTE] ^ cts[0][TARGET_BYTE] == encrypt_1[TARGET_BYTE] ^ cts[1][TARGET_BYTE]:
        print("Key match. Round 13 %02x, Round 14 %02x" % (Round13Guess,Round14Guess))
        encrypt_2 = aes.encryptToRound(pts[2],15,km)
        if encrypt_2[TARGET_BYTE] ^ cts[2][TARGET_BYTE] == encrypt_0[TARGET_BYTE] ^ cts[0][TARGET_BYTE]:
          print("Confirmed. Remaining error bytes:")
          KEY_SAVE = encrypt_2[TARGET_BYTE] ^ cts[2][TARGET_BYTE]
          errorState = False
          for i in range(0,100):
            guess1 = aes.encryptToRound(pts[i],15,km)
            if guess1[TARGET_BYTE] ^ cts[i][TARGET_BYTE] != KEY_SAVE :
              print("Error mismatch")
              errorState = True
          if not errorState:
            print("Candidate found!")
            sys.exit(0)

tryTarget()
