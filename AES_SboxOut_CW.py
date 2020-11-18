#!/usr/bin/env python3

import binascii
import chipwhisperer.analyzer as cwa
from chipwhisperer.analyzer.attacks.models.aes.funcs import inv_sbox,sbox,subbytes,shiftrows

def getHammingWeight(x):
  return bin(x).count("1")

HW_LUT = [getHammingWeight(x) for x in range(0,256)]

class AttackModel:
  INVSHIFT_undo = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]
  def __init__(self):
    self.knownKey = binascii.unhexlify("4b596315d21df5a531079c838e11eee6")

  def loadPlaintextArray(self,pt):
    print("Loading plaintext array for AES SBox Out HW (CW Variant) Attack...")
    self.pt = pt

  def loadCiphertextArray(self,ct):
    self.ct = ct

  def distinguisher(self,tnum,bnum,kguess):
    global HW_LUT
    klist = list(self.knownKey)
    klist[bnum] = kguess
    # st1 = [self.pt[tnum][i] ^ klist[i] for i in range(0,16)] # initial ky mixin
    st1 = [self.pt[tnum][i] ^ kguess for i in range(0,16)]
    st1 = subbytes(st1)
    st1 = shiftrows(st1)
    return HW_LUT[st1[bnum]] >= 4
