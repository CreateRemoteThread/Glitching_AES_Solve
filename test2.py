#!/usr/bin/env python3

from Crypto.Cipher import AES
import numpy as np
import binascii
import aeskeyschedule

keyfwd = binascii.unhexlify("4b1d9ce6d207ee15311163a58e59f583") # sbox mixcols hw output
# keyfwd = binascii.unhexlify("524a41541c0bc85272ef31c0ddc22943")
# keyfwd = binascii.unhexlify("c95c9f4d0054e0376518b43e6e4eb7ab")
# keyfwd = binascii.unhexlify("4b596315d21df5a531079c838e11eee6")

AES_MASK = [25, 19, 34, 65, 206, 22, 61, 247, 67, 232, 173, 67, 83, 211, 199, 165]

ct = binascii.unhexlify("2801dd800e7ae333258224d5cbfc5420ec72a12256bdff61814972c7f93948f8")

for i in range(0,16):
  key_real = list(keyfwd)
  for keyguess in range(0,256):
    key_real[i] = keyguess
    mode = AES.MODE_ECB
    cryptor = AES.new(bytes(key_real),AES.MODE_ECB)
    q = list(cryptor.decrypt(ct))
    for f in range(0,len(q)):
      q[f] ^= AES_MASK[f % len(AES_MASK)]
    print(bytes(q))
