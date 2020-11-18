#!/usr/bin/env python3

import sys
import numpy as np
import binascii
from Crypto.Cipher import AES

AES_MASK = [25, 19, 34, 65, 206, 22, 61, 247, 67, 232, 173, 67, 83, 211, 199, 165]

pt = np.load(sys.argv[1],mmap_mode="r")
tl = len(pt)

pt_stg2 = np.zeros((tl,16),np.uint8)

cryptor = AES.new(b"524a41541c0bc85272ef31c0ddc22943",AES.MODE_ECB)

for i in range(0,tl):
  # pt_stg1 = pt[i]
  pt_stg1 = list(pt[i])
  for x in range(0,16):
    pt_stg1[x] ^= AES_MASK[x]
  pt_stg2[i] = pt_stg1
  # pt_stg2[i] = list(cryptor.decrypt(pt_stg1))

np.save("glitch/pt_after_iv.npy",pt_stg2)

