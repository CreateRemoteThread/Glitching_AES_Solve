#!/usr/bin/env python3

import binascii
from chipwhisperer.analyzer.attacks.models.aes.key_schedule import key_schedule_rounds

# original forward key:    4b596315d21df5a531079c838e11eee6 (no XOR)
# Last round DPA key:      c95c9f4d0054e0376518b43e6e4eb7ab (r9, no XOR)
# First round DPA key:     524a41541c0bc85272ef31c0ddc22943 (PT ^ AES_MASK)

XOR_KEY = [0xc5,0xb9,0x50,0x88,0xde,0x71,0x6f,0x34,0xcd,0xa4,0x75,0xed,0xa3,0xa4,0xb9,0xd7]
XOR_KEY2 = [0x47,0x4c,0x6a,0x70,0x8f,0x3d,0x87,0x7c,0x95,0x51,0x9f,0xd5,0xbe,0x3a,0x1b,0xff]
from Crypto.Cipher import AES
from aeskeyschedule import key_schedule,reverse_key_schedule

key = list(binascii.unhexlify("4b596315d21df5a531079c838e11eee6"))
for i in range(0,16):
  key[i] ^= XOR_KEY[i]
aes_orig_key = reverse_key_schedule(key,1)

print(binascii.hexlify(aes_orig_key))
key = list(binascii.unhexlify("4b596315d21df5a531079c838e11eee6"))
for i in range(0,16):
  key[i] ^= XOR_KEY2[i]
aes_orig_key = reverse_key_schedule(key,2)

print(binascii.hexlify(aes_orig_key))
cryptor = AES.new(bytes(aes_orig_key),AES.MODE_ECB)

pt="2801dd800e7ae333258224d5cbfc5420ec72a12256bdff61814972c7f93948f8"
print(cryptor.decrypt(binascii.unhexlify(pt)))




