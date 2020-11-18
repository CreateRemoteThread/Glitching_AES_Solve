#!/usr/bin/env python3

from chipwhisperer.analyzer.attacks.models.aes.funcs import subbytes, shiftrows, mixcolumns
from chipwhisperer.analyzer.attacks.models.aes.key_schedule import key_schedule_rounds
import binascii

for i in range(0,16):
  state = [0x00] * 16
  state[i] = 0xFF
  print("%d" % i),
  state = shiftrows(state)
  print(state)
  state = mixcolumns(state)
  print(state)

