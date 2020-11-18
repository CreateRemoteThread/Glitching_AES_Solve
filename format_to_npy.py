#!/usr/bin/env python3

import sys
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt

f = open(sys.argv[1])
d = f.readline()

lastptl = ""
traces = np.zeros((3000,1625),np.float32)
traceIndex = -1

data_in = np.zeros((3000,16),np.uint8)
data_out = np.zeros((3000,16),np.uint8)

while d:
  # grab and go to next line first
  experiment = np.safe_eval(d.rstrip())
  pt = experiment[0].replace("plaintext:","")[1:-1].split()
  pt_l = "".join(["%02x" % int(token) for token in pt])
  pt_r = [int(token) for token in pt]
  time_l = int(experiment[1].split(":")[1].replace(" ",""))
  power_l = float(experiment[2].split(":")[1].replace(" ",""))
  result_l = experiment[4]
  d = f.readline()
  if pt_l != lastptl:
    lastptl = pt_l
    lastout = None
    traceIndex += 1
    print("Processing trace %d, pt %s" % (traceIndex,lastptl)) 
  if result_l == "NO ANSWER":
    result_l = "00" * 16
    traces[traceIndex,time_l] = 0.0
  else:
    result_x = "".join(["%02x" % x for x in result_l ])
    result_r = [int(x) for x in result_l ]
    result_l = result_x
    if lastout is None:  # handle writing here only.
      lastout = result_l
      data_in[traceIndex] = pt_r
      data_out[traceIndex] = result_r
    traces[traceIndex,time_l] = power_l

f.close()
np.save("glitch/in.npy",data_in)
np.save("glitch/out.npy",data_out)
np.save("glitch/traces.npy",traces)
