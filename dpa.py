#!/usr/bin/env python3

from numpy import *
import AES_SboxOut_HW
import AES_SboxOut_CW
import AES_TTableOut_HW
import AES_LastRound
import AES_Sbox_Diff
import XorOut_HW
import numpy as np
import matplotlib.pyplot as plt
import sys
import scipy
import scipy.stats

TRACE_COUNT = 2560
SAMPLE_OFFSET = 0
SAMPLE_COUNT=100

def doCPA(f,round,key):
  global am
  meant = np.mean(f,axis=0)[0:200]
  TRACE_LENGTH = 200
  sumnum = np.zeros(TRACE_LENGTH)
  sumden1 = np.zeros(TRACE_LENGTH)
  sumden2 = np.zeros(TRACE_LENGTH)
  hyp = np.zeros(TRACE_COUNT)
  for tnum in range(0,TRACE_COUNT):
    hyp[tnum] = am.genIVal(tnum,round,key)
  meanh = np.mean(hyp,dtype=np.float32)
  for tnum in range(0,TRACE_COUNT):
    hdiff = (hyp[tnum] - meanh)
    tdiff = f[tnum][0:200] - meant
    sumnum = sumnum + (hdiff * tdiff)
    sumden1 = sumden1 + hdiff * hdiff
    sumden2 = sumden2 + tdiff * tdiff
  d_ = np.sqrt(sumden1  * sumden2)
  d = np.zeros(len(d_))
  for d_index in range(0,len(d_)):
    if d_[d_index] == 0.0:
      d[d_index] = 1.0
    else:
      d[d_index] = d_[d_index]
  cpaout = sumnum / d
  # plt.plot(cpaout)
  # plt.show()
  return max(cpaout)

def do_DPA_bitsummary(f,round,key):
  fx = zeros(200,np.float32)
  for i in range(0,SAMPLE_COUNT):
    (numg1,numg2,dpaval) = do_DPA_sample(f,round,key,i)
    # print("DPA: Round %d, Key Guess: %02x Sample %d (Left: %d Right: %d, Total %d)" % (round,key,i,numg1,numg2,numg1+numg2))
    if numg1 <= 3 or numg2 <= 3:
      fx[i] = 0.0
    else:
      fx[i] = dpaval
  return fx

def do_DPA_sample(f,round,key,sample):
  global am
  group1 = 0.0
  group2 = 0.0
  num_g1 = 0
  num_g2 = 0
  for i in range(0,TRACE_COUNT):
    if f[i][sample] == 0.0:
      continue
    if am.distinguisher(i,round,key):
      num_g1 += 1
      group1 += f[i][sample]
    else:
      num_g2 += 1
      group2 += f[i][sample]
  group1 /= num_g1
  group2 /= num_g2
  return (num_g1,num_g2,abs(group1 - group2))

def do_DPA(f,round,key):
  global am
  group1 = []
  group2 = []
  num_g1 = 0
  num_g2 = 0
  g1 = zeros(len(f[0]))
  g2 = zeros(len(f[0]))
  for i in range(0,TRACE_COUNT):
    if am.distinguisher(i,round,key):
      num_g1 += 1
      g1[:] += (f[i])
      group1.append(f[i])
    else:
      num_g2 += 1
      g2[:] += (f[i])
      group2.append(f[i])
  g1[:] /= num_g1
  g2[:] /= num_g2
  return abs(g1[:] - g2[:])

traces = np.load("glitch/traces.npy",mmap_mode="r")[0:TRACE_COUNT,0:200]
pts = np.load("glitch/in.npy",mmap_mode="r")[0:TRACE_COUNT]
cts = np.load("glitch/out.npy",mmap_mode="r")[0:TRACE_COUNT]

am = AES_SboxOut_CW.AttackModel()
# am = AES_SboxOut_HW.AttackModel()
# am = AES_Sbox_Diff.AttackModel()
# am = AES_TTableOut_HW.AttackModel()
# am = XorOut_HW.AttackModel()
# am = AES_LastRound.AttackModel()
am.loadPlaintextArray(pts)
try:
  am.loadCiphertextArray(cts)
except:
  print("TODO: Fix loadCiphertextArray in the superclass")

key_out = ""
for round in range(0,16):
  differences = []
  diff_offsets = []
  for i in range(0,255):
    # ival = do_DPA_bitsummary(traces,round,i)
    # differences += [max(ival)]
    # diff_offsets += [argmax(ival)]
    # ival = doCPA(traces,round,i)
    # differences += [ival]
    fq = do_DPA(traces,round,i)
    differences += [max(fq)]
    diff_offsets += [argmax(fq)]
  plt.clf()
  plt.title("Maximum Difference of Means for Round %d" % round)
  plt.plot(differences)
  plt.savefig("graphs/round%d.png" % round)
  # plt.show()
  sorted_dpa = argsort(differences)[::-1]
  print("Selected %02x [%d], %f, %02x %f, %02x %f" % (argmax(differences),diff_offsets[argmax(differences)],differences[sorted_dpa[0]],sorted_dpa[1],differences[sorted_dpa[1]],sorted_dpa[2],differences[sorted_dpa[2]]))
  key_out += "%02x" % argmax(differences)

print(key_out)
