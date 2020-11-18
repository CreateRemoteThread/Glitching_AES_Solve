#!/usr/bin/env python3

import sys
import numpy as np

f = open("campaign_results.txt")
d = f.readline()

last_ptl = ""
fq = None

bucketCount = {}

while d:
  experiment = np.safe_eval(d.rstrip())
  pt = experiment[0].replace("plaintext:","")[1:-1].split()
  pt_l = "".join(["%02x" % int(token) for token in pt])
  time_l = int(experiment[1].split(":")[1].replace(" ",""))
  result_l = experiment[4]
  if result_l == "NO ANSWER":
    result_l = "00" * 16
  else:
    result_x = "".join(["%02x" % x for x in result_l ])
    result_l = result_x
  if pt_l == last_ptl:
    fq.write(result_l)
    fq.write("\n")
  else:
    if fq is not None:
      fq.close()
    print("+%s" % pt_l)
    fq = open("experiments/%s" % pt_l,"a")
    fq.write(result_l)
    fq.write("\n")
    last_ptl = pt_l
  if pt_l in bucketCount.keys():
    bucketCount[pt_l] += 1
  else:
    bucketCount[pt_l] = 1
  d = f.readline()

f.close()

for pt_l in bucketCount.keys():
  print("%s:%d" % (pt_l,bucketCount[pt_l]))
