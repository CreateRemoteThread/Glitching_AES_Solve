#!/usr/bin/env python3

import sys
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt

f = open(sys.argv[1])
d = f.readline()

lastptl = ""

lastKnownGood = {}
lastKnownPT = {}

bucketCount = {}

mutes = np.zeros(2000)
glitches = np.zeros(2000)
good = np.zeros(2000)

while d:
  experiment = np.safe_eval(d.rstrip())
  pt = experiment[0].replace("plaintext:","")[1:-1].split()
  pt_l = "".join(["%02x" % int(token) for token in pt])
  time_l = int(experiment[1].split(":")[1].replace(" ",""))
  power_l = float(experiment[2].split(":")[1].replace(" ",""))
  result_l = experiment[4]
  d = f.readline()
  if pt_l != lastptl:
    print("ptl:%s" % pt_l)
    lastptl = pt_l
  if result_l == "NO ANSWER":
    result_l = "00" * 16
    mutes[time_l] += 1
  elif len(result_l) != 16:
    print(result_l)
    sys.exit(0)
  else:
    result_x = "".join(["%02x" % x for x in result_l ])
    result_l = result_x 
    if result_l not in lastKnownPT.keys():
      lastKnownPT[result_l] = pt_l
    else:
      if lastKnownPT[result_l] != pt_l:
        print("Collision: %s %s" % (pt_l,lastKnownPT[result_l]))
        sys.exit(0)
    if pt_l not in lastKnownGood.keys():
      print("%s lkg:%s" % (lastptl,result_l))
      lastKnownGood[pt_l] = result_l
      good[time_l] += 1
    else:
      if result_l == lastKnownGood[pt_l]:
        good[time_l] += 1
      else:
        print("GLITCH:%s" % pt_l)
        glitches[time_l] += 1
        sys.exit(0)

fig,ax = plt.subplots()
ax.plot(mutes,color='yellow',label="Mutes")
ax.plot(good,color='green',label="Good")
ax2 = ax.twinx()
ax2.plot(glitches,color='red',label="Glitches")
plt.legend()
plt.show()

f.close()
