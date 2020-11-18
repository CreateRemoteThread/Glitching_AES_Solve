#!/usr/bin/env python3

import numpy as np
import matplotlib.pyplot as plt
import sys

traces = np.load(sys.argv[1],mmap_mode="r")
plt.plot(traces[0])
plt.show()
