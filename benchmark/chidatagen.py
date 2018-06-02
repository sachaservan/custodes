#!/usr/bin/python
import csv
import sys
import math
import random

def convert(outfile, n, k):
    with open(outfile, 'w') as fout:
        for i in range(0, n):
            r = random.randint(0, k-1)
            for j in range(0, k-1):
                if j == r:
                    fout.write(str(1) + ",")
                else:
                    fout.write(str(0) + ",")
            if r == k-1:
                fout.write(str(1) + "\n")
            else:
                fout.write(str(0) + "\n")

if __name__ == "__main__":
    if (len(sys.argv) < 4):
        print ("Create a random categorical dataset with <k> cols (categories) \
                and <n> rows.")
        print ("Usage: datasetgen.py <file out> <n> <k>")
        sys.exit(1)

    sys.argv.pop(0)
    fout = sys.argv.pop(0)
    n = sys.argv.pop(0)
    k = sys.argv.pop(0)
    convert(fout, int(n), int(k))
