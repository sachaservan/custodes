#/usr/bin/python
import csv
import sys
import math
import random

def convert(outfile, n, valmin, valmax):
    with open(outfile, 'w') as fout:
        for i in range(0, n):
            r1 = random.randint(valmin, valmax)
            r2 = random.randint(valmin, valmax)
            if random.randint(0, 3) == 1:
                r2 = math.floor(r1/2)

            fout.write("" + str(r1) + "," + str(r2) + "\n")


if __name__ == "__main__":
    if (len(sys.argv) < 5):
        print ("Create a random dataset with two cols and <n> rows."\
                "where values is between <min> and <max>.")
        print ("Usage: datasetgen.py <file out> <n> <min> <max>")
        sys.exit(1)

    sys.argv.pop(0)
    fout = sys.argv.pop(0)
    n = sys.argv.pop(0)
    minval = sys.argv.pop(0)
    maxval = sys.argv.pop(0)
    convert(fout, int(n), int(minval), int(maxval))
