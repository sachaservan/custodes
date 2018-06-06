import glob
import json

for filename in glob.glob("../cmd/*.json"):
    with open(filename) as f:
        data = json.load(f)
        print(data)

