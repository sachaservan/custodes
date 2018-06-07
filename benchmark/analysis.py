import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib    
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import math
import json
import datetime
import matplotlib.dates as mdates
import os.path
import pickle

sns.set(context='paper', style={'axes.axisbelow': True,
    'axes.edgecolor': '.8',
    'axes.facecolor': 'white',
    'axes.grid': True,
    'axes.labelcolor': '.15',
    'axes.linewidth': 0.5,
    'figure.facecolor': 'white',
    'font.family': [u'sans-serif'],
    'font.sans-serif': [u'Abel'],
    'font.weight' : u'light',
    'grid.color': '.8',
    'grid.linestyle': u'-',
    'image.cmap': u'Greys',
    'legend.frameon': True,
    'legend.numpoints': 1,
    'legend.scatterpoints': 1,
    'lines.solid_capstyle': u'butt',
    'text.color': '.15',
    'xtick.color': '.15',
    'xtick.direction': u'out',
    'xtick.major.size': 0.0,
    'xtick.minor.size': 0.0,
    'ytick.color': '.15',
    'ytick.direction': u'out',
    'ytick.major.size': 0.0,
    'ytick.minor.size': 0.0}, font_scale = 2)

flatui = ['#28aad5', '#b24d94', '#38ae97' ,'#ec7545']


def runtime_bar(type, numParties, data):
    comptime = {}
    divtime = {}
    for d in data:
        if d['TestType'] == type and d['NumberOfParties'] == numParties:
            if d['DatasetSize'] not in comptime:
                comptime[d['DatasetSize']] = []
            comptime[d['DatasetSize']].append(d['ComputationTime'])
            
            if d['DatasetSize'] not in divtime:
                divtime[d['DatasetSize']] = []
            divtime[d['DatasetSize']].append(d['DivisionTime'])
            
    
    sorted_keys = sorted(divtime.keys())
    ind = range(len(sorted_keys))
    comp = []
    comp_std = []
    div = []
    div_std = []
    
    for k in sorted_keys:
        comp.extend(comptime[k])
        div.extend(divtime[k])
        comp_std.append(np.array(comptime[k]).std())
        div_std.append(np.array(divtime[k]).std())
    print(comp)
    width = 0.35
    p1 = plt.bar(ind, comp, width, yerr=comp_std, color=flatui[0])
    p2 = plt.bar(ind, div, width, bottom=comp, yerr=div_std, color=flatui[1])

    plt.ylabel('time in seconds')
    plt.xticks(ind, [str(i) for i in sorted_keys])
    plt.legend((p1[0], p2[0]), ('Computation Time', 'Division Time'))

    plt.show()    
            
    

if __name__== "__main__":
    all_runs = []
    for filename in glob.glob("..\\cmd\\*.json"):
        with open(filename) as f:
            data = json.load(f)
            all_runs.append(data)
            
    runtime_bar('TTEST', 3, all_runs)
        
        