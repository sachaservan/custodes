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

def minutes_second_formatter(value, tick_number):
    m, s = divmod(value, 60)
    return '%02d:%02d' % (m, s)

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
    'ytick.minor.size': 0.0}, font_scale = 1.5)

flatui = ['#28aad5', '#b24d94', '#38ae97' ,'#ec7545']


def runtime_bar(type, data, shares, show):
    comptime = {}
    divtime = {}
    
    numParties = []
    datasetSizes = []
    
    #prefill
    for d in data:
        if d['TestType'] == type and d['UseShares'] == shares:
            if d['DatasetSize'] not in datasetSizes:
                datasetSizes.append(d['DatasetSize'])
                comptime[d['DatasetSize']] = {}
                divtime[d['DatasetSize']] = {}
                
            if d['NumberOfParties'] not in numParties:
                numParties.append(d['NumberOfParties'])
                
            if d['NumberOfParties'] not in comptime[d['DatasetSize']]:
                comptime[d['DatasetSize']][d['NumberOfParties']] = []
                divtime[d['DatasetSize']][d['NumberOfParties']] = []               
       
    for d in data:
        if d['TestType'] == type:
            print(d['DatasetSize'], d['NumberOfParties'])
            comptime[d['DatasetSize']][d['NumberOfParties']].append(d['ComputationTime'])
            divtime[d['DatasetSize']][d['NumberOfParties']].append(d['DivisionTime'])
            
            
    width = 0.15    
    gap = 0.01
    f, (ax1) = plt.subplots(1, 1, sharey=False, figsize=(6, 4))             
    numParties = sorted(numParties)
    datasetSizes = sorted(datasetSizes)
    
    xIndices = len(numParties) * len(datasetSizes)  
    xTicks = []
    xLabels = []
    p1 = None
    p2 = None
    for ds, datasetSize in enumerate(datasetSizes):
        for p, numParty in enumerate(numParties):        
            mean_comp = np.array(comptime[datasetSize][numParty]).mean() 
            std_comp = np.array(comptime[datasetSize][numParty]).std()
            mean_div = np.array(divtime[datasetSize][numParty]).mean()
            std_div = np.array(divtime[datasetSize][numParty]).std()
            #current_in
            total_width = width * len(numParties) + gap * (len(numParties) - 1)
            pos = (ds - total_width / 2 + width / 2) + width * p + gap * p
            xTicks.append(pos)
            if p == (len(numParties) - 1) / 2:
                xLabels.append(str(numParty) + '\n' + '{:,}'.format(datasetSize))
            else:
                xLabels.append(numParty)
            p1 = ax1.bar(pos, mean_comp, width, yerr=std_comp, color=flatui[0])            
            p2 = ax1.bar(pos, mean_div, width, bottom=mean_comp, yerr=std_div, color=flatui[1], hatch='//')
          
    plt.xticks(xTicks, xLabels)
    ax1.xaxis.grid(False)
    ax1.set_ylabel('time (mm:ss)')
    ax1.yaxis.set_major_formatter(plt.FuncFormatter(minutes_second_formatter))
    plt.legend((p1[0], p2[0]), ('computation', 'division'))
    
    f.savefig('fig/runtime_' + type.lower() + '.pdf', bbox_inches='tight')
    plt.tight_layout()
    
    if show:
        plt.show()    
    
            
    

if __name__== "__main__":
    show = False
    
    all_runs = []
    for filename in glob.glob("./res/*.json"):
        with open(filename) as f:
            data = json.load(f)
            all_runs.append(data)
            
    runtime_bar('TTEST', all_runs, false, show)
    runtime_bar('PEARSON', all_runs, false, show)
        
        