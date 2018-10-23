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
import time
import matplotlib.dates as mdates
from matplotlib.font_manager import FontProperties

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
    'xtick.color': '.8',
    'xtick.direction': u'out',
    'xtick.major.size': 0.0,
    'xtick.minor.size': 0.0,
    'ytick.color': '.8',
    'ytick.direction': u'out',
    'ytick.major.size': 0.0,
    'ytick.minor.size': 0.0}, font_scale = 1.2)

flatui = ['#28aad5', '#b24d94', '#38ae97' ,'#ec7545']

datasetname = { 'T-Test'  : {1000 : 'rand_1k', 5000: 'rand_5k', 10000: 'rand_10k', 4177: 'Abalone'},
                'Pearson' : {1000 : 'rand_1k', 5000: 'rand_5k', 10000: 'rand_10k', 4177: 'Abalone'}, 
                'Chi-Squared' : {1000 : 'cat_1k', 5000: 'cat_5k', 10000: 'cat_10k', 108: 'Pittsburgh'}}

sortorder = { 'T-Test'  : {1000 : '1', 5000: '2', 10000: '3', 4177: '0'},
              'Pearson' : {1000 : '1', 5000: '2', 10000: '3', 4177: '0'}, 
              'Chi-Squared' : {1000 : '1', 5000: '2', 10000: '3', 108: '0'}}


def runtime_bar(type, data, showCategoriesLabel, show, size):
    comptime = {}
    divtime = {}
    
    numParties = []
    NumRowss = []
    categories = {}
    
    #prefill
    for d in data:
        if d['Test'] == type:
            if d['NumRows'] not in NumRowss:
                NumRowss.append(d['NumRows'])
                comptime[d['NumRows']] = {}
                divtime[d['NumRows']] = {}
                categories[d['NumRows']] = []
                
            if d['NumParties'] not in numParties:
                numParties.append(d['NumParties'])
                
            if d['NumCols'] not in categories[d['NumRows']]:
                categories[d['NumRows']].append(d['NumCols'])
                
            if d['NumParties'] not in comptime[d['NumRows']]:
                comptime[d['NumRows']][d['NumParties']] = {}
                divtime[d['NumRows']][d['NumParties']] = {}                

            if d['NumCols'] not in comptime[d['NumRows']][d['NumParties']]:
                comptime[d['NumRows']][d['NumParties']][d['NumCols']] = []
                divtime[d['NumRows']][d['NumParties']][d['NumCols']] = []   
       
    for d in data:
        if d['Test'] == type:
            comptime[d['NumRows']][d['NumParties']][d['NumCols']].append(d['ComputeRuntime'])
            divtime[d['NumRows']][d['NumParties']][d['NumCols']].append(d['DivRuntime'])
            
    print(categories)        
    width = 0.24 
    gap = 0.02
    f, (ax1) = plt.subplots(1, 1, sharey=False, figsize=size)
    numParties = sorted(numParties)
    NumRowss = sorted(NumRowss)
    NumRowss = sorted(NumRowss, key=lambda k: sortorder[type][k]) 
    print(NumRowss)
    
    xLabels = {}
    p1 = None
    p2 = None
    ccc = 0
    for ds, NumRows in enumerate(NumRowss): 
        xLabels[NumRows] = {} 
        for c, category in enumerate(categories[NumRows]):   
            xLabels[NumRows][category] = []
            idx = ccc #ds * len(categories[NumRows]) + c 
            ccc = ccc + 1
            
            for p, numParty in enumerate(numParties):          
                mean_comp = np.array(comptime[NumRows][numParty][category]).mean() 
                std_comp = np.array(comptime[NumRows][numParty][category]).std()
                mean_div = np.array(divtime[NumRows][numParty][category]).mean()
                std_div = np.array(divtime[NumRows][numParty][category]).std()
                #current_in
                total_width = width * len(numParties) + gap * (len(numParties) - 1)
                pos = (idx - total_width / 2 + width / 2) + width * p + gap * p
                
                xLabels[NumRows][category].append((pos, numParty))
                
                p1 = ax1.bar(pos, mean_comp, width, yerr=std_comp, color=flatui[1], hatch='//')            
                p2 = ax1.bar(pos, mean_div, width, bottom=mean_comp, yerr=std_div, color=flatui[0])
          
    # label
    axis_to_data = ax1.transAxes + ax1.transData.inverted()
    data_to_axis = axis_to_data.inverted()
    width_trans = data_to_axis.transform([width / 2, 0])[0]
    cat_yoff = -.20
    ds_yoff = -.30
    leftmost = 1000
    if not showCategoriesLabel:
        ds_yoff = cat_yoff
    pa_yoff = -.1
    
    for ds in xLabels: 
        all_xpos = []
        min_xpos = []
        max_xpos = []
        for cat in xLabels[ds]:  
            cat_all_xpos = []
            cat_min_xpos = []
            cat_max_xpos = []
            for p in xLabels[ds][cat]:
                xpos = data_to_axis.transform([p[0], 0])[0]
                
                all_xpos.append(xpos)
                min_xpos.append(data_to_axis.transform([p[0] - width / 2, 0])[0])
                max_xpos.append(data_to_axis.transform([p[0] + width / 2, 0])[0])
                
                cat_all_xpos.append(xpos)
                cat_min_xpos.append(data_to_axis.transform([p[0] - width / 2, 0])[0])
                cat_max_xpos.append(data_to_axis.transform([p[0] + width / 2, 0])[0])
                
                ax1.text(xpos, pa_yoff, str(p[1]), ha='center', fontsize=11, transform=ax1.transAxes)   
            if showCategoriesLabel:
                xpos = np.array(cat_all_xpos).mean()
                ax1.text(xpos, cat_yoff, str(cat), ha='center', fontsize=11, transform=ax1.transAxes)
                xpos = np.array(cat_min_xpos).min() 
                plt.plot([xpos, xpos], [0, cat_yoff], 'k-', lw=1.0, color='.8', clip_on=False, transform=ax1.transAxes)
                xpos = np.array(cat_max_xpos).max()
                plt.plot([xpos, xpos], [0, cat_yoff], 'k-', lw=1.0, color='.8', clip_on=False, transform=ax1.transAxes)
                    
                
        xpos = np.array(all_xpos).mean()
        dsName = datasetname[type][ds]
        ax1.text(xpos, ds_yoff, dsName, ha='center', fontsize=11, transform=ax1.transAxes)
        xpos = np.array(min_xpos).min() 
        leftmost = min(leftmost, xpos)
        plt.plot([xpos, xpos], [0, ds_yoff], 'k-', lw=2.5, color='.8', clip_on=False, transform=ax1.transAxes)
        xpos = np.array(max_xpos).max()
        plt.plot([xpos, xpos], [0, ds_yoff], 'k-', lw=2.5, color='.8', clip_on=False, transform=ax1.transAxes)

    ax1.text(leftmost-0.005, pa_yoff, '# parties:', ha='right', fontsize=11, transform=ax1.transAxes)
    ax1.text(leftmost-0.005, ds_yoff, 'dataset:', ha='right', fontsize=11, transform=ax1.transAxes)
    if showCategoriesLabel:
        ax1.text(leftmost-0.005, cat_yoff, '# categories:', ha='right', fontsize=11, transform=ax1.transAxes)
        
    f.subplots_adjust(bottom=0.3)
    plt.xticks([])
    ax1.xaxis.grid(False)
    ax1.set_ylabel('time in seconds')
    #formatter = matplotlib.ticker.FuncFormatter(lambda ms, x: time.strftime('%M:%S', time.gmtime(ms)))
    #ax1.yaxis.set_major_formatter(formatter)
   
    plt.legend((p1[0], p2[0]), ('computation', 'division'))
    plt.setp(ax1.get_xticklabels(), color=".15")
    plt.setp(ax1.get_yticklabels(), color=".15")
    
    mode = 'shares'
    #if shares:
    #    mode = 'shares'
    f.savefig('fig/runtime_' + type.lower() + '_' + mode + '.pdf', bbox_inches='tight')
    
    
    if show:
        plt.show()    
        
        
    

if __name__== "__main__":
    show = True
    
    all_runs = []
    for filename in glob.glob("../results/*.json"):
        with open(filename) as f:
            data = json.load(f)
            all_runs.append(data)
    
    for d in all_runs:
        if d['Test'] == 'T-Test' and d['NumParties'] == 16 and d['NumRows'] == 10000:
            print (d['DivRuntime'])
    
    runtime_bar('Chi-Squared', all_runs, True, show, (14, 4))    
    runtime_bar('T-Test', all_runs, False, show, (6, 4))
    runtime_bar('Pearson', all_runs, False, show, (6, 4))
        
        