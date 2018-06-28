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
    'ytick.minor.size': 0.0}, font_scale = 1.2)

flatui = ['#28aad5', '#b24d94', '#38ae97' ,'#ec7545']


def runtime_bar(type, data, shares, showCategoriesLabel, show, size):
    comptime = {}
    comparetime = {}
    divtime = {}
    tottime = {}
    
    numParties = []
    datasetSizes = []
    categories = []
    
    #prefill
    for d in data:
        if d['TestType'] == type and d['UseShares'] == shares:
            if d['DatasetSize'] not in datasetSizes:
                datasetSizes.append(d['DatasetSize'])
                comptime[d['DatasetSize']] = {}
                divtime[d['DatasetSize']] = {}
                tottime[d['DatasetSize']] = {}
                comparetime[d['DatasetSize']] = {}
                
            if d['NumberOfParties'] not in numParties:
                numParties.append(d['NumberOfParties'])
                
            if d['NumberOfCategories'] not in categories:
                categories.append(d['NumberOfCategories'])
                
            if d['NumberOfParties'] not in comptime[d['DatasetSize']]:
                comptime[d['DatasetSize']][d['NumberOfParties']] = {}
                divtime[d['DatasetSize']][d['NumberOfParties']] = {} 
                tottime[d['DatasetSize']][d['NumberOfParties']] = {} 
                comparetime[d['DatasetSize']][d['NumberOfParties']] = {}                  

            if d['NumberOfCategories'] not in comptime[d['DatasetSize']][d['NumberOfParties']]:
                comptime[d['DatasetSize']][d['NumberOfParties']][d['NumberOfCategories']] = []
                divtime[d['DatasetSize']][d['NumberOfParties']][d['NumberOfCategories']] = [] 
                tottime[d['DatasetSize']][d['NumberOfParties']][d['NumberOfCategories']] = []                   
                comparetime[d['DatasetSize']][d['NumberOfParties']][d['NumberOfCategories']] = []   
       
    for d in data:
        if d['TestType'] == type and d['UseShares'] == shares:
            comptime[d['DatasetSize']][d['NumberOfParties']][d['NumberOfCategories']].append(d['ComputationTime'])
            divtime[d['DatasetSize']][d['NumberOfParties']][d['NumberOfCategories']].append(d['DivisionTime'])
            tottime[d['DatasetSize']][d['NumberOfParties']][d['NumberOfCategories']].append(d['TotalTime'])
            comparetime[d['DatasetSize']][d['NumberOfParties']][d['NumberOfCategories']].append(d['ComparisonTime'])
                   
    width = 0.15    
    gap = 0.02
    f, (ax1) = plt.subplots(1, 1, sharey=False, figsize=size)
    numParties = sorted(numParties)
    datasetSizes = sorted(datasetSizes)
    categories = sorted(categories)
    
    xIndices = len(numParties) * len(datasetSizes)  
    xLabels = {}
    p1 = None
    p2 = None
    p3 = None
    datasetLabelPrefix = '\n'
    for ds, datasetSize in enumerate(datasetSizes): 
        xLabels[datasetSize] = {} 
        for c, category in enumerate(categories):  
            xLabels[datasetSize][category] = []
            idx = ds * len(categories) + c 
            
            for p, numParty in enumerate(numParties):        
                mean_comp = np.array(comptime[datasetSize][numParty][category]).mean() 
                #std_comp = np.array(comptime[datasetSize][numParty][category]).std()
                mean_div = np.array(divtime[datasetSize][numParty][category]).mean()
                #std_div = np.array(divtime[datasetSize][numParty][category]).std()
                mean_compare = np.array(comparetime[datasetSize][numParty][category]).mean()
                tot_std = np.array(tottime[datasetSize][numParty][category]).std()
                
                
                
                #current_in
                total_width = width * len(numParties) + gap * (len(numParties) - 1)
                pos = (idx - total_width / 2 + width / 2) + width * p + gap * p
                
                xLabels[datasetSize][category].append((pos, numParty))
                
                p1 = ax1.bar(pos, mean_comp, width, color=flatui[0])            
                               
                if mean_compare != 0:
                    p2 = ax1.bar(pos, mean_div, width, bottom=mean_comp, color=flatui[1], hatch='//')
                    p3 = ax1.bar(pos, mean_compare, width, bottom=mean_div + mean_comp,  yerr=tot_std, color=flatui[2], hatch='\\')
                else:
                    p2 = ax1.bar(pos, mean_div, width, bottom=mean_comp, yerr=tot_std, color=flatui[1], hatch='//')
          
    # label
    axis_to_data = ax1.transAxes + ax1.transData.inverted()
    data_to_axis = axis_to_data.inverted()
    width_trans = data_to_axis.transform([width / 2, 0])[0]
    cat_yoff = -.20
    ds_yoff = -.30
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
                plt.plot([xpos, xpos], [0, cat_yoff], 'k-', lw=0.5, color='.8', clip_on=False, transform=ax1.transAxes)
                xpos = np.array(cat_max_xpos).max()
                plt.plot([xpos, xpos], [0, cat_yoff], 'k-', lw=0.5, color='.8', clip_on=False, transform=ax1.transAxes)
                    
                
        xpos = np.array(all_xpos).mean()
        ax1.text(xpos, ds_yoff, str(ds), ha='center', fontsize=11, transform=ax1.transAxes)
        xpos = np.array(min_xpos).min() 
        plt.plot([xpos, xpos], [0, ds_yoff], 'k-', lw=0.5, color='.8', clip_on=False, transform=ax1.transAxes)
        xpos = np.array(max_xpos).max()
        plt.plot([xpos, xpos], [0, ds_yoff], 'k-', lw=0.5, color='.8', clip_on=False, transform=ax1.transAxes)
        
    f.subplots_adjust(bottom=0.3)
    plt.xticks([])
    ax1.xaxis.grid(False)
    ax1.set_ylabel('time (mm:ss)')
    formatter = matplotlib.ticker.FuncFormatter(lambda ms, x: time.strftime('%M:%S', time.gmtime(ms)))
    ax1.yaxis.set_major_formatter(formatter)
    ymin, ymax = ax1.get_ylim()
    
    step = 60
    print (type, ymax / step)
    if ymax / step < 5:
        step = 20    
    elif ymax / step > 9 and ymax / step < 20:
        step = 2 * 60
    elif ymax / step > 20 and ymax / step < 50:
        step = 5 * 60
    elif ymax / step > 50:
        step = 15 * 60
        formatter = matplotlib.ticker.FuncFormatter(lambda ms, x: time.strftime("%H:%M:%S", time.gmtime(ms)))
        ax1.yaxis.set_major_formatter(formatter)
    plt.yticks(range(0, int(ymax), step))
    if p3 is not None:
        plt.legend((p1[0], p2[0], p3[0]), ('computation', 'division', 'compare'))
    else:
        plt.legend((p1[0], p2[0]), ('computation', 'division'))
    
    mode = 'noshares'
    if shares:
        mode = 'shares'
    f.savefig('fig/runtime_' + type.lower() + '_' + mode + '.pdf', bbox_inches='tight')
    
    
    if show:
        plt.show()    
        
        
    

if __name__== "__main__":
    show = True
    print ('TestType', 'UseShares', 'NumberOfParties', 'DatasetSize',  'PValue', 'TotalTime')
    
    all_runs = []
    for filename in glob.glob("./res/*.json"):
        with open(filename) as f:
            data = json.load(f)
            all_runs.append(data)
            print (data['TestType'], data['UseShares'], data['NumberOfParties'], data['DatasetSize'],  data['PValue'], data['TotalTime'])
            
    
    runtime_bar('CHI2', all_runs, True, True, show, (14, 4))    
    runtime_bar('TTEST', all_runs, True, False, show, (6, 4))
    runtime_bar('PEARSON', all_runs, True, False, show, (6, 4))
        
        