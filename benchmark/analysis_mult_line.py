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


def multiplication_line(show, size):
    
    f, (ax1) = plt.subplots(1, 1, sharey=False, figsize=size)
    df = pd.read_csv('multiplication_times.csv')
    sns.pointplot(x="numparties", y="shares", data=df, ax=ax1, color=flatui[0])
    sns.pointplot(x="numparties", y="paillier", data=df, ax=ax1, color=flatui[1], linestyles='--')
    
    ax1.legend(handles=ax1.lines[::len(df)+1], labels=['shares multiplication', 'paillier multiplication'])
        
    ax1.set_ylabel('time (ms)')
    ax1.set_xlabel('number of parties')   
        
    f.savefig('fig/multiplication_line.pdf', bbox_inches='tight')
        
    if show:
        plt.show()    
            

if __name__== "__main__":
    show = True
    multiplication_line(show, (6, 4))
        
        