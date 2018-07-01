from scipy import stats
import pandas as pd
import numpy as np

datasets = {1000: pd.read_csv('benchmark_1000.csv', names =['A', 'B']), 
            5000: pd.read_csv('benchmark_5000.csv', names =['A', 'B']),
            10000: pd.read_csv('benchmark_10000.csv', names =['A', 'B'])}
            
error = {'TTEST':[], 'CHI2':[], 'PEARSON': []}

df = pd.read_csv('data.csv')
for index, row in df.iterrows():
    if row['runid'] > 0 or row['NumberOfParties'] != 3:
        continue
    stat_hypo = row['PValue']
    data = datasets[row['DatasetSize']]
    
    if row['TestType'] == 'TTEST':
        stat_comp, pvalue_comp = stats.ttest_ind(data['A'], data['B'])
        
        p_hypo = stats.distributions.t.sf(np.abs(stat_hypo), len(data['A'])*2 - 2) * 2
        
        error['TTEST'].append(abs(pvalue_comp - p_hypo))
        print(row['TestType'], row['DatasetSize'], pvalue_comp, p_hypo)

    elif row['TestType'] == 'PEARSON':
        stat_comp, pvalue_comp = stats.pearsonr(data['A'], data['B'])
        
        df = len(data['A']) - 2
        TINY = 1e-20
        rpb = stat_hypo
        t = rpb*np.sqrt(df/((1.0-rpb+TINY)*(1.0+rpb+TINY)))
        p_hypo = stats.betai(0.5*df, 0.5, df/(df+t*t))
        
        error['PEARSON'].append(abs(pvalue_comp - p_hypo))
        print(row['TestType'], row['DatasetSize'], pvalue_comp, p_hypo)
        
    elif row['TestType'] == 'CHI2':
        data = pd.read_csv('benchmark_chisq_' + str(row['DatasetSize']) + '_' + str(row['NumberOfCategories']) + '.csv.', names=range(row['NumberOfCategories']))
        histoA = []
        #print(len(data.columns), row['NumberOfCategories'])
        for i in range(len(data.columns)):
            histoA.append(data[i].sum())
        
        s = np.array(histoA).sum()
        histoB = [s / len(histoA) for x in histoA]
        stat_comp, pvalue_comp = stats.chisquare(histoA, f_exp=histoB)
        
        p_hypo = 1 - stats.chi2.cdf(stat_hypo, df=len(histoA) - 1)
        error['CHI2'].append(abs(pvalue_comp - pvalue_comp))
        print(row['TestType'], row['DatasetSize'], pvalue_comp, p_hypo)
        
        #        print (i)
        #stat_comp, pvalue_comp = stats.pearsonr(data['A'], data['B'])
        #print(row['TestType'], row['DatasetSize'], stat_comp, stat_hypo)

print()
all = []
for t in error:
    all = all + error[t]
    print(t, np.array(error[t]).mean())
print("ALL", np.array(all).mean(), np.array(all).std())
    
    
    
    