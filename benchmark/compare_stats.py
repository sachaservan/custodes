from scipy import stats
import pandas as pd
import numpy as np

datasets = {1000: pd.read_csv('benchmark_1000.csv', names =['A', 'B']), 
            5000: pd.read_csv('benchmark_5000.csv', names =['A', 'B']),
            10000: pd.read_csv('benchmark_10000.csv', names =['A', 'B'])}

df = pd.read_csv('data.csv')
for index, row in df.iterrows():
    
    stat_hypo = row['PValue']
    data = datasets[row['DatasetSize']]
    if row['TestType'] == 'TTEST':
        stat_comp, pvalue_comp = stats.ttest_ind(data['A'], data['B'])
        print(row['TestType'], row['DatasetSize'], stat_comp, stat_hypo)

    elif row['TestType'] == 'PEARSON':
        stat_comp, pvalue_comp = stats.pearsonr(data['A'], data['B'])
        print(row['TestType'], row['DatasetSize'], stat_comp, stat_hypo)
        
    elif row['TestType'] == 'CHI2':
        data = pd.read_csv('benchmark_chisq_' + str(row['DatasetSize']) + '_' + str(row['NumberOfCategories']) + '.csv.', names=range(row['NumberOfCategories']))
        histoA = []
        #print(len(data.columns), row['NumberOfCategories'])
        for i in range(len(data.columns)):
            histoA.append(data[i].sum())
        
        s = np.array(histoA).sum()
        histoB = [s / len(histoA) for x in histoA]
        stat_comp, pvalue_comp = stats.chisquare(histoA, f_exp=histoB)
        print(row['TestType'], row['DatasetSize'], stat_comp, stat_hypo)
        
        #        print (i)
        #stat_comp, pvalue_comp = stats.pearsonr(data['A'], data['B'])
        #print(row['TestType'], row['DatasetSize'], stat_comp, stat_hypo)
