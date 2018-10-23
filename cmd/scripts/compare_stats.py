from scipy import stats
from scipy.stats import distributions
import pandas as pd
import numpy as np
import scipy.special as special

datasets = {4177: pd.read_csv('../datasets/abalone_height_vs_weight.csv', names =['A', 'B']),
            108: pd.read_csv('../datasets/pittsburgh_bridges_categorical.csv', names =['A', 'B', 'C', 'D']),
            1000: pd.read_csv('../datasets/benchmark_1000.csv', names =['A', 'B']), 
            5000: pd.read_csv('../datasets/benchmark_5000.csv', names =['A', 'B']),
            10000: pd.read_csv('../datasets/benchmark_10000.csv', names =['A', 'B'])}

df = pd.read_csv('data.csv')
sums = {'TotalRuntime': [], 'SetupTime' : [], 'AuditRuntime': [], 'AbsoluteError' : {'T-Test': [], 'Pearson': [], 'Chi-Squared': []}}

def _betai(a, b, x):
    x = np.asarray(x)
    x = np.where(x < 1.0, x, 1.0)  # if x > 1 then return 1.0
    return special.betainc(a, b, x)

for index, row in df.iterrows():
    for k in sums:
        if k != 'AbsoluteError':
            sums[k].append(row[k])
    
    stat_hypocert = row['Value']
    data = datasets[row['NumRows']]
    if row['Test'] == 'T-Test':
        stat_comp, pvalue_comp = stats.ttest_ind(data['A'], data['B'])

        df = len(data['A']) + len(data['B']) - 2.0
        n1 = len(data['A'])
        v1 = data['A'].mean() 
        n2 = len(data['B'])
        v2 = data['B'].mean() 
        vn1 = v1 / n1
        vn2 = v2 / n2
        df = (vn1 + vn2)**2 / (vn1**2 / (n1 - 1) + vn2**2 / (n2 - 1))
        df = n1 + n2 - 2.0

        p_value_hypo = distributions.t.sf(np.abs(stat_hypocert), df) * 2

        sums['AbsoluteError'][row['Test']].append(abs(pvalue_comp - p_value_hypo))
        print(row['Test'], row['NumRows'], abs(pvalue_comp), p_value_hypo)

    elif row['Test'] == 'Pearson':
        stat_comp, pvalue_comp = stats.pearsonr(data['A'], data['B'])
        df = len(data['A']) - 2.0
        t_squared = stat_hypocert**2 * (df / ((1.0 - stat_hypocert) * (1.0 + stat_hypocert)))
        p_value_hypo = _betai(0.5*df, 0.5, df/(df+t_squared))

        sums['AbsoluteError'][row['Test']].append(abs(pvalue_comp - p_value_hypo))
        print(row['Test'], row['NumRows'], abs(pvalue_comp), p_value_hypo)
        
    elif row['Test'] == 'Chi-Squared':
        if row['NumRows'] != 108:
            data = pd.read_csv('../datasets/benchmark_chisq_' + str(row['NumRows']) + '_' + str(row['NumCols']) + '.csv', names=range(row['NumCols']))
        else:
            data = pd.read_csv('../datasets/pittsburgh_bridges_categorical.csv', names=range(row['NumCols']))
        histoA = []
        #print(len(data.columns), row['NumCols'])
        for i in range(len(data.columns)):
            histoA.append(data[i].sum())
        
        s = np.array(histoA).sum()
        histoB = [s / len(histoA) for x in histoA]
        stat_comp, pvalue_comp = stats.chisquare(histoA, f_exp=histoB)

        p_value_hypo = distributions.chi2.sf(stat_hypocert, row['NumCols'] - 1 - 0)

        sums['AbsoluteError'][row['Test']].append(abs(pvalue_comp - p_value_hypo))
        print(row['Test'], row['NumRows'], abs(pvalue_comp), p_value_hypo)
        
        #        print (i)
        #stat_comp, pvalue_comp = stats.pearsonr(data['A'], data['B'])
        #print(row['Test'], row['NumRows'], stat_comp, stat_hypocert)

print()
for k in sums:
    if k != 'AbsoluteError':
        print(k, ': mean =', np.mean(sums[k]), 'std =', np.std(sums[k]))
    else:
        for j in sums[k]:
            print(k, j, ': mean =', np.mean(sums[k][j]), 'std =', np.std(sums[k][j]))