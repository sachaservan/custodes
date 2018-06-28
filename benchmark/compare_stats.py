from scipy import stats
import pandas as pd

datasets = {1000: pd.read_csv('benchmark_1000.csv', names =['A', 'B']), 
            5000: pd.read_csv('benchmark_5000.csv', names =['A', 'B']),
            10000: pd.read_csv('benchmark_10000.csv', names =['A', 'B'])}

df = pd.read_csv('data.csv')
for index, row in df.iterrows():
    
    if row['TestType'] == 'TTEST':
        stat_hypo = row['PValue']
        data = datasets[row['DatasetSize']]
        stat_comp, pvalue_comp = stats.ttest_ind(data['A'], data['B'])
        
        diff = abs(stat_comp - stat_hypo)
        print(row['TestType'], row['DatasetSize'], stat_comp, stat_hypo)

    elif row['TestType'] == 'PEARSON':
        stat_hypo = row['PValue']
        data = datasets[row['DatasetSize']]
        stat_comp, pvalue_comp = stats.pearsonr(data['A'], data['B'])
        
        print(row['TestType'], row['DatasetSize'], stat_comp, stat_hypo)
