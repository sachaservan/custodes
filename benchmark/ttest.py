from scipy import stats
import pandas as pd

df = pd.read_csv('benchmark_1000.csv', names =['A', 'B'])

print(stats.ttest_ind(df['A'], df['B']))

