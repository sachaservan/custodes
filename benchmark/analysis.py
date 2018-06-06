from enum import Enum
class TestType(Enum):
    T_TEST = 1
    PEARSON = 2
    CHI2 = 3
    NONE = 4


with open('../log.txt') as f:
    content = f.readlines()

content = [x.strip() for x in content] 


current_test_type = TestType.NONE

for i, line in enumerate(content):
    if line == 'Running T-Test...':
        current_test_type = TestType.T_TEST
    elif line == 'Running Pearson\'s Coorelation Test...':
        current_test_type = TestType.PEARSON  
    elif line == 'Running Chi^2 Test...':
        current_test_type = TestType.CHI2        
    else:
        print(line.split('\t'))
        