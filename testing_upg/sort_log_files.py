import json
import  datetime
from datetime import  datetime
import pprint
import ast
from operator import itemgetter
from dateutil import parser


def parse_date(datestr):
    return datetime.strptime(datestr[:-3], "%Y-%m-%d %H:%M:%S.%f")
    #return parser.parse(datestr)


with open('data1.json', 'r') as file:
    datastr = file.read()
#print(type(datastr))
#print(datastr)
D2=eval(datastr)
#print(D2)
D3=ast.literal_eval(datastr)

newlist = dict()
#for j in D3:
    #print(j)
    #print(j.get("pid"))
#    print(parse_date(j.get("Date")))

#newlist = sorted(D3, parse_date(key=itemgetter("Date"))) 
print("------Sorting the logs-----")
try:
    newlist = sorted(D3, key=lambda k: parse_date(k["Date"])) 
except TypeError:
    print(D3.get("lms"))
    pass
pprint.pprint(newlist)
with open('universal_log.json', 'a') as f:
    f.truncate()
    json.dump(newlist, f, indent=2)  
print("------Sorting Completed and dumped to file-----")
#print(D3)
#print(type(D3))




"""
datalist = []
datalist.append(D3)
#print(datalist)
logdict = dict()
logdict["logs"] = (datalist)
pprint.pprint(logdict["logs"])

for i in logdict.get("logs"):
    for j in i:
        print(j.get("Date"))


with open('data1.json') as json_file:
    data = json.load(json_file)
    print(type(data))
    pprint.pprint(data)
    #mydicts = map(json.loads, filter(str.strip, f))
    # This sorts on date value, but leaves them as original str
    # in dict, can convert ahead of time if you want, or not, as you please
    sorteddicts = sorted(data, key=lambda d: parse_date(d["Date"]))
    #print(sorteddicts)
    
    

with open('data1.json') as json_file:
    data = json.load(json_file)
    print(type(data))
    pprint.pprint(data)
    #mydicts = map(json.loads, filter(str.strip, f))
    # This sorts on date value, but leaves them as original str
    # in dict, can convert ahead of time if you want, or not, as you please
    sorteddicts = sorted(data, key=lambda d: parse_date(d["Date"]))
    #print(sorteddicts)

    
"""