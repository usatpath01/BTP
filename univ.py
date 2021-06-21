import os
import sys
import gzip
import shutil
import subprocess

##Give input file name as the first argument

def run_fast_scandir(dir,files):
	for f in os.scandir(dir):
		if f.is_dir():
			run_fast_scandir(f.path,files)
		if f.is_file():
			files.append(f.path)

##Remember to change it to the /var/log/
path_file = "/var/log"+"/"
output_file_name = "universal_log_file.txt"
input_file_name = sys.argv[1]

subfolders = [f.name for f in os.scandir(path_file)
if f.is_dir()]


##Taking names of applications from input.txt
req_app = []
with open(input_file_name,"r") as fp:
	lines = fp.readlines()
	for line in lines:
		req_app.append(line.rstrip("\n"))

##finding all files inside the subdirectories
files = []
for x in subfolders:
	if x in req_app:
		run_fast_scandir(path_file+x,files)

##handle .gzip file and merging all files
with open(output_file_name,"wb") as outfile:
	for file in files:
		if ".gz" in file.split("/")[-1]:
			with gzip.open(file,'rb') as f_in:
				shutil.copyfileobj(f_in,outfile)

		elif "log" in file.split("/")[-1]:
			with open(file,'rb') as infile:
				shutil.copyfileobj(infile,outfile)


## Ran command to sort the file from the bash
cp = subprocess.run(["sort -k 6 universal_log_file.txt -o universal_log_file.txt"], check=True,shell=True)