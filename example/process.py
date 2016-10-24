#! /usr/bin/env
import re
import os.path
import sys

'''
  This python script will clean the symbol table 
  - Qiang Guan, LANL
'''
# Start
if len(sys.argv)<3:
  print "Usage: ./process.py binary_file symbol_table"
  sys.exit() 

in_file = sys.argv[1] # Input file is a binary
out_file = sys.argv[2] # Output file will be a symbol table
tmp_file = "all_symbols"
cmd_str = "readelf --syms ./"+in_file+" >> "+tmp_file

if os.system(cmd_str)!=0:
  print "Failed in generating symbol table!"
  sys.exit()

if os.path.isfile(tmp_file)!=True:
  print "Symbol table file %s not exist!" %in_file
  sys.exit()

inputfile = open(tmp_file, "r");
outputfile = open(out_file, "w")

for line in inputfile:
  if re.match("(.*)FUNC(.*)", line): # Keep only FUNC
    if re.match("(.*) 0 FUNC(.*)", line)==None: # Clean empty FUNC
      outputfile.write(line)

inputfile.close()
outputfile.close()


