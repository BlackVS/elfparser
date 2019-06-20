#!/usr/bin/env python
import sys, os
from elf import *
# sys.path[0:0] = ['.', '..']



def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile=ELF(f)
    print("done...")

if __name__ == '__main__':
    if len(sys.argv)>1:
        filename = sys.argv[1]
#        process_file0(filename)
        process_file(filename)
