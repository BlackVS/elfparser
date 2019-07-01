#!/usr/bin/env python
import sys, os, os.path
from binstruct import *
from elf_exceptions import *

class BIN_header(BinStruct):
    __DEFINE_STRUCT__ = """
        uint8 BIN_MAG;
        uint8 BIN_segments;   
        uint8 SPI_flash_interface;    
        uint8 CPU_type; 
        uint32 entry;   
    """
assert(len(BIN_header)==8)

if __name__ == '__main__':
    if len(sys.argv)==3:
        fin     = sys.argv[1]
        dirout  = sys.argv[2]
        print('Processing file:', fin)
        data=[]
        with open(fin, 'rb') as f:
            f.seek(int(foffset,16))
            data=f.read(int(fsize,16))
        with open(fout, 'wb+') as f:
	        f.write(data)
        print("done...")
    else:
        print("Incorrect params. Usage:")
        print("extract_segments fin dir_out")
