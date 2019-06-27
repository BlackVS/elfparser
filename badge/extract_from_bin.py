#!/usr/bin/env python
import sys, os, os.path


if __name__ == '__main__':
    if len(sys.argv)==5:
        fin     = sys.argv[1]
        foffset = sys.argv[2]
        fsize   = sys.argv[3]
        fout    = sys.argv[4]
#        process_file0(filename)
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
        print("extract_from_bin fin offset size fout")
