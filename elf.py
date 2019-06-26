#!/usr/bin/env python
from elf_exceptions import *
from elf_structs import *
from collections import defaultdict
import inspect
import os, os.path
import copy
import struct

ELF_FNAME_STRUCTURE = "elf_structure.txt"
ELF_FNAME_HEADER = "elf_header"

def get_cstring(buffer,offset):
    res=""
    pos=offset
    while pos<len(buffer) and buffer[pos]!=0:
        res+=chr(buffer[pos])
        pos+=1
    return res

def hex_or_none(v):
    return (hex(v),"-")[v==0]

def log(msg,o):
    #frame = inspect.currentframe()
    #args, _, _, values = inspect.getargvalues(frame)
    #print( "%s:%s" % (args[0], values[args[0]]) )
    print(">=======================")
    print("{} :".format(msg))
    print(o)
    print("<=======================\n")


class ELFParser(object):
    """description of class"""
    def __init__(self, stream, dest_dir=None, store_in_structure = False ):
        self.header = None
        self.program_headers = []
        self.sections = []
        self.structure = []

        self.stream = stream
        self.dest_dir = dest_dir
        self._identify_file()
        if self.elfclass != 32:
            raise ELFError('Only 32bit supported for now! ELF_CLASS %s' % repr(self.elfclass))
        self.dump_header(store_in_structure)

    @staticmethod
    def get_elf_version(stream):
        pos = stream.tell()
        try:
            stream.seek(0)
            magic = stream.read(4)
            if magic != b'\x7fELF':
                raise ELFError('Invalid magic, not ELF : %s' % repr(magic))

            ei_class = stream.read(1)
            if ei_class == b'\x01':
                elfclass = 32
            elif ei_class == b'\x02':
                elfclass = 64
            else:
                raise ELFError('Invalid EI_CLASS %s' % repr(ei_class))

            ei_data = stream.read(1)
            if ei_data == b'\x01':
                is_little_endian = True
            elif ei_data == b'\x02':
                is_little_endian = False
            else:
                raise ELFError('Invalid EI_DATA %s' % repr(ei_data))
        finally:
            stream.seek(pos)
        return (elfclass, is_little_endian)

    def _identify_file(self):
        self.elfclass, self.is_little_endian = ELFParser.get_elf_version(self.stream)

    def dump_header(self, store_in_structure=False):
        self.header = ELF32_Ehdr(self.is_little_endian, self.stream);
        if self.dest_dir!=None:
            res=self.header.dump(ELF_FNAME_HEADER, self.dest_dir)
            if store_in_structure:
                self.structure.append( res ) #hedaer starts from 0
        #log("ELF Header",self.header)

    def dump_program_headers(self, store_in_structure=False):
        if self.header==None or self.stream == None:
            raise ELFError("{}: No header or input stream!".format(__name__) )

        f=None
        try:
            self.stream.seek( self.header.e_phoff )
            fn_pheaders=os.path.join( self.dest_dir, "elf_segments_info.txt")
            f=open(fn_pheaders, "wt+")

            f.write("{:8}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}\n".format("idx", "p_type", "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_flags", "p_align" ))
            for i in range( self.header.e_phnum ):
                phdr=ELF32_ProgramHeader(self.is_little_endian)
                if len(phdr)!=self.header.e_phentsize:
                    raise ELFError("{}: Failed to parse programs headers!".format(__name__) )
                phdr.read_and_parse(self.stream)
                phdr_res=phdr.dump("segment_{:02}.hdr".format(i), self.dest_dir)
                f.write("{:4}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}\n".format(
                         i, phdr.p_type, phdr.p_offset, phdr.p_vaddr, phdr.p_paddr, phdr.p_filesz, phdr.p_memsz, phdr.p_flags, phdr.p_align 
                         )
                        )
                self.program_headers.append( phdr )
                if store_in_structure:
                    self.structure.append( phdr_res )
            for i,phdr in enumerate(self.program_headers):
                fname_short="segment_{:02}.bin".format(i)
                fname=os.path.join( self.dest_dir, fname_short)
                with open(fname,"wb+") as fb:
                    self.stream.seek(phdr.p_offset)
                    data=self.stream.read(phdr.p_filesz)
                    fb.write(data)
                if store_in_structure:
                    self.structure.append( (phdr.p_offset, phdr.p_filesz, "raw", "segment_{:02}".format(i)) )

        except Exception as e:
            raise e
        finally:
            if f:
                f.close()

    def dump_section_headers(self, store_in_structure=False):
        if self.header==None or self.stream == None:
            raise ELFError("{}: No header or input stream!".format(__name__) )

        f=None
        f2=None
        try:
            self.stream.seek( self.header.e_shoff )
            f=open(os.path.join( self.dest_dir, "elf_sections_info.txt"), "wt+")
            f.write( "{:8}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}\n".format("idx", "sh_name", "sh_type", "sh_flags", "sh_addr", "sh_offset", "sh_size", "sh_link", "sh_info", "sh_addralign", "sh_entsize" ))
            for i in range( self.header.e_shnum ):
                shdr=ELF32_SectionHeader(self.is_little_endian)
                if len(shdr)!=self.header.e_shentsize:
                    raise ELFError("{}: Failed to parse sections headers!".format(__name__) )
                shdr.read_and_parse(self.stream)
                shdr_res=shdr.dump("section_{:02}.hdr".format(i), self.dest_dir)
                f.write("{:4}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}\n".format(
                         i, shdr.sh_name, shdr.sh_type, shdr.sh_flags, shdr.sh_addr, shdr.sh_offset, shdr.sh_size, shdr.sh_link, shdr.sh_info, shdr.sh_addralign, shdr.sh_entsize 
                         )
                        )
                self.sections.append( shdr )
                if store_in_structure:
                    self.structure.append( shdr_res )
                
            #get sections names first
            raw_names=None
            if self.header.e_shstrndx!=0: #section with sections names is present
                shdr=self.sections[self.header.e_shstrndx]
                self.stream.seek(shdr.sh_offset)
                raw_names=self.stream.read(shdr.sh_size)

            ##
            f2=open(os.path.join( self.dest_dir, "elf_sections_info2.txt"), "wt+")
            f2_fmt_title = "{:4} {:8}  {:8}   {:10}   {:12}\n\n"
            f2_fmt       = "{:4} {:08x}   {:10}   {:10}   {:12}\n"
            f2.write(f2_fmt_title.format("#", "sh_offset", "sh_size", "v_addr", "name"))
            for i,shdr in enumerate(self.sections):
                section_name=shdr.sh_name
                if shdr.sh_name!=0:
                    section_name=get_cstring(raw_names, shdr.sh_name)
                f2.write(f2_fmt.format(i, shdr.sh_offset, hex_or_none(shdr.sh_size), hex_or_none(shdr.sh_addr), section_name))
                #####
                sz=shdr.sh_size
                if store_in_structure:
                    self.structure.append( (shdr.sh_offset,sz, "raw", "section_{:02}".format(i)) )
                if sz>0:
                    fname_short="section_{:02}.bin".format(i)
                    fname=os.path.join( self.dest_dir, fname_short)
                    with open(fname,"wb+") as fb:
                        self.stream.seek(shdr.sh_offset)
                        data=self.stream.read(sz)
                        fb.write(data)

        except Exception as e:
            raise e
        finally:
            if f: f.close()
            if f2: f2.close()

    def write_structure(self):
        #self.structure.sort()
        res=defaultdict(list)
        for s in self.structure:
            res[(s[0],s[1],s[2])].append( s[3] )
        with open(os.path.join( self.dest_dir, ELF_FNAME_STRUCTURE), "wt+") as f:
            for (r0,r1,r2),r3 in sorted(res.items()):
                f.write("{:08x} {:08x} {:25} {}\n".format(r0,r1,r2," ".join(r3)))



class ELFAssembler(object):
    def __init__(self, src_dir, output_file ):
        self.header = None
        self.program_headers = dict()
        self.sections = dict()
        self.structure = []
        self.stream = open(output_file,"wb+")
        self.src_dir = src_dir
        #first read structure 
        self.read_header()
        self.read_structure()
        self.analyze_segments()

    def read_header(self):
        fheader=os.path.join( self.src_dir, ELF_FNAME_HEADER+".bin")
        with open(fheader, "rb") as f:
            self.elfclass, self.is_little_endian = ELFParser.get_elf_version(f)
            if self.elfclass!=32:
                raise ELFError('Only 32bit supported for now! ELF_CLASS %s' % repr(self.elfclass))
            self.header=ELF32_Ehdr(self.is_little_endian, f)

    def read_structure(self):
        with open(os.path.join( self.src_dir, ELF_FNAME_STRUCTURE), "rt") as f:
            for s in f:
                spos, ssize, stype, *sfiles = s.split()
                ipos  = int(spos ,16)
                isize = int(ssize,16)
                #print("{:08x} {:08x} {:25} {}".format(ipos, isize, stype, sfiles))
                self.structure.append( (ipos, isize, stype, sfiles) )


    #walk through program headers in structer, load from raw and update loaded program headers/table
    def analyze_segments(self):
        #load raw
        sizes=dict()
        for p in filter(lambda s: s[2]=="ELF32_ProgramHeader", self.structure):
            #print(p)
            fname=p[3][0]
            fseg =fname.split(".")[0]
            seg_idx=int(fseg.split("_")[1],16)

            with open(os.path.join(self.src_dir, fname), "rb") as f:
                phdr=ELF32_ProgramHeader(self.is_little_endian, f)
                self.program_headers[seg_idx]=phdr

            sizes[seg_idx]=os.path.getsize( os.path.join( self.src_dir, fseg+".bin" ) )

        ##load map file
        with open(os.path.join( self.src_dir, "elf_segments_info.txt"), "rt") as fmap:
            titles = fmap.readline().split()
            #print(titles)
            for t in fmap:
                values=t.split()
                idx=int(values[0])
                for i in range(1,len(values)):
                    phdr[ titles[i] ] = values[i]
                #check filesizes:
                if ( phdr.p_filesz != sizes[idx]):
                    raise ELFError("Filesize for segment () in map not equal to real file size: {}!={}".format(idx, phdr.p_filesz, sizes[idx]))

