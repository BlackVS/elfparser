#!/usr/bin/env python
from elf_exceptions import *
from elf_structs import *
import inspect
import os, os.path
import copy
import struct

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


class ELF(object):
    """description of class"""
    def __init__(self, stream, dest_dir=None):
        self.header = None
        self.program_headers = []
        self.sections = []

        self.stream = stream
        self.dest_dir = dest_dir
        self._identify_file()
        if self.elfclass != 32:
            raise ELFError('Only 32bit supported for now! ELF_CLASS %s' % repr(self.elfclass))
        self.dump_header()

    def _identify_file(self):
        """ Verify the ELF file and identify its class and endianness.
        """
        # Note: this code reads the stream directly, without using ELFStructs,
        # since we don't yet know its exact format. ELF was designed to be
        # read like this - its e_ident field is word-size and endian agnostic.
        pos = self.stream.tell()
        try:
            self.stream.seek(0)
            magic = self.stream.read(4)
            elf_assert(magic == b'\x7fELF', 'Magic number does not match')

            ei_class = self.stream.read(1)
            if ei_class == b'\x01':
                self.elfclass = 32
            elif ei_class == b'\x02':
                self.elfclass = 64
            else:
                raise ELFError('Invalid EI_CLASS %s' % repr(ei_class))

            ei_data = self.stream.read(1)
            if ei_data == b'\x01':
                self.is_little_endian = True
            elif ei_data == b'\x02':
                self.is_little_endian = False
            else:
                raise ELFError('Invalid EI_DATA %s' % repr(ei_data))
        finally:
            self.stream.seek(pos)

    def dump_header(self):
        self.header = ELF32_Ehdr(self.is_little_endian, self.stream);
        if self.dest_dir!=None:
            self.header.dump("elf_header", self.dest_dir)
        log("ELF Header",self.header)

    def dump_program_headers(self):
        if self.header==None or self.stream == None:
            raise ELFError("{}: No header or input stream!".format(__name__) )

        f=None
        try:
            self.stream.seek( self.header.e_phoff )
            fn_pheaders=os.path.join( self.dest_dir, "segments_info.txt")
            f=open(fn_pheaders, "wt+")

            f.write("{:8}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}\n".format("idx", "p_type", "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_flags", "p_align" ))
            for i in range( self.header.e_phnum ):
                phdr=ELF32_ProgramHeader(self.is_little_endian)
                if len(phdr)!=self.header.e_phentsize:
                    raise ELFError("{}: Failed to parse programs headers!".format(__name__) )
                phdr.read_and_parse(self.stream)
                phdr.dump("segment_{:02}_hdr".format(i), self.dest_dir)
                f.write("{:4}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}\n".format(
                         i, phdr.p_type, phdr.p_offset, phdr.p_vaddr, phdr.p_paddr, phdr.p_filesz, phdr.p_memsz, phdr.p_flags, phdr.p_align 
                         )
                        )
                self.program_headers.append( phdr )
            for i,phdr in enumerate(self.program_headers):
                fname=os.path.join( self.dest_dir, "segment_{:02}.bin".format(i))
                with open(fname,"wb+") as fb:
                    self.stream.seek(phdr.p_offset)
                    data=self.stream.read(phdr.p_filesz)
                    fb.write(data)

        except Exception as e:
            raise e
        finally:
            if f:
                f.close()

    def dump_section_headers(self):
        if self.header==None or self.stream == None:
            raise ELFError("{}: No header or input stream!".format(__name__) )

        f=None
        f2=None
        try:
            self.stream.seek( self.header.e_shoff )
            f=open(os.path.join( self.dest_dir, "sections_info.txt"), "wt+")
            f.write( "{:8}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}\n".format("idx", "sh_name", "sh_type", "sh_flags", "sh_addr", "sh_offset", "sh_size", "sh_link", "sh_info", "sh_addralign", "sh_entsize" ))
            for i in range( self.header.e_shnum ):
                shdr=ELF32_SectionHeader(self.is_little_endian)
                if len(shdr)!=self.header.e_shentsize:
                    raise ELFError("{}: Failed to parse sections headers!".format(__name__) )
                shdr.read_and_parse(self.stream)
                shdr.dump("section_{:02}_hdr".format(i), self.dest_dir)
                f.write("{:4}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}\n".format(
                         i, shdr.sh_name, shdr.sh_type, shdr.sh_flags, shdr.sh_addr, shdr.sh_offset, shdr.sh_size, shdr.sh_link, shdr.sh_info, shdr.sh_addralign, shdr.sh_entsize 
                         )
                        )
                self.sections.append( shdr )
                
            #get sections names first
            raw_names=None
            if self.header.e_shstrndx!=0: #section with sections names is present
                shdr=self.sections[self.header.e_shstrndx]
                self.stream.seek(shdr.sh_offset)
                raw_names=self.stream.read(shdr.sh_size)

            ##
            f2=open(os.path.join( self.dest_dir, "sections_info2.txt"), "wt+")
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
                if sz==0:
                    continue
                fname=os.path.join( self.dest_dir, "section_{:02}.bin".format(i))
                with open(fname,"wb+") as fb:
                    self.stream.seek(shdr.sh_offset)
                    data=self.stream.read(sz)
                    fb.write(data)

        except Exception as e:
            raise e
        finally:
            if f: f.close()
            if f2: f2.close()

