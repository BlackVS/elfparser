#!/usr/bin/env python
from elf_exceptions import *
from elf_structs import *
import inspect
import os, os.path
import copy

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

    def dump_header(self, idx=0):
        self.header = ELF32_Ehdr(self.is_little_endian, self.stream);
        if self.dest_dir!=None:
            self.header.dump("{:04}_header".format(idx), self.dest_dir)
        log("Header",self.header)
        return idx+1

    def dump_program_headers(self, idx=1):
        if self.header==None or self.stream == None:
            raise ELFError("{}: No header or input stream!".format(__name__) )

        f=None
        try:
            self.stream.seek( self.header.e_phoff )
            fn_pheaders=os.path.join( self.dest_dir, "info_pheaders.txt")
            f=open(fn_pheaders, "wt+")

            f.write("{:8}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}\n".format("idx", "p_type", "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_flags", "p_align" ))
            for i in range( self.header.e_phnum ):
                self.program_headers.append( ELF32_PHeader(self.is_little_endian) )
                phdr = self.program_headers[-1]
                if len(phdr)!=self.header.e_phentsize:
                    raise ELFError("{}: Failed to parse prgram header!".format(__name__) )
                phdr.read_and_parse(self.stream)
                phdr.dump("{:04}_pheader_{}".format(idx,i), self.dest_dir)
                f.write("{:04x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}\n".format(idx, phdr.p_type, phdr.p_offset, phdr.p_vaddr, phdr.p_paddr, phdr.p_filesz, phdr.p_memsz, phdr.p_flags, phdr.p_align ))
                idx+=1
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
        return idx