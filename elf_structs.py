#!/usr/bin/env python
from binstruct import *
from elf_exceptions import *

class ELF_e_ident(BinStruct):
    __DEFINE_STRUCT__ = """
        uint8 EI_MAG[4];
        uint8 EI_CLASS;   
        uint8 EI_DATA;    
        uint8 EI_VERSION; 
        uint8 EI_OSABI;   
        uint8 EI_ABIVERSION;
        uint8 _padding[7];
    """
assert(len(ELF_e_ident)==16)

## size = 52 for 32-bit
#
class ELF32_Ehdr(BinStruct):
    __DEFINE_STRUCT__ = """
        ELF_e_ident    	e_ident;
        uint16		e_type;
        uint16		e_machine;
        uint32		e_version;
        uint32		e_entry;
        uint32		e_phoff;
        uint32		e_shoff;
        uint32		e_flags;
        uint16		e_ehsize;
        uint16		e_phentsize;
        uint16		e_phnum;
        uint16		e_shentsize;
        uint16		e_shnum;
        uint16		e_shstrndx;
    """
assert(len(ELF32_Ehdr)==52)
