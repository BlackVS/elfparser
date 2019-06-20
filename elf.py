#!/usr/bin/env python
from elf_exceptions import *
from elf_structs import *
import inspect

def log(msg,o):
    #frame = inspect.currentframe()
    #args, _, _, values = inspect.getargvalues(frame)
    #print( "%s:%s" % (args[0], values[args[0]]) )
    print(">=======================")
    print("{} :".format(msg))
    for field in o.__fields__:
        print("{}={}".format(field, str(getattr(o, field, None))))
    print("<=======================\n")


class ELF(object):
    """description of class"""
    def __init__(self, stream):
        self.stream = stream
        self._identify_file()
        if self.elfclass != 32:
            raise ELFError('Only 32bit supported for now! ELF_CLASS %s' % repr(self.elfclass))
        self.header = ELF32_Ehdr();
        data = self.stream.read( len(self.header) )
        self.header.unpack(data)
        log("Header",self.header)


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
                self.little_endian = True
                ELF_byte_order=cstruct.LITTLE_ENDIAN
            elif ei_data == b'\x02':
                self.little_endian = False
                ELF_byte_order=cstruct.BIG_ENDIAN
            else:
                raise ELFError('Invalid EI_DATA %s' % repr(ei_data))
        finally:
            self.stream.seek(pos)
