#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import struct
import sys

__all__ = ['BinStruct',
          ]

# type: fmt
BIN_TYPE_IDX_FMT   = 0
BIN_TYPE_IDX_PYTHON_TYPE = 1
BIN_TYPES = {
    # "alias" : ( pack flag, python type, size )
    'pad'   : ('x', int),
    'bool'  : ('?', bool),
    'char'  : ('b', str ),
    'byte'  : ('B', int ),
    'int8'  : ('b', int ),
    'uint8' : ('B', int ),
    'int16' : ('h', int ),
    'uint16': ('H', int ),
    'int32' : ('i', int ),
    'uint32': ('I', int ),
    'int64' : ('q', int ),
    'uint64': ('Q', int ),
}


class BinStructMeta(type):
    def __new__(cls, name, bases, dct):
        __DEFINE_STRUCT__ = dct.get("__DEFINE_STRUCT__", None)
        __fmt__        = ""
        __data__       = dict()
        __datastruct__ = list()
        if __DEFINE_STRUCT__ is not None: #BinStructMeta and BinStruct has not __struct__ at init time
            #parse
            reConsoleParser = re.compile(r"([\w.]+)\s*([\w.]+)\s*(?:\[(\d+)\])?;")

            try:
                parsed = reConsoleParser.findall(__DEFINE_STRUCT__)
            except Exception as inst:
                raise Exception("Error parsing: " + __DEFINE_STRUCT__)
            pos=0
            for (vtype, vname, varrsize) in parsed:
                if varrsize==None or varrsize=='':
                    varrsize=1
                # if known ordinary type
                t=BIN_TYPES.get(vtype,None)
                varrsize=max(1, int(varrsize))
                if t!=None:
                    fmt = t[BIN_TYPE_IDX_FMT]
                    if varrsize==1:
                        __datastruct__.append( (vname, vtype, fmt, pos) )
                        __data__[vname]=t[BIN_TYPE_IDX_PYTHON_TYPE]()
                    else:
                        if len(fmt)==1:
                            fmt=str(varrsize)+fmt
                        else:
                            fmt=fmt*varrsize
                        __datastruct__.append( (vname, vtype, fmt, pos) )
                        __data__[vname]= [t[BIN_TYPE_IDX_PYTHON_TYPE]()]*varrsize
                    __fmt__  += fmt
                    pos+=struct.calcsize(fmt)
                    continue
            dct['__packedsize__'] = struct.calcsize(__fmt__)
            dct['__fmt__']        = __fmt__
            dct['__data__']       = __data__
            dct['__datastruct__'] = __datastruct__
        new_cls = super().__new__(cls, name, bases, dct)
        if __fmt__:
            BIN_TYPES[name]=(__fmt__,new_cls)
        return new_cls

    def __len__(cls):
        """ Structure size (in bytes) """
        return cls.__packedsize__

    @property
    def size(cls):
        """ Structure size (in bytes) """
        return cls.__packedsize__

#_BinStructParent = BinStructMeta('_BinStructParent', (object, ), {})

class BinStruct(metaclass = BinStructMeta):
#class BinStruct(_BinStructParent):
    def __init__(self, stream=None, buffer=None):
        if not stream and not buffer:
            pass

    def unpack(self, buffer, isLE=True):
        if len(buffer)<self.size:
            raise Exception("Error parsing: " + __DEFINE_STRUCT__)
        for (vname, vtype, fmt, pos) in self.__datastruct__:
            if isinstance(self.__data__[vname],BinStruct):
                #recursive unpack
                self.__data__[vname].unpack(buffer[pos:],isLE)
            else:
                data = struct.unpack_from(fmt, buffer, pos)
                if len(data)==1:
                    self.__data__[vname]=type(self.__data__[vname])(data[0])
                else:
                    self.__data__[vname]=type(self.__data__[vname])(data)

    def pack(self, isLE=True):
        return None


    def clear(self):
        self.unpack(None)

    def __len__(self):
        """ Structure size (in bytes) """
        return self.__packedsize__

    @property
    def size(self):
        """ Structure size (in bytes) """
        return self.__packedsize__

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and self.__dict__ == other.__dict__)

    def __ne__(self, other):
        return not self.__eq__(other)

    def format_as_str(self, shift=0):
        prefix=""
        if shift:
            prefix=" "*shift
        result = prefix + "<{}> :\n".format(type(self).__name__)
        for field, value in self.__data__.items():
            if isinstance(value,BinStruct):
                result += prefix + "{} = ".format(field)
                result += prefix + value.format_as_str(shift+4)
            else:
                if isinstance(value, int):
                    value=hex(value)
                if isinstance(value, list) or isinstance(value, tuple):
                    result += prefix + field + " = [ " + ", ".join(map(lambda v: hex(v) if isinstance(v,int) else str(v), value)) + " ]\n"
                else:
                    result += prefix + "{} = {}\n".format(field, value)
        return result 

    def __str__(self, shift=0):
        return  self.format_as_str()

    def __repr__(self):
        return self.__str__()

