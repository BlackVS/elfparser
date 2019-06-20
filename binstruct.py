#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import struct
import sys

__all__ = ['BinStruct',
          ]

BIN_BYTEORDER_LE = 1
BIG_BYTEORDER_BE = 2

__byte_order__ = BIN_BYTEORDER_LE

BIN_ARRAYS = {
    'bytes' : ('c','bytes', 1),
    }

BIN_TYPE_TO_FORMAT = {
    # "alias" : ( pack flag, python type, size )
    'pad'   : ('x', None,  1),
    'bool'  : ('?', bool,  1),
    'char'  : ('b', str,   1),
    'byte'  : ('B', int,   1),
    'int8'  : ('b', int,   1),
    'uint8' : ('B', int,   1),
    'int16' : ('h', int,   2),
    'uint16': ('H', int,   2),
    'int32' : ('i', int,   4),
    'uint32': ('I', int,   4),
    'int64' : ('q', int,   8),
    'uint64': ('Q', int,   8),
}

class BinStructMeta(type):
    def __new__(mcs, name, bases, dict):
        __struct__ = dict.get("__struct__", None)
        if __struct__ is not None:
            dict['__fmt__'], dict['__fields__'], dict['__fields_types__'] = mcs.parse_struct(__struct__)
            if '__byte_order__' in dict:
                dict['__fmt__'] = dict['__byte_order__'] + dict['__fmt__']
            # Add the missing fields to the class
            for field in dict['__fields__']:
                if field not in dict:
                    dict[field] = None
            # Calculate the structure size
            dict['__size__'] = struct.calcsize(dict['__fmt__'])
        new_class = type.__new__(mcs, name, bases, dict)
        if __struct__ is not None:
            STRUCTS[name] = new_class
        return new_class

    @staticmethod
    def parse_struct(st):
        # naive C struct parsing
        fmt = []
        fields = []
        fields_types = {}
        # remove the comments
        st = st.replace("*/","*/\n")
        st = "  ".join(re.split("/\*.*\*/",st))
        st = "\n".join([s.split("//")[0] for s in st.split("\n")])
        st = st.replace("\n", " ")
        for line_s in st.split(";"):
            line_s = line_s.strip()
            if line_s:
                line = line_s.split()
                if len(line) < 2:
                    raise Exception("Error parsing: " + line_s)
                vtype = line[0].strip()
                # signed/unsigned/struct
                if vtype == 'unsigned' or vtype == 'signed' or vtype == 'struct' and len(line) > 2:
                    vtype = vtype + " " + line[1].strip()
                    del line[0]
                vname = line[1]
                # short int, long int, or long long
                if vname == 'int' or vname == 'long':
                    vtype = vtype + " " + vname
                    del line[0]
                    vname = line[1]
                # void *
                if vname.startswith("*"):
                    vname = vname[1:]
                    vtype = 'void *'
                # parse length
                vlen = 1
                if "[" in vname:
                    t = vname.split("[")
                    if len(t) != 2:
                        raise Exception("Error parsing: " + line_s)
                    vname = t[0].strip()
                    vlen = t[1]
                    vlen = vlen.split("]")[0].strip()
                    try:
                        vlen = int(vlen)
                    except:
                        vlen = DEFINES.get(vlen, None)
                        if vlen is None:
                            raise
                        else:
                            vlen = int(vlen)
                while vtype in TYPEDEFS:
                    vtype = TYPEDEFS[vtype]
                if vtype.startswith('struct '):
                    vtype = vtype[7:]
                    t = STRUCTS.get(vtype, None)
                    if t is None:
                        raise Exception("Unknow struct \"" + vtype + "\"")
                    vtype = t
                    ttype = "c"
                    vlen = vtype.size * vlen
                else:
                    ttype = C_TYPE_TO_FORMAT.get(vtype, None)
                    if ttype is None:
                        raise Exception("Unknow type \"" + vtype + "\"")
                fields.append(vname)
                fields_types[vname] = (vtype, vlen)
                if vlen > 1:
                    fmt.append(str(vlen))
                fmt.append(ttype)
        fmt = "".join(fmt)
        return fmt, fields, fields_types

    def __len__(cls):
        return cls.__size__

    @property
    def size(cls):
        """ Structure size (in bytes) """
        return cls.__size__

_BinStructParent = BinStructMeta('_BinStructParent', (object, ), {})

#class BinStruct(metaclass = BinStructMeta):
class BinStruct(_BinStructParent):
    def __init__(self, string=None, **kargs):
        if string is not None:
            self.unpack(string)
        else:
            try:
                self.unpack(string)
            except:
                pass
        for key, value in kargs.items():
            setattr(self, key, value)

    def unpack(self, string):
        """
        Unpack the string containing packed C structure data
        """
        if string is None:
            string = CHAR_ZERO * self.__size__
        data = struct.unpack(self.__fmt__, string)
        i = 0
        for field in self.__fields__:
            (vtype, vlen) = self.__fields_types__[field]
            if vtype == 'char': # string
                setattr(self, field, data[i])
                i = i + 1
            elif isinstance(vtype, CStructMeta):
                num = int(vlen / vtype.size)
                if num == 1: # single struct
                    sub_struct = vtype()
                    sub_struct.unpack(EMPTY_BYTES_STRING.join(data[i:i+sub_struct.size]))
                    setattr(self, field, sub_struct)
                    i = i + sub_struct.size
                else: # multiple struct
                    sub_structs = []
                    for j in range(0, num):
                        sub_struct = vtype()
                        sub_struct.unpack(EMPTY_BYTES_STRING.join(data[i:i+sub_struct.size]))
                        i = i + sub_struct.size
                        sub_structs.append(sub_struct)
                    setattr(self, field, sub_structs)
            elif vlen == 1:
                setattr(self, field, data[i])
                i = i + vlen
            else:
                setattr(self, field, list(data[i:i+vlen]))
                i = i + vlen

    def pack(self):
        """
        Pack the structure data into a string
        """
        data = []
        for field in self.__fields__:
            (vtype, vlen) = self.__fields_types__[field]
            if vtype == 'char': # string
                data.append(getattr(self, field))
            elif isinstance(vtype, CStructMeta):
                num = int(vlen / vtype.size)
                if num == 1: # single struct
                    v = getattr(self, field, vtype())
                    v = v.pack()
                    if sys.version_info >= (3, 0):
                        v = ([bytes([x]) for x in v])
                    data.extend(v)
                else: # multiple struct
                    values = getattr(self, field, [])
                    for j in range(0, num):
                        try:
                            v = values[j]
                        except:
                            v = vtype()
                        v = v.pack()
                        if sys.version_info >= (3, 0):
                            v = ([bytes([x]) for x in v])
                        data.extend(v)
            elif vlen == 1:
                data.append(getattr(self, field))
            else:
                v = getattr(self, field)
                v = v[:vlen] + [0] * (vlen - len(v))
                data.extend(v)
        return struct.pack(self.__fmt__, *data)

    def clear(self):
        self.unpack(None)

    def __len__(self):
        """ Structure size (in bytes) """
        return self.__size__

    @property
    def size(self):
        """ Structure size (in bytes) """
        return self.__size__

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and self.__dict__ == other.__dict__)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        result = []
        for field in self.__fields__:
            result.append(field + "=" + str(getattr(self, field, None)))
        return type(self).__name__ + "(" + ", ".join(result) + ")"

    def __repr__(self):
        return self.__str__()

