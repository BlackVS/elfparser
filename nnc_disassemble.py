#!/usr/bin/env python
import sys

sys.path.append('..')
import esptool, espefuse
from binascii import *

def hexify(bitstring, separator=""):
    try:
        as_bytes = tuple(ord(b) for b in bitstring)
    except TypeError:  # python 3, items in bitstring already ints
        as_bytes = tuple(b for b in bitstring)
    return separator.join(("%02x" % b) for b in as_bytes)


def image_info(chip,filename):
    finfo=open("{}.info".format(filename),"wt+")

    image = esptool.LoadFirmwareImage(chip, filename)
    print('Image version: %d' % image.version)
    print('Entry point: %08x' % image.entrypoint if image.entrypoint != 0 else 'Entry point not set')
    print("secure_pad: {}".format(image.secure_pad))
    print("flash_mode: {}".format(image.flash_mode))
    print("flash_size_freq: {}".format(image.flash_size_freq))
    finfo.write("0x{:x}\n".format(image.entrypoint))
    finfo.write("{}\n".format(len(image.segments)))
    finfo.write("{} {} {} \n".format(image.secure_pad,image.flash_mode,image.flash_size_freq))

    print('%d segments' % len(image.segments))
    print()

    idx = 0
    for seg in image.segments:
        idx += 1
        print('Segment %d: %r' % (idx, seg))
        print("  addr=0x{:x} file_offs=0x{:x} include_in_checksum={}\n".format(seg.addr, seg.file_offs, seg.include_in_checksum))
        fsegname="{}.seg{}".format(filename,idx)
        with open(fsegname, "wb+") as file:
            file.write(seg.data)
        finfo.write("{} {} 0x{:x} 0x{:x} {}\n".format(idx, fsegname, seg.addr, seg.file_offs, seg.include_in_checksum))

            
    calc_checksum = image.calculate_checksum()
    print('Checksum: %02x (%s)' % (image.checksum, 'valid' if image.checksum == calc_checksum else 'invalid - calculated %02x' % calc_checksum))
    try:
        digest_msg = 'Not appended'
        if image.append_digest:
            is_valid = image.stored_digest == image.calc_digest
            digest_msg = "%s (%s)" % (hexify(image.calc_digest).lower(),
                                      "valid" if is_valid else "invalid")
            print('Validation Hash: %s' % digest_msg)
    except AttributeError:
        pass  # ESP8266 image has no append_digest field

    finfo.close()
    print("END")


#image_info("esp32","nn_test.bin")
if __name__ == '__main__':
    if len(sys.argv)>=2:
        fin     = sys.argv[1]
        print('Processing file:', fin)
        image_info("esp32",fin)
        print("done...")
    else:
        print("Incorrect params. Usage:")
        print("nnc_disassemble fin.bin")
