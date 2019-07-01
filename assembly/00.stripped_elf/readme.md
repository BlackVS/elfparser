# Some notes:

# Segemnt 0 (with program partition)

## ELF
segment 0 starts from 0 and contains ELF header ( 0x34 bytes) + program headers table (0x20 x num_of_segments)
and program data

Load address: 0x3f3fff40
Program data start at: 0x3f3fff40 + 0x34 + 0x20 x 5 = 0x3f3fff40 + 0xd4 = 0x3F400014


## BIN
segment 0 contains bin partition header (8 bytes - virtual load address and segment size together with 8 bytes header)
and program data

Load address: 0x3f400020
Program data without header start at: 0x3f400020

Delta = 0x3f400020 - 0x3f400014 = 0xc (zero pad)

i.e. to substitute ELF segment 0 in ELF by BIN segment 0 we have take bin segment 0 and:
- cut 8-bytes partition header
+ add 0x34 ELF header
+ add 0x20 x 5 space for partition (partition table will be filled by data from map)
+ 12-bytes zero pad
x change load bin address 0x3f400020 to 0x3f400020 - 0x34 - 0x20 x 5 - 0xc = 0x3F3FFF40

# Segment 1

## ELF
p_paddr     p_filesz    p_memsz
3ffbdb60    000026b0    00008cf0

## BIN
load        len
0x3ffbdb60  0x03614 

26b0+6640(bss)=8cf0
i.e. elf=bin+bss (bss size in bin?)

# Segment 2

## ELF
p_paddr     p_filesz    p_memsz
40080000    0x00400     0x00400

## BIN
load        len
40080000    0x00400

Just copy

# Segment 3

## ELF
p_paddr     p_filesz    p_memsz
40080400    000101d7    000101d7

## BIN
load        len
0x40080400  0x00914 3.1
0x40080d14  0x15b64 3.2

Join 2 bin segmnets in one ELF segment

# Segment 4

## ELF
p_paddr     p_filesz    p_memsz
400d0018    000746c2    000746c2

## BIN
load        len
0x400d0018  0xd1f18

Just copy
