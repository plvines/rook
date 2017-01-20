'''
Author: Paul Vines
'''

from struct import unpack
from math import floor


def pos2dword(pos):
    if pos < 0:
        return 0

    return (pos >> 5) * 4


def pos2byte(pos):
    if pos < 0:
        return 0

    return floor(pos / 8)


def bl2i(byte_list):
    r = 0
    for b in byte_list:
        r = b + (r << 8)

    return r


def i2bl(bi, num_bytes):
    r = []
    for i in range(num_bytes):
        r.append((bi >> (i * 8)) & 0xff)

    return r


def b2i(byte_list):
    if type(byte_list) == int:
        return byte_list

    return int(byte_list[0])


def i2bs(integer, little=False):
    if little:
        return integer.to_bytes(4, byteorder='little')
    else:
        return integer.to_bytes(4, byteorder='big')


def i2b(integer):
    return integer.to_bytes(1, byteorder='big')


def bs2i(bytestring, reverse_order=False):
    if reverse_order:
        if len(bytestring) == 4:
            return unpack("<I", bytestring)[0]
        else:
            i = 0
            for index, b in enumerate(bytestring):
                i = (int(b) << 8 * index) + i
            return i

    else:
        if len(bytestring) == 4:
            return unpack(">I", bytestring)[0]
        else:
            i = 0
            for b in bytestring:
                i = (i << 8) + int(b)
            return i


def il2bs(int_list, bytes_per_int=1):
    return b''.join(map(lambda x: x.to_bytes(bytes_per_int, byteorder='big'),
                        int_list))


def il2bs_little(int_list, bytes_per_int=1):
    return b''.join(map(lambda x: x.to_bytes(bytes_per_int,
                                             byteorder='little'), int_list))


def bs2il(bytestring):
    return [int(x) for x in bytestring]


def strip(bytestring, strip_byte):
    if type(strip_byte) == bytes:
        strip_byte = b2i(strip_byte)
    elif type(strip_byte) == str:
        strip_byte = ord(strip_byte)

    i = 0
    for b in bytestring:
        if b == strip_byte:
            break
        i += 1

    return bytestring[:i]


def split(bytestring, split_on):
    if type(split_on) == bytes:
        split_on = split_on[0]
    elif type(split_on) == str:
        split_on = s2bs(split_on)[0]

    splitted = []
    start = 0
    end = 0
    for i, b in enumerate(bytestring):
        if b == split_on:
            if start == i:
                start = i + 1
                continue
            end = i
            splitted.append(bytestring[start:end])
            start = end + 1

    if start != len(bytestring):
        splitted.append(bytestring[start:])

    return splitted


def s2bs(string):
    return bytes(string, "utf-8")


def bs2s(bytestring):
    return str(bytestring, "utf-8")


def i2f(i):
    return bs2f(i2bs(i))


def bs2f(bytestring):
    return unpack('f', bytestring)[0]
