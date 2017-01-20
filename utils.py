'''
Author: Paul Vines
'''

import collections
import itertools
import Byte
from math import floor
PADDING_BYTE = b'\xff'
BLOCK_SIZE = 16


class Bunch:
    def __init__(self, **kwds):
        self.__dict__.update(kwds)


def parse_pt_cap_wheaders(filename):
    f = open(filename, 'r')
    packets = []
    lines = []
    for line in f:
        if line == "\n" or line == "\r\n":
            packets.append(list(map(lambda x: int(x, 16),
                                    chunk(''.join(lines), 2))))
            lines = []

        else:
            lines.append(line.split('  ', 2)[1].replace(' ', '')[:])

    f.close()
    return packets


def parse_pt_cap(filename):
    f = open(filename, 'r')
    packets = []
    lines = []
    for line in f:
        if line == "\n" or line == "\r\n":
            temp = (list(map(lambda x: int(x, 16), chunk(''.join(lines), 2))))
            packets.append(list(temp[42:]))
            lines = []

        else:
            lines.append(line.split('  ', 2)[1].replace(' ', '')[:])

    f.close()
    return packets


def find_bits(value_list, num_bits_list, max_store_index):
    store = [0 for x in range(max_store_index)]
    store_index = 0
    bit_index = 0
    for i, v in enumerate(value_list):
        (bit_index, store_index, store) = find_bits_helper(
            v, num_bits_list[i], store, store_index, bit_index,
            max_store_index)
        print(store)

    return store


def find_bits_helper(value, num_bits, store, store_index, bit_index,
                     max_store_index):
    print(value, num_bits, store_index, bit_index)
    data = 0
    shift_index = bit_index
    for i in range(num_bits):
        # data = (data << 1) | ((value >> i) & 1)
        print("reading:", ((value >> ((num_bits - 1) - i)) & 1) << bit_index)
        data = ((value >> ((num_bits - 1) - i) & 1) << bit_index) | data
        bit_index += 1

        if bit_index == 8:
            prev_data = store[store_index]

            store[store_index] = (data) | prev_data
            print("storing:", data, prev_data, " << ", shift_index,
                  data << shift_index | prev_data)
            store_index += 1
            bit_index = 0
            shift_index = 0
            if store_index >= max_store_index:
                return (bit_index, store_index, store)
            else:
                data = 0

    print("storing:", data, store[store_index], " << ", shift_index,
          data << shift_index | store[store_index])
    store[store_index] = (data) | store[store_index]
    return (bit_index, store_index, store)


def hide_bits(message, num_bits_list, max_message_index):
    values = []
    bit_index = 0
    message_index = 0
    for n in num_bits_list:
        (t, bit_index, message_index) = hide_bits_helper(
            message, n, message_index, bit_index, max_message_index)
        values.append(t)
        if (message_index >= max_message_index):
            break

    return (values, num_bits_list)


def hide_bits_helper(message, num_bits, message_index, bit_index,
                     max_message_index):
    data = 0
    print(num_bits, message_index, bit_index)
    for i in range(num_bits):
        data = (data << 1) | ((int(message[message_index]) >> bit_index) & 1)
        bit_index += 1
        if bit_index == 8:
            message_index += 1
            bit_index = 0
            if message_index >= max_message_index:
                return (data, bit_index, message_index)

    return (data, bit_index, message_index)


def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)


def chunk(string, size):
    for i in range(0, len(string), size):
        yield string[i:i+size]


def take(data, thing):
    return data[:len(thing)], data[len(thing):]


def flatten_1(list_of_lists):
    return [item for li in list_of_lists for item in li]


def avg_by_index(list_of_lists):
    result = []
    for i in range(list_of_lists[0]):
        result.append([l[i] for l in list_of_lists])

    return result


def flatten(l, ltypes=collections.Sequence):
    l = list(l)
    while l:
        while l and isinstance(l[0], ltypes):
            l[0:1] = l[0]
        if l:
            yield l.pop(0)


def flatten_once(l):
    return list(itertools.chain.from_iterable(l))


def trim_to_seq(packet_list, seq=1):
    for i in range(len(packet_list)):
        print("SEQ:", Byte.bs2i(packet_list[i][0:2], reverse_order=True))
        if Byte.bs2i(packet_list[i][0:2], reverse_order=True) == seq:
            return packet_list[i:]


def trim_past_seq(packet_list, seq=1, under=0xfff0):
    for i in range(len(packet_list)):
        print("SEQ:", Byte.bs2i(packet_list[i][0:2], reverse_order=True))
        byte = Byte.bs2i(packet_list[i][0:2], reverse_order=True)
        if byte >= seq and byte < under:
            return packet_list[i:]


def is_stun(payload):
    if len(payload) >= 2:
        return payload[1] == 1 and (payload[0] == 0 or payload[0] == 1)
    else:
        return False


# returns (has_a_mapping, port or None)
def get_stun_mapping(payload):
    result = False
    port = None
    if is_stun(payload):
        result = True
        length = Byte.bs2i(payload[2:4])
        p = payload[20:]
        while not Byte.bs2i(p[:2]) == 1:
            l = Byte.bs2i(p[2:4])
            if l + 4 >= len(p):
                result = False
                break
            p = p[l + 4:]

        if result:
            port = Byte.bs2i(p[6:8])

    return (result, port)


def pos2dword(pos):
    return (pos >> 5) * 4


def pos2byte(pos):
    return floor(pos / 8)


LZSS_LOOKSHIFT = 4
LZSS_LOOKAHEAD = (1 << LZSS_LOOKSHIFT)


def LZSS_Decompress(inbuf, outlength):
    total_bytes = 0
    cmd_byte = 0
    get_cmd_byte = 0
    a = 0
    b = 0
    outbuf = [0 for v in range(outlength)]

    while True:
        if get_cmd_byte == 0:
            cmd_byte = inbuf[a]
            a += 1

        get_cmd_byte = (get_cmd_byte + 1) & 0x7

        if (cmd_byte & 0x1) != 0:
            position = inbuf[a] << LZSS_LOOKSHIFT
            a += 1
            position |= (inbuf[a] >> LZSS_LOOKSHIFT)
            count = (inbuf[a] & 0xF) + 1
            a += 1
            if count == 1:
                break

            source = b - position - 1
            for i in range(count):
                temp = inbuf[source]
                outbuf[b] = temp
                b += 1
                source += 1

            total_bytes += count

        else:
            outbuf[b] = inbuf[a]
            b += 1
            a += 1
            total_bytes += 1

        cmd_byte = cmd_byte >> 1

    return bytes(outbuf)
