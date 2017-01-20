'''
Author: Paul Vines
'''

from Byte import pos2byte, bl2i, i2f
from math import ceil


class Block():
    def __init__(self, position, free_bits, value_size, lookup, rev_lookup,
                 name, max_index=None):
        self.position = position
        self.free_bits = free_bits
        self.value_size = value_size
        self.lookup = lookup
        self.rev_lookup = rev_lookup
        self.name = name
        if max_index:
            self.max_index = max_index
        else:
            self.max_index = 2**free_bits

    def hide(self, data):
        if callable(self.lookup):
            return self.lookup(data)

        if type(self.lookup) == list:
            return self.lookup[data]

    def unhide(self, data):
        if callable(self.rev_lookup):
            return self.rev_lookup(data)

        if type(self.rev_lookup) == dict:
            return self.rev_lookup[data]


masks = {}
for i in range(1024):
    t = 0
    for j in range(i):
        t = 1 + (t << 1)
    masks[i] = t

print_things = False


class Packet():
    PARSE = 0
    SPEC = 1
    BLOCKS = 2

    def __init__(self, payload, start_pos=0, mode=0, blocks=[],
                 block_dict={}, counts={}, ngrams=1):
        self._mode = mode
        self._ngrams = ngrams

        if self._mode == self.SPEC and self._ngrams > 1:
            self._prev_list = []
            for i in range(1, self._ngrams):
                self._prev_list.append({})

        else:
            self._prev_list = None

        self.pos = start_pos
        self.length = len(payload) * 8
        self.payload = payload
        self.blocks = blocks
        self.block_dict = block_dict
        self.counts = counts
        self.read_count = 1

    def bytes_remaining(self):
        return (self.length - self.pos) >> 3

    def read_bits(self, num_bits, alterable=False, key=''):
        if self.pos + num_bits > self.length:
                self.pos = self.length
                return 0

        orig_pos = self.pos
        start = pos2byte(self.pos)
        end = start + max(0, ceil((num_bits - (8 - (self.pos % 8))) / 8))
        b = self.payload[start:end + 1]

        b = bl2i(reversed(b))
        b = b >> (self.pos % 8)
        b = b & masks[num_bits]

        if alterable:

            value_key = str(b)

            if self._mode == Packet.SPEC:
                if self._prev_list:
                    value_key = ''
                    # iterate through previous entries to great the n-gram key
                    # made up of the n-1 previous entries at this key
                    for i in range(len(self._prev_list)):
                        # set previous to 0 if it didn't exist
                        if key not in self._prev_list[i]:
                            self._prev_list[i][key] = 0

                        value_key = (str(value_key) + '_' +
                                     str(self._prev_list[i][key]))

                        # shift previous values to more previous
                        if i + 1 < len(self._prev_list):
                            if key not in self._prev_list[i + 1]:
                                self._prev_list[i + 1][key] = 0

                            self._prev_list[i][key] = (
                                self._prev_list[i + 1][key])

                        # shift this value into the most recent previous value
                        else:
                            self._prev_list[-1][key] = b

                    value_key = value_key[1:] + '_' + str(b)

                if key in self.counts:
                    if value_key in self.counts[key][1]:
                        self.counts[key][1][value_key] += 1
                    else:
                        self.counts[key][1][value_key] = 1
                else:
                    self.counts[key] = (Block(0, num_bits, num_bits,
                                              None, None, key), {})

            elif self._mode == Packet.BLOCKS:
                if key in self.block_dict:
                    block = self.block_dict[key]
                    self.blocks.append(Block(self.pos, block.free_bits,
                                             block.value_size, block.lookup,
                                             block.rev_lookup, block.name))

        self.pos += num_bits

        if print_things:
            print('#', str(self.read_count) + '.', str(hex(orig_pos)) + ':' +
                  str(hex(self.pos - 1)) + '->' + hex(b))
        self.read_count += 1
        return b

    def read_var_bits(self, alterable=False, key=''):
        v = self.read_bits(6, alterable=False, key='')
        if v & 3 > 0:
            self.pos -= 4
            b = (((2 - v) >> 31) & 0x10) + (4 * (v + 1))
            r = self.read_bits(b, alterable=False, key='')
        else:
            r = v >> 2

        return r

    def read_vlq_bits(self):
        result = 0

        i = 1
        read = self.read_bits(8)
        result = read & 0x7F

        # check most signficant bit
        while read & 0x80 != 0:
            read = self.read_bits(8)
            result = ((read & 0x7F) << (i * 7)) | result
            i += 1

        return result

    def seek(self, num_bits):
        self.pos += num_bits

    def read_bool(self):
        return self.read_bits(1) != 0

    # 32-bit
    def read_float(self, alterable=False, key=''):
        return i2f(self.read_bits(32, alterable, key))

    def read_bytes(self, num_bytes, critical=False):
        global print_things

        if critical:
            print_things = True

        if print_things:
            print("< --- Read Bytes --- >")
            orig = True
        else:
            orig = False

        result = [self.read_bits(8) for i in range(num_bytes)]

        # Removed because I pass number of bytes, not number of bits
        # if num_bits % 8 != 0:
        # result.append(self.read_bits(num_bytes % 8))

        print_things = orig
        if print_things:
            print("< --- Read Bytes --- >\n")
            self.read_count = 1

        if critical:
            print_things = False

        return result

    def read_string(self, terminators=[], max_len=None):
        s = ''
        i = 0
        while True:
            c = chr(self.read_bits(8))
            i += 1
            if c == '\x00' or c in terminators:
                break
            elif max_len and i >= max_len:
                break

            s += c

        return s

    def read_0x80(self):
        if print_things:
            print("< --- Read Something --- >")
        i = 0
        v = 0
        t = 0

        while i != 35:
            v = self.read_bits(8)
            t |= ((v & 0x7F) << i)
            i += 7

            if v & 0x80 == 0:
                break

        if print_things:
            print("< --- Read Something --- >\n")
        if print_things:
            print('t:', hex(t))

        return t

    def read_something(self):
        a = self.read_bits(8)
        while a != 0:
            a = self.read_bits(8)

        return a

    def snappy_decompress(self, header=True, start_point=None):
        if header:
            if self.read_bits(32) != 0x50414e53:
                return []

        if start_point:
            self.pos = start_point

        new_payload = []
        uncompressed_length = self.read_vlq_bits()

        while self.pos < self.length:
            tag = self.read_bits(2)
            if tag == 0x00:
                length = self.read_bits(6)
                if length == 60:
                    length = self.read_bits(8)
                elif length == 61:
                    length = self.read_bits(8) | (self.read_bits(8) << 8)
                elif length == 62:
                    length = (self.read_bits(8) | (self.read_bits(8) << 8) |
                              (self.read_bits(8) << 16))
                elif length == 63:
                    length = (self.read_bits(8) | (self.read_bits(8) << 8) |
                              (self.read_bits(8) << 16) |
                              (self.read_bits(8) << 24))

                length += 1

                new_payload += self.read_bytes(length)

            elif tag == 0x01:
                length = self.read_bits(3) + 4
                offset = (self.read_bits(3) << 8) | self.read_bits(8)

                for i in range(length):
                    new_payload.append(new_payload[-offset])

            elif tag == 0x02:
                length = self.read_bits(6) + 1
                offset = self.read_bits(8) | (self.read_bits(8) << 8)
                if offset > length and False:
                    new_payload += new_payload[-offset:length - offset]
                else:
                    for i in range(length):
                        new_payload.append(new_payload[-offset])

            elif tag == 0x03:
                length = self.read_bits(6) + 1
                offset = (self.read_bits(8) | (self.read_bits(8) << 8) |
                          (self.read_bits(8) << 16) |
                          (self.read_bits(8) << 24))
                if offset > length and False:
                    new_payload += new_payload[-offset:length - offset]
                else:
                    for i in range(length):
                        new_payload.append(new_payload[-offset])

        if len(new_payload) != uncompressed_length:
            print("Snappy Decompression Length Mismatch",
                  hex(len(new_payload)), hex(uncompressed_length))

        return new_payload
