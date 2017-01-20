'''
Author: Paul Vines
'''

from Crypto.Random.Fortuna.FortunaGenerator import AESGenerator
from collections import namedtuple
from Byte import bs2i, il2bs, b2i, pos2byte, bl2i, i2bl
from math import ceil, floor, log
import pickle as pkl
from utils import BLOCK_SIZE, Bunch
from Packet import Packet, Block

masks = {}
for i in range(80):
    t = 0
    for j in range(i):
        t = 1 + (t << 1)
    masks[i] = t


PacketType = namedtuple('PacketType', 'max_bits blocks')


class Parser(object):
    def __init__(self, seq_index):
        self.seq_index = seq_index

    @classmethod
    def from_file(cls, filename):
        return pkl.load(open(filename, 'rb'))

    def save(self, filename):
        pkl.dump(self, open(filename, 'wb'))

    def get_packet_type(self, packet):
        return PacketType(0, [])

    def _make_reverse_lookup(values):
        indices = {}
        for i, v in enumerate(values):
            indices[v] = i

        return indices


def ParseTuple(data, pos, blocks):
    return Bunch(data=data, pos=pos, blocks=blocks)


class DataFragment():

    def __init__(self):
        self.is_compressed = False
        self.uncompressed_size = 0
        self.bytes = 0
        self.length = 0
        self.filename = None
        self.buffer = None

    def uncompress_fragments(self):
        if not self.is_compressed:
            return

        new_buffer = Packet(self.buffer).snappy_decompress()

        if new_buffer:
            self.is_compressed = False
            self.bytes == self.uncompressed_size
            self.buffer = new_buffer


class Subchannel():
    WAITING = 0
    DIRTY = 1
    TOSEND = 2

    def __init__(self):
        self.num_fragments = 0
        self.state = Subchannel.WAITING
        self.send_seq = 0

    def free(self):
        self.num_fragments = 0
        self.state = Subchannel.WAITING


def make_blocks(count_dict, freq_cutoff=10):
    filtered_blocks = {}

    for c in sorted(count_dict.keys()):
        count = count_dict[c]
        total = sum([count[1][a] for a in count[1]])
        uniform_freq = 1 / len(count[1])

        values = []
        for v in sorted(count[1].keys()):
            f = float(count[1][v]) / total
            if f > uniform_freq / freq_cutoff:
                values.append(int(v))
            else:
                print("crazy freq!", v, f, uniform_freq)

        if len(values) > 0:
            free_bits = floor(log(len(values), 2))
        else:
            continue

        values = list(values[0:2**free_bits])
        filtered_blocks[c] = Block(0, free_bits, count[0].value_size, values,
                                   Parser._make_reverse_lookup(values), c)

    return filtered_blocks


MAX_SEQ_NUM = 240
SEQ_WINDOW = 1  # 5
MIN_SPACING = 5
FLAG_LEN = 2
FLAG_POS_LEN = 100
KEEP_ALIVE_LEN = 1000
IV_LENGTH = 16


class StegoEngine(object):
    def __init__(self, seed, spec, utilization, max_packet_spacing,
                 _print=False):
        self._seed = seed
        self._drbg_count = 0
        self._print = _print
        self._utilization = utilization
        self._parser = spec
        self._max_packet_spacing = max_packet_spacing
        self._drbg = AESGenerator()
        self._drbg.reseed(seed)
        self._init_keep_alive()
        self._init_flag()
        self._bit_index = 0
        self._byte_index = 0
        self._pack_count = 0

    def _init_keep_alive(self):
        self._keep_alives = []
        self._keep_alive_index = 0
        for i in range(KEEP_ALIVE_LEN):
            self._keep_alives.append(self._drbg.pseudo_random_data(1))

    def _init_flag(self):
        self.flagged = False
        self._flag_positions = []
        self._flag_values = []
        for i in range(FLAG_POS_LEN):
            self._flag_positions.append(self._next_random_int())

        for i in range(FLAG_LEN):
            self._flag_values.append(self._drbg.pseudo_random_data(1))

    def _next_random_int(self):
        t = bs2i(self._drbg.pseudo_random_data(4))
        self._drbg_count += 1
        return t

    def _determine_next_packet(self, cur_packet):
        self._next_packet = []
        for i in range(5):
            self._next_packet.append(((cur_packet + MIN_SPACING +
                                       self._next_random_int() %
                                       self._max_packet_spacing) +
                                      (i * 30)) % MAX_SEQ_NUM)

    def _is_next_packet(self, payload):
        if self._max_packet_spacing < 5:
            return self._pack_count % self._max_packet_spacing == 1
        if len(payload) > self._parser.seq_index:
            return min(map(lambda x: abs(x - int(
                payload[self._parser.seq_index])),
                self._next_packet)) == 0
        else:
            return False

    def _finished_message(self):
        return

    def reset(self):
        self._drbg = AESGenerator()
        self._drbg.reseed(self._seed)
        self._init_keep_alive()
        self._init_flag()
        self._finished_message()

    def _store_data(self, payload, pos, data, num_bits):
        if log(max(1, data), 2) > num_bits:
            print("data exceeds number of bits")
            return payload
        start = pos2byte(pos)
        end = start + max(0, ceil((num_bits - (8 - (pos % 8))) / 8))
        b = payload[start:end + 1]

        bi = bl2i(reversed(b))
        res = (bi & masks[pos % 8])
        res += (data << (pos % 8))
        res += (bi & (~(masks[(pos % 8) + num_bits]) & 0xffffffffffffffff))

        bl = i2bl(res, len(b))
        for i, b in enumerate(bl):
            payload[start + i] = b

        return payload

    # DOES NOT MODIFY POSITION
    def _read_int(self, data, pos, num_bits):
        start = pos2byte(pos)
        end = start + max(0, ceil((num_bits - (8 - (pos % 8))) / 8))
        b = data[start:end + 1]

        b = bl2i(reversed(b))
        b = b >> (pos % 8)
        b = b & masks[num_bits]

        return b

 
class StegoSender(StegoEngine):
    def __init__(self, seed, spec, utilization, max_packet_spacing, read_buf):
        StegoEngine.__init__(self, seed, spec, utilization,max_packet_spacing)
        self._read_buf = read_buf
        self._finished_message()
        self._data_sent = 0

    def _finished_message(self):
        if not self._read_buf.empty():
            self._cur_msg = self._read_buf.get()
            self._cur_msg = self._cur_msg[:BLOCK_SIZE] # messages should only ever be BLOCK_SIZE long
        else:
            self._cur_msg = None
        self._byte_index = 0
        self._bit_index = 0

    # RETURNS None IF THE PACKET IS UNTOUCHED
    def insert(self, payload):

        if (self._cur_msg is None):
            self._finished_message()

        if not self.flagged and self._cur_msg is None:
            return None
        elif not self.flagged:
            return self.send_flag(payload)

        else:
            self._pack_count += 1
            if self._is_next_packet(payload):
                self._determine_next_packet(
                    b2i(payload[self._parser.seq_index]))
                if self._print:
                    print("sender", self._next_packet, self._drbg_count)
                return self._hide_data(payload)

            else:
                return None

    def send_flag(self, payload):

        packet_type = self._parser.get_packet_type(payload)
        if not packet_type or len(packet_type.blocks) == 0:
            print("no packet_type")
            return None

        blocks = packet_type.blocks
        num_bits = 8 * FLAG_LEN
        if num_bits > int(self._utilization * float(packet_type.max_bits)):
            return None
        else:
            sum_bits = 0
            indices = []
            a = 0
            while sum_bits < num_bits and a < len(self._flag_positions):

                index = self._flag_positions[a] % len(blocks)
                a += 1
                if index not in indices:
                    indices.append(index)
                    sum_bits += blocks[index].free_bits

            if a >= len(self._flag_positions):
                return None

            blocks_to_use = map(lambda x: blocks[x], indices)
            new_payload = [v for v in payload]

            for block in blocks_to_use:
                num_bits_for_block = min(block.free_bits, num_bits)
                value_to_hide = self._hide_bits(block,
                                                num_bits_for_block, flag=True)

                self._store_data(new_payload, block.position, value_to_hide,
                                 block.value_size)
                num_bits -= num_bits_for_block

            self.flagged = True
            self._determine_next_packet(payload[self._parser.seq_index])
            print(">>>>>>>>>>>>>>>>>> first send:", self._next_packet)

            if self._byte_index != 0 or self._bit_index != 0:
                self._byte_index = 0
                self._bit_index = 0

            return il2bs(new_payload)

    def _hide_data(self, payload):
        packet_type = self._parser.get_packet_type(payload)
        if not packet_type or len(packet_type.blocks) == 0:
            return None

        blocks = packet_type.blocks
        ka_index = self._next_random_int() % len(blocks)
        if self._print:
            print("KA", self._drbg_count)

        keep_alive_block = blocks[ka_index]
        if (self._cur_msg is None):
            new_payload = [v for v in payload]
            value_to_hide = self._hide_keep_alive(keep_alive_block,
                                                  keep_alive=True)

            self._store_data(new_payload, keep_alive_block.position,
                             value_to_hide, keep_alive_block.value_size)

            return il2bs(new_payload)
        else:
            if self._print:
                print([[b.name, b.free_bits] for b in blocks])

            bits_remaining = (8 * (len(self._cur_msg) - self._byte_index - 1)) + (8 - self._bit_index)
            num_bits = min(int(self._utilization * float(
                packet_type.max_bits - keep_alive_block.free_bits)),
                bits_remaining)

            if (num_bits == 0):
                return None
            else:
                sum_bits = 0
                indices = []

                while sum_bits < num_bits:
                    index = self._next_random_int() % len(blocks)
                    if self._print:
                        print("index", self._drbg_count)

                    if index not in indices and index != ka_index:
                        indices.append(index)
                        sum_bits += blocks[index].free_bits

                blocks_to_use = map(lambda x: blocks[x], indices)
                new_payload = [v for v in payload]

                # change keep_alive_block value to make sure it is NOT keep alive
                value_to_hide = self._hide_keep_alive(keep_alive_block, keep_alive=False)

                self._store_data(new_payload, keep_alive_block.position,
                                 value_to_hide, keep_alive_block.value_size)
                for block in blocks_to_use:
                    num_bits_for_block = min(block.free_bits, num_bits)
                    value_to_hide = self._hide_bits(block, num_bits_for_block)

                    self._store_data(new_payload, block.position,
                                     value_to_hide, block.value_size)
                    num_bits -= num_bits_for_block

                if self._byte_index == len(self._cur_msg):
                    self._finished_message()

                print("have sent:", self._data_sent, " bytes so far")
                return il2bs(new_payload)

    def _hide_keep_alive(self, block, keep_alive=True):
        if keep_alive:
            message = b2i(self._keep_alives[self._keep_alive_index]) % block.max_index
            self._keep_alive_index = (self._keep_alive_index +1) % len(self._keep_alives)

        else:
            # ensure the keep_alive block will not be equal to a "true" keep_alive
            message = (b2i(self._keep_alives[self._keep_alive_index]) +1) % block.max_index

        return block.hide(message)

    def _hide_bits(self, block, num_bits, flag=False):
        data = 0
        i = 0
        if flag:
            message = b''.join(self._flag_values)
        else:
            message = self._cur_msg

        # Gets the most significant bits first
        for i in range(num_bits):
            data = (data << 1) | ((int(message[self._byte_index]) >> (7 - self._bit_index)) & 1)

            self._bit_index += 1

            if self._bit_index == 8:
                self._data_sent += 1

                self._byte_index += 1
                self._bit_index = 0

                if self._byte_index >= BLOCK_SIZE or (flag and self._byte_index >= FLAG_LEN):
                    return block.hide(data)

        return block.hide(data)


class StegoReceiver(StegoEngine):
    def __init__(self, seed, spec, utilization, max_packet_spacing, write_buf):
        StegoEngine.__init__(self, seed, spec, utilization, max_packet_spacing)
        self._message_received = []
        self._write_buf = write_buf
        self._finished_message()
        self._print = False

    def _finished_message(self):
        if self._byte_index == BLOCK_SIZE:
            self._write_buf.put(il2bs(self._message_received))

        self._byte_index = 0
        self._bit_index = 0
        self._message_received = [0 for x in range(BLOCK_SIZE)]

    def _finished_keep_alive(self):
        self._byte_index = 0
        self._bit_index = 0
        self._message_received = [0 for x in range(BLOCK_SIZE)]

    def extract(self, payload):
        if self.flagged:
            self._pack_count += 1
            if self._is_next_packet(payload):
                self._determine_next_packet(payload[self._parser.seq_index])
                if self._print:
                    print("receiver", self._next_packet, self._drbg_count)
                self._find_data(payload)
                return True
            else:
                return False
        else:
            return self.receive_flag(payload)

    def receive_flag(self, payload):
        packet_type = self._parser.get_packet_type(payload)
        if not packet_type or len(packet_type.blocks) == 0:
            return False

        blocks = packet_type.blocks
        num_bits = 8 * FLAG_LEN
        if num_bits > int(self._utilization * float(packet_type.max_bits)):
            return False
        else:
            sum_bits = 0
            indices = []
            a = 0
            while sum_bits < num_bits and a < len(self._flag_positions):

                index = self._flag_positions[a] % len(blocks)
                a += 1
                if index not in indices:
                    indices.append(index)
                    sum_bits += blocks[index].free_bits

            if a >= len(self._flag_positions):
                return False

            blocks_to_use = map(lambda x: blocks[x], indices)
            for block in blocks_to_use:
                num_bits_for_block = min(block.free_bits, num_bits)
                self._find_bits(self._read_int(payload, block.position,
                                               block.value_size), block,
                                num_bits_for_block)
                num_bits -= num_bits_for_block

            all_match = True
            flag_vals_as_int = list(map(lambda x: int(x[0]), self._flag_values))
            for i in range(FLAG_LEN):
                if flag_vals_as_int[i] != self._message_received[i]:
                    all_match = False

            if all_match:
                self.flagged = True
                print("FLAG FOUND")
                self._determine_next_packet(payload[self._parser.seq_index])
                print("first recv", self._next_packet)

            if self._byte_index != 0 or self._bit_index != 0:
                self._byte_index = 0
                self._bit_index = 0

            self._message_received = [0 for x in range(BLOCK_SIZE)]

            # True if the packet contained the flag, and thus was altered
            return all_match

    def _find_data(self, payload):
        packet_type = self._parser.get_packet_type(payload)
        if not packet_type or len(packet_type.blocks) == 0:
            return False

        blocks = packet_type.blocks
        ka_index = self._next_random_int() % len(blocks)
        if self._print:
            print("KA", self._drbg_count)
        keep_alive_block = blocks[ka_index]

        if self._byte_index == 0 and self._check_keep_alive(payload,
                                                            keep_alive_block):
            self._finished_keep_alive()
            return True
        else:
            blocks = packet_type.blocks
            bits_remaining = (8 * (BLOCK_SIZE - self._byte_index -1) +
                              (8 - self._bit_index))
            num_bits = min(int(self._utilization * float(packet_type.max_bits - keep_alive_block.free_bits)), bits_remaining)
            if (num_bits == 0):
                return False
            else:
                if self._print:
                    print([[b.name, b.free_bits] for b in blocks])
                sum_bits = 0
                indices = []
                while sum_bits < num_bits:

                    index = self._next_random_int() % len(blocks)
                    if index not in indices and index != ka_index:
                        indices.append(index)
                        sum_bits += blocks[index].free_bits

                blocks_to_use = map(lambda x: blocks[x], indices)
                for block in blocks_to_use:
                    num_bits_for_block = min(block.free_bits, num_bits)
                    self._find_bits(self._read_int(payload, block.position,
                                                   block.value_size), block,
                                    num_bits_for_block)
                    num_bits -= num_bits_for_block

                if (self._byte_index == BLOCK_SIZE):
                    self._finished_message()

                return True

    def _check_keep_alive(self, payload, block):

        try:
            found_value = b2i(block.unhide(
                self._read_int(payload, block.position, block.value_size)))
        except KeyError:
            return False

        expected_value = b2i(self._keep_alives[self._keep_alive_index]) % (block.max_index)

        if expected_value == found_value:
            self._keep_alive_index = (self._keep_alive_index + 1) % len(self._keep_alives)
            return True
        else:
            return False

    def _find_bits(self, buf_data, block, num_bits):
        data = self._message_received[self._byte_index]
        i = 0

        # reverse lookup
        try:
            value = block.unhide(buf_data & masks[block.value_size])

        except KeyError:
            return

        # Gets the most significant bits first
        if self._byte_index >= BLOCK_SIZE:
            return

        for i in range(num_bits):
            data = (data << 1) | ((value >> (num_bits -1) - i) & 1)
            self._bit_index += 1

            if self._bit_index == 8:
                self._message_received[self._byte_index] = data
                self._byte_index += 1
                self._bit_index = 0
                if self._byte_index >= BLOCK_SIZE: # done with packet!
                    return
                else:
                    data = self._message_received[self._byte_index]


        self._message_received[self._byte_index] = data
