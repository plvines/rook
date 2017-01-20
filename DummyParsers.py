'''
Author: Paul Vines
'''

from Packet import Packet
from StegoEngine import Parser, PacketType


class DummyParser(Parser):
    def __init__(self, block_dict, mode=Packet.PARSE, ngrams=1):
        Parser.__init__(self, 0)
        self._mode = mode

    def get_packet_type(self, packet, blocks=None, counts=None):
        p = Packet(payload=packet, start_pos=0, mode=self._mode,
                   blocks=blocks, block_dict=self._block_dict, counts=counts,
                   ngrams=self._ngrams)

        while p.pos < p.length:
            p.read_bits(8, alterable=True, key=str(p.pos))

        return PacketType(sum(map(lambda b: b.free_bits, p.blocks)), p.blocks)

