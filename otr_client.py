'''
Author: Paul Vines
'''

import Byte
from pydivert.windivert import WinDivert
from Crypto.Cipher import AES
from Crypto import Random
import threading
import utils
import potr
import os
import time
from Byte import s2bs, strip, split, bs2s
from StegoEngine import IV_LENGTH, StegoSender, StegoReceiver, make_blocks
from IO import IO
from queue import Queue
from utils import enum, PADDING_BYTE, errlog, get_stun_mapping, is_stun
import socket
from message import Message, CMD, ACK_MSG, process_msg
import configparser
import checksum
import pickle as pkl
from DummyParsers import DummyParser
from Packet import Packet

Status = enum('CONNECTED', 'DISCONNECTED', 'CONNECTING',
              'WAITING_FOR_FLAG', 'WAITING_FOR_ACK')

dg = True


class InterceptorClient(threading.Thread):

    def __init__(self, read_buf, write_buf, insert_port, extract_port,
                 utilization, packet_spacing, seed, send_spec=None,
                 recv_spec=None, send=True, recv=True, stun=True,
                 packet_cap_start=500, packet_cap_end=2000):
        threading.Thread.__init__(self)
        self._driver = WinDivert(r".\\lib\\1.0\\amd64\\WinDivert.dll")
        self._keep_running = True
        self._force_shutdown = False

        if send_spec is not None:
            self._stego_sender = StegoSender(seed, send_spec, utilization,
                                             packet_spacing, read_buf)
        else:
            self._stego_sender = None
        if recv_spec is not None:
            self._stego_receiver = StegoReceiver(seed, recv_spec,
                                                 utilization,
                                                 packet_spacing, write_buf)
        else:
            self._stego_receiver = None

        self._out_port = int(insert_port)
        self._in_port = int(extract_port)
        self._utilization = utilization
        self._packet_spacing = packet_spacing
        self._seed = seed
        self._read_buf = read_buf
        self._write_buf = write_buf
        self._send = send
        self._recv = recv
        self._stun = stun
        self._packet_cap_start = packet_cap_start
        self._packet_cap_end = packet_cap_end

    def run(self):
        if self._stun:
            self.run_stun()
        else:
            self.run_nonstun()

    def run_stun(self):
        errlog("scanning for stuns")
        handle = self._driver.open_handle(filter="udp", priority=1000)
        self._in_port = None
        self._out_port = None
        self._ip_addr = socket.gethostbyname(socket.gethostname())

        while self._keep_running and not (self._in_port and self._out_port):
            packet = handle.receive()

            new_mapping, port = get_stun_mapping(packet.payload)
            if new_mapping:
                errlog(port, packet.src_addr, self._ip_addr)
                if packet.src_addr == self._ip_addr:
                    self._out_port = port
                    errlog("out")
                else:
                    self._in_port = port
                    errlog("in")

            handle.send(packet)

        handle.close()

        if self._keep_running:
            handle = self._driver.open_handle(filter="udp.DstPort == " +
                                              str(self._in_port) +
                                              " or udp.DstPort == " +
                                              str(self._out_port),
                                              priority=1000)

            errlog("starting:", self._in_port, self._out_port)
            print("Ready to Connect (c)")
        while not self._force_shutdown and (self._keep_running or
                                            self._stego_sender._cur_msg
                                            is not None):
            packet = handle.receive()

            try:
                new_mapping, port = get_stun_mapping(packet.payload)
                reopen = False
                if new_mapping:
                    if packet.src_addr == self._ip_addr:
                        if not port == self._out_port:
                            self._out_port = port
                            reopen = True
                    else:
                        if not port == self._in_port:
                            self._in_port = port
                            reopen = True

                    handle.send(packet)

                    if reopen:
                        handle.close()
                        filter = ("udp.DstPort == " +
                                  str(self._in_port) +
                                  " or udp.DstPort == "
                                  + str(self._out_port))
                        handle = self._driver.open_handle(filter, priority=1000)
                        errlog("New Out:", self._out_port,
                               "New Out:", self._in_port)

                elif not is_stun(packet.payload):
                    dont_send = False
                    # outgoing packets
                    if packet.dst_port == self._out_port and self._send:
                        packet.payload = self._stego_sender.insert(packet.payload)
                        self._driver.update_packet_checksums(packet)

                    # incoming packets
                    elif packet.dst_port == self._in_port and self._recv:
                        if self._stego_receiver.extract(packet.payload):
                            dont_send = True

                    if not dont_send:
                        handle.send(packet)

                else:
                    handle.send(packet)

            except AttributeError:
                errlog("AttributeError")

        handle.close()

    def _build_specs(self):
        filter = ("udp.DstPort == " + str(self._in_port) +
                  " or udp.DstPort == " + str(self._out_port))
        handle = self._driver.open_handle(filter, priority=1000)

        errlog(str(self._packet_cap_start), str(self._packet_cap_end))
        recv_payloads = []
        send_payloads = []
        # Create spec loop
        while not self._force_shutdown and (self._keep_running and
                                            ((len(recv_payloads) <
                                              self._packet_cap_end + 50) or
                                             (len(send_payloads) <
                                              self._packet_cap_end + 50))):

            packet = handle.receive()

            # outgoing packets
            if ((packet.src_port == self._in_port) and
                    (packet.dst_port == self._out_port) and self._send):
                send_payloads.append(packet.payload)

            # incoming packets
            elif ((packet.src_port == self._out_port) and
                  (packet.dst_port == self._in_port) and self._recv):
                recv_payloads.append(packet.payload)

            handle.send(packet)
            print(len(recv_payloads), len(send_payloads))

        handle.close()

        self._make_specs(send_payloads, recv_payloads)

    def _make_specs(self, send_payloads, recv_payloads):
        print("making specs!")
        parser = DummyParser(block_dict={}, mode=Packet.SPEC, ngrams=1)
        counts1 = {}
        send_payloads = utils.trim_past_seq(send_payloads,
                                            seq=self._packet_cap_start)
        byte1 = Byte.bs2i(send_payloads[0][0:2], reverse_order=True)
        byte2 = Byte.bs2i(send_payloads[-1][0:2], reverse_order=True)
        print("Seq Range for Send:", byte1, "-", byte2)
        for p in send_payloads[:self._packet_cap_end - self._packet_cap_start]:
            parser.get_packet_type(p, blocks=None, counts=counts1)

        send_filtered = make_blocks(counts1)

        send_spec = DummyParser(send_filtered, Packet.BLOCKS)
        self._stego_sender = StegoSender(self._seed, send_spec,
                                         self._utilization,
                                         self._packet_spacing,
                                         self._read_buf)

        parser = DummyParser(None, mode=Packet.SPEC, ngrams=1)
        counts2 = {}
        recv_payloads = utils.trim_past_seq(recv_payloads,
                                            seq=self._packet_cap_start)
        byte1 = Byte.bs2i(recv_payloads[0][0:2], reverse_order=True)
        byte2 = Byte.bs2i(recv_payloads[-1][0:2], reverse_order=True)
        print("Seq Range for Recv:", byte1, "-", byte2)

        for p in recv_payloads[:self._packet_cap_end - self._packet_cap_start]:
            parser.get_packet_type(p, blocks=None, counts=counts2)

        recv_filtered = make_blocks(counts2)
        recv_spec = DummyParser(recv_filtered, Packet.BLOCKS)
        self._stego_receiver = StegoReceiver(self._seed, recv_spec,
                                             self._utilization,
                                             self._packet_spacing,
                                             self._write_buf)

        pkl.dump(recv_spec, open("client_recv.pkl", 'wb'))
        pkl.dump(send_spec, open("client_send.pkl", 'wb'))

    def run_nonstun(self):
        errlog(str(self._out_port), str(self._in_port))

        if self._stego_sender is None or self._stego_receiver is None:
            self._build_specs()

        print("Ready to Connect (c)")
        filter = ("udp.DstPort == " + str(self._in_port) +
                  " or udp.DstPort == " + str(self._out_port))
        handle = self._driver.open_handle(filter, priority=1000)

        # Actual operation loop
        while not self._force_shutdown and (self._keep_running or
                                            (self._stego_sender._cur_msg
                                             is not None)):
            packet = handle.receive()
            dont_send = False

            # outgoing packets
            if packet.dst_port == self._out_port and self._send:
                altered = self._stego_sender.insert(packet.payload)
                if altered is not None:
                    packet.payload = altered
                    # TODO should change this to be included in StegoEngine/PacketParser
                    packet.payload = (packet.payload[:9] +
                                      checksum.tf2_checksum(
                                          packet.payload[11:]) +
                                      packet.payload[11:])
                    self._driver.update_packet_checksums(packet)
            # incoming packets
            elif packet.dst_port == self._in_port and self._recv:
                if self._stego_receiver.extract(packet.payload):
                    dont_send = False

            if not dont_send:
                handle.send(packet)

        handle.close()

    def stop(self):
        errlog("interceptor stopping!")
        self._keep_running = False
        self._force_shutdown = True

    def force_stop(self):
        self._force_shutdown = True

    def _write(self, bytes):
        self._write_buf.put(bytes)

    def is_flag_received(self):
        return self._stego_receiver.flagged


class RookClient ():
    def __init__(self, config, out_port='27015', in_port='27005',
                 utilization=1.0, packet_spacing=10,
                 seed=b'abcdefghijklmnop',
                 send_spec=None,
                 recv_spec=None, packet_cap_start=500, packet_cap_end=2000):
        self._read_buf = Queue()
        self._write_buf = Queue()

        if config:
            c = configparser.ConfigParser()
            c.read(config)

            if c.has_option('Basic', 'client_spec'):
                send_spec = pkl.load(open(c.get('Basic', 'client_spec'), 'rb'))
            else:
                send_spec = None
            if c.has_option('Basic', 'server_spec'):
                recv_spec = pkl.load(open(c.get('Basic', 'server_spec'), 'rb'))
            else:
                recv_spec = None

            if c.has_option('Basic', 'packet_cap_start'):
                self._packet_cap_start = int(c.get('Basic',
                                                   'packet_cap_start'))
            else:
                self._packet_cap_start = 0

            if c.has_option('Basic', 'packet_cap_end'):
                self._packet_cap_end = int(c.get('Basic', 'packet_cap_end'))
            else:
                self._packet_cap_end = 0

            self._otr_thread = RookOTRClient(key=s2bs(c.get('Client', 'key')),
                                             key_index=s2bs(c.get('Client', 'key_index')), rook=self,
                                             id=c.get('Client', 'id'))
            self._interceptor_thread = InterceptorClient(read_buf=self._write_buf,
                                                         write_buf=self._read_buf,
                                                         insert_port=c.get('Basic', 'outbound_port'),
                                                         extract_port=c.get('Basic', 'inbound_port'),
                                                         utilization=c.getfloat('Basic', 'utilization'),
                                                         packet_spacing=c.getint('Basic', 'packet_spacing'),
                                                         seed=s2bs(c.get('Basic', 'seed')), send_spec=send_spec,
                                                         recv_spec=recv_spec,
                                                         stun=c.getboolean('Basic', 'stun'), packet_cap_start=self._packet_cap_start, packet_cap_end=self._packet_cap_end)

        else:
            self._otr_thread = RookOTRClient(key=b'aaaaaaaaaaaaaaaa',
                                             key_index='1', rook=self,
                                             id='scout')
            self._interceptor_thread = InterceptorClient(self._write_buf,
                                                         self._read_buf,
                                                         str(out_port),
                                                         str(in_port),
                                                         utilization,
                                                         packet_spacing,
                                                         seed, send_spec,
                                                         recv_spec)

        self._keep_running = True

    def run(self):
        self._interceptor_thread.start()
        self._otr_thread.start()
        while (self._keep_running):
            time.sleep(1)
        # clean up threads
        self._otr_thread.stop()
        self._otr_thread.join()
        errlog("otr joined")
        self._interceptor_thread.stop()
        self._interceptor_thread.join()
        errlog("interceptor joined")

    def _print_bufs(self):
        while not self._read_buf.empty():
            print("\n***** OUTPUT:\n", self._read_buf.get(), "\n*****\n")

    def is_flag_received(self):
        return self._interceptor_thread.is_flag_received()

    def stop(self):
        self._keep_running = False

DEFAULT_POLICY_FLAGS = {'ALLOW_V1': False, 'ALLOW_V2': True,
                        'REQUIRE_ENCRYPTION': True}

PROTOCOL = 'rook'
MMS = 1024  # TODO


class RookContext(potr.context.Context):
    def __init__(self, account, peer, other_id, send_method):
        super(RookContext, self).__init__(account, peer)
        self._send_method = send_method
        self.other_id = other_id

    def getPolicy(self, key):
        if key in DEFAULT_POLICY_FLAGS:
            return DEFAULT_POLICY_FLAGS[key]
        else:
            return False

    def inject(self, msg, appdata=None):
        errlog(">>> INJECT THINGS!")
        m = Message(server=False, cmd=CMD.SEND_OTR,
                    dest=self.other_id, content=msg)
        self._send_method(m.bytestring())

    def setState(self, newstate):
        # TODO possibly send feedback to the user here
        super(RookContext, self).setState(newstate)
        errlog("client set state: " + str(newstate))


class RookContextManager:
    def __init__(self, id, send_method):
        self.account = RookAccount(id)
        self.contexts = {}
        self._send_method = send_method

    def start_context(self, other_username, other_id):
        if other_username not in self.contexts:
            errlog("^^^ creating context:", self.account, other_username,
                   other_id)
            self.contexts[other_username] = RookContext(self.account,
                                                        other_username,
                                                        other_id,
                                                        self._send_method)
        return self.contexts[other_username]

    def get_context_for_user(self, other_username, other_id):
        return self.start_context(other_username, other_id)


class RookAccount(potr.context.Account):
    def __init__(self, id):
        global PROTOCOL, MMS
        super(RookAccount, self).__init__(id, PROTOCOL, MMS)

        # TODO better directory name?
        self.keyFilePath = os.path.join("./otr.private_key", id)

    def loadPrivkey(self):
        try:
            with open(self.keyFilePath, 'rb') as keyFile:
                errlog("loading private key!", keyFile)
                return potr.crypt.PK.parsePrivateKey(keyFile.read())[0]
        except IOError:
            pass
        return None

    def savePrivkey(self):
        try:
            with open(self.keyFilePath, 'wb') as keyFile:
                keyFile.wrte(self.getPrivkey().serializePrivateKey())
        except IOError:
            pass


class GatherThread(threading.Thread):
    def __init__(self, OTRClient):
        threading.Thread.__init__(self)
        self._client = OTRClient
        self._keep_running = True
        self._msg = "a" * 64

    def run(self):
        while self._keep_running:
            time.sleep(5)
            self._client._send_ciphertext(Message(server=False,
                                                  cmd=CMD.SEND_MESSAGE,
                                                  dest=self._client._user_to_id[s2bs(self._client._id)],
                                                  content=s2bs(self._msg)).bytestring())

    def stop(self):
        self._keep_running = False
        errlog("Stopping GatherThread")


# TODO: refactor some of these to an interface
class RookOTRClient(threading.Thread):

    def __init__(self, key, key_index, rook, id):
        threading.Thread.__init__(self)
        self._gather_thread = None
        self._key = key
        self._key_index = key_index
        self._rook = rook
        self._decipher = None
        self._id = id
        self._otr_manager = RookContextManager(self._id, self._send_ciphertext)
        self._io_thread = IO(self)
        self._status = Status.DISCONNECTED
        self._write_buf = rook._write_buf
        self._read_buf = rook._read_buf
        self._keep_running = True
        self._user_to_id = None
        self._id_to_user = None
        self._current_convo_id = None
        self._msg = Message()

    def run(self):
        self._io_thread.start()

        while (self._keep_running):
            time.sleep(1)
            if not self._status == Status.CONNECTED:
                self._pre_connection_methods()
            else:
                received = self._recv_ciphertext()
                if received is not None:
                    self._handle_msg(received)

    def _parse_user_list(self, msg):
        user_to_id = {}
        id_to_user = {}
        errlog("raw user list:", msg)
        for entry in split(msg, '\n'):
            name, i = split(entry, ' ')
            user_to_id[name] = i
            id_to_user[i] = name

        return user_to_id, id_to_user

    def print_user_list(self):
        if self._user_to_id is not None:
            print("*** USERS ***")
            for u in self._user_to_id:
                print("+", bs2s(u))

    def gather_data(self):
        if self._user_to_id is not None:
            if s2bs(self._id) in self._user_to_id:
                self._gather_thread = GatherThread(self)
                self._gather_thread.start()
            else:
                print("User", self._id, "not found in user list")
        else:
            print("Need a user list (type /list)")

    def _handle_msg(self, msg):
        actionable = False
        if not self._msg.complete:
            self._msg.add_more(msg)

            if self._msg.complete:
                actionable = True
                m = self._msg
        else:
            m = Message(message=msg)
            if m.complete:
                actionable = True
            else:
                self._msg = m

        if actionable:
            errlog("%%% server", m.server, "cmd", m.cmd, "content", m.content)
            if m.server:
                if m.cmd == CMD.USER_LIST:
                    self._user_to_id, self._id_to_user = self._parse_user_list(m.content)
                    self.print_user_list()
                elif m.cmd == CMD.CONVO_FAILED:
                    print("Conversation failed.")
                else:
                    print("Unrecognized Server Command")
            else:
                if m.cmd == CMD.SEND_MESSAGE:
                    if (m.dest in self._id_to_user and
                        self._id_to_user[m.dest] != self._id):
                        print(bs2s(self._id_to_user[m.dest]), ":",
                              bs2s(m.content))
                    else:
                        print("unkown:", m.content)
                elif m.cmd == CMD.SEND_OTR:
                    self._otr_recv(m)

    # TODO INTERFACE METHOD
    def _pre_connection_methods(self):
        if self._status == Status.CONNECTING:
            self._iv = Random.new().read(AES.block_size)
            errlog("key:", self._key)
            self._cipher = AES.new(self._key, AES.MODE_CFB, self._iv)
            errlog("sending Index!", self._key_index)
            self._send_plaintext(self._key_index)
            errlog("sending IV!", self._iv)
            self._send_plaintext(self._iv)
            self._status = Status.WAITING_FOR_FLAG
        elif self._status == Status.WAITING_FOR_FLAG:
            if self._rook.is_flag_received():
                errlog("sending ACK!", ACK_MSG)
                self._send_ciphertext(ACK_MSG)
                self._status = Status.WAITING_FOR_ACK
        elif self._status == Status.WAITING_FOR_ACK:
            if self._decipher is None:
                self._recv_iv()
            else:
                received = self._recv_ciphertext()
                if received is not None:
                    errlog("receiving ACK!", received)

                    # send username
                    m = Message(server=True, cmd=CMD.SET_USERNAME,
                                content=s2bs(self._id))

                    self._send_ciphertext(m.bytestring())
                    if received == ACK_MSG:
                        print("Connected!")
                        self._status = Status.CONNECTED

    # TODO INTERFACE METHOD
    def connect_to_server(self):
        if self._status == Status.DISCONNECTED:
            self._status = Status.CONNECTING
        else:
            print("not disconnected!")

    def restart_connection(self):
        if self._status == Status.CONNECTED:
            self._send_ciphertext(Message(server=True,
                                          cmd=CMD.DISCONNECT).bytestring())
        else:
            time.sleep(1)
            self._status = Status.CONNECTING

    def rename(self, name):
        if self._status == Status.CONNECTED:
            self._send_ciphertext(Message(server=True,
                                          cmd=CMD.SET_USERNAME,
                                          content=s2bs(name)).bytestring())
        else:
            print("must connect to a server first")

    # TODO INTERFACE METHOD
    def _recv_plaintext(self, raw=False):
        if not self._read_buf.empty():
            received_bytes = self._read_buf.get_nowait()
            if not raw:
                received_bytes = strip(received_bytes, PADDING_BYTE)

            return received_bytes

    # TODO INTERFACE METHOD
    def _recv_ciphertext(self, raw=False):
        r = self._recv_plaintext(raw=True)
        if r:
            r = self._decipher.decrypt(r)
            if not raw:
                r = strip(r, PADDING_BYTE)

            return r

    # TODO INTERFACE METHOD
    def _recv_iv(self):
        received = self._recv_plaintext(raw=True)
        if received:
            errlog(">>>>>>>>>>>> received iv:", received)
            self._decipher = AES.new(self._key, AES.MODE_CFB,
                                     received[:IV_LENGTH])

    # TODO INTERFACE METHOD
    def _send_plaintext(self, msg):
        processed_msg = process_msg(msg)
        for p in processed_msg:
            print("PLAINTEXT: ", p)
            self._write_buf.put(p)

    # TODO INTERFACE METHOD
    def _send_ciphertext(self, msg):
        processed_msg = process_msg(msg)
        for p in processed_msg:
            self._write_buf.put(self._cipher.encrypt(p))

    # TODO
    def send_server_message(self, msg):
        if self._status == Status.CONNECTED:
            self._send_ciphertext(Message(server=True, cmd=CMD.NONE,
                                          content=msg).bytestring())

        else:
            print("Please connect to a server first")

    def query_user_list(self):
        if self._status == Status.CONNECTED:
            self._send_ciphertext(Message(server=True,
                                          cmd=CMD.USER_LIST_QUERY)
                                  .bytestring())

        else:
            print("Please connect to a server first")

    def start_convo_with(self, name):
        print(name)
        if self._user_to_id is not None:
            if s2bs(name) in self._user_to_id:
                self._current_convo_id = self._user_to_id[s2bs(name)]
            else:
                print("User", name, "not found in user list")
        else:
            print("Need a user list (type /list)")

    # TODO INTERFACE METHOD
    def send_user_message(self, msg):
        if self._status == Status.CONNECTED:
            if (self._current_convo_id is not None):
                self._send_ciphertext(Message(server=False,
                                              cmd=CMD.SEND_MESSAGE,
                                              dest=self._current_convo_id,
                                              content=s2bs(msg)).bytestring())

        else:
            print("Please start a conversation with someone")

    # TODO INTERFACE METHOD
    def send_user_otr_message(self, msg):
        if self._status == Status.CONNECTED:
            if (self._current_convo_id is not None):
                self._otr_send(msg, self._id_to_user[self._current_convo_id])
        else:
            print("Please start a conversation with someone")

    # TODO INTERFACE METHOD
    def stop(self):
        errlog("RookOTRClient stopping")
        if self._gather_thread is not None:
            self._gather_thread.stop()
            self._gather_thread.join()

        if self._status == Status.CONNECTED:
            self._send_ciphertext(Message(server=True,
                                          cmd=CMD.DISCONNECT).bytestring())

            while(not self._write_buf.empty()):
                time.sleep(.01)

        self._rook.stop()
        self._keep_running = False

    def _otr_recv(self, msg):
        otrctx = self._otr_manager.get_context_for_user(self._id_to_user[msg.dest], msg.dest)
        encrypted = True

        try:
            res = otrctx.receiveMessage(msg.content)
        except potr.context.UnencryptedMessage:
            encrypted = False

        if not encrypted:
            print("OTR Message was not encrypted?!?", msg.content)
        else:
            if res[0] is not None:
                # handle decrypted message
                errlog("DECRYPTED: ", res[0], res)
                print(bs2s(self._id_to_user[msg.dest]), ":", bs2s(res[0]))

    def _otr_send(self, msg, username):
        otrctx = self._otr_manager.get_context_for_user(username,
                                                        self._current_convo_id)
        errlog("Context:", otrctx, otrctx.state, potr.context.STATE_ENCRYPTED)

        if otrctx.state == potr.context.STATE_ENCRYPTED:
            # this will encrypt and then call 'inject' on the encrypted message
            otrctx.sendMessage(0, s2bs(msg))
        else:
            print("querying to start OTR!")
            self._send_ciphertext(Message(server=False,
                                          cmd=CMD.SEND_OTR,
                                          dest=self._user_to_id[username],
                                          content=b'?OTRv2?')
                                  .bytestring())
