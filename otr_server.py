'''
Author: Paul Vines
'''

from Crypto import Random
import threading
import time
from pydivert.windivert import WinDivert
import socket
from utils import enum, PADDING_BYTE
import utils
from IO import IO
from queue import Queue
from StegoEngine import StegoSender, StegoReceiver, IV_LENGTH, make_blocks
from DummyParsers import DummyParser
from Packet import Packet
from message import Message, CMD, ACK_MSG, process_msg
from Byte import strip, i2b, b2i, s2bs
import Byte
import checksum
from Crypto.Cipher import AES
from utils import get_stun_mapping, is_stun, errlog
import configparser
import pickle as pkl


# ---///--- structs ---\\\---
def Client(write_buf, read_buf, stego_sender, stego_receiver, cur_msg, iv, key,
           cipher, decipher, username, id, ip, port, status, timestamp,
           recv_payloads, send_payloads):
    return utils.Bunch(write_buf=write_buf, read_buf=read_buf,
                       stego_sender=stego_sender,
                       stego_receiver=stego_receiver, cur_msg=cur_msg, iv=iv,
                       key=key, cipher=cipher, decipher=decipher,
                       username=username, id=id, ip=ip, port=port,
                       status=status, timestamp=timestamp,
                       recv_payloads=recv_payloads,
                       send_payloads=send_payloads)


def Inactive(id, ip, port, timestamp):
    return utils.Bunch(id=id, ip=ip, port=port, timestamp=timestamp)


def NewClient(id, ip, port):
    return utils.Bunch(id=id, ip=ip, port=port)


def Convo(client, id):
    return utils.Bunch(client=client, id=id)

Status = enum('WAITING_FOR_FLAG', 'WAITING_FOR_ACK', 'CONNECTED')


class RookServer():
    def __init__(self, config=None, utilization=1.0, packet_spacing=10,
                 seed=b'abcdefghijklmnop', server_spec=None, client_spec=None,
                 ip_addr=socket.gethostbyname(socket.gethostname()),
                 inbound_port='27015', keys={b'1':b'aaaaaaaaaaaaaaaa'},
                 packet_cap_start=500, packet_cap_end=2000):
        if config:
            c = configparser.ConfigParser()
            c.read(config)
            keys = {}
            for k, v in c.items('Keys'):
                keys[s2bs(k)] = s2bs(v)

            if c.has_option('Basic', 'server_spec'):
                send_spec = pkl.load(open(c.get('Basic', 'server_spec'), 'rb'))
            else:
                send_spec = None
            if c.has_option('Basic', 'server_spec'):
                recv_spec = pkl.load(open(c.get('Basic', 'client_spec'), 'rb'))
            else:
                recv_spec = None

            if c.has_option('Basic', 'packet_cap_start'):
                self._packet_cap_start = int(c.get('Basic', 'packet_cap_start'))
            else:
                self._packet_cap_start = 0

            if c.has_option('Basic', 'packet_cap_end'):
                self._packet_cap_end = int(c.get('Basic', 'packet_cap_end'))
            else:
                self._packet_cap_end = 0

            self._io_thread = IO(self)
            self._server_thread = RookOTRServer(keys=keys,
                                                utilization=c.getfloat('Basic', 'utilization'),
                                                seed=s2bs(c.get('Basic', 'seed')),
                                                send_spec=send_spec,
                                                recv_spec=recv_spec,
                                                packet_spacing=c.getint('Basic', 'packet_spacing'),
                                                packet_cap_start=self._packet_cap_start,
                                                packet_cap_end=self._packet_cap_end)

            self._interceptor_thread = InterceptorServer(utilization=c.getfloat('Basic', 'utilization'),
                                                         seed=s2bs(c.get('Basic', 'seed')),
                                                         send_spec=server_spec,
                                                         recv_spec=client_spec,
                                                         packet_spacing=c.getint('Basic', 'packet_spacing'),
                                                         inbound_port=c.get('Basic', 'inbound_port'),
                                                         ip_addr=ip_addr,
                                                         new_clients=self._server_thread._new_clients,
                                                         clients=self._server_thread._clients,
                                                         inactives=self._server_thread._inactives,
                                                         port_changes=self._server_thread._port_changes,
                                                         stun=c.getboolean('Basic', 'stun') )

            self._keep_running = True
        else:
            self._io_thread = IO(self)
            self._server_thread = RookOTRServer(keys=keys,
                                                utilization=utilization,
                                                seed=seed,
                                                send_spec=server_spec,
                                                recv_spec=client_spec,
                                                packet_spacing=packet_spacing,
                                                packet_cap_start=packet_cap_start,
                                                packet_cap_end=packet_cap_end)

            self._interceptor_thread = InterceptorServer(utilization=utilization,
                                                         seed=seed,
                                                         send_spec=server_spec,
                                                         recv_spec=client_spec,
                                                         packet_spacing=packet_spacing,
                                                         inbound_port=inbound_port,
                                                         ip_addr=ip_addr,
                                                         new_clients=self._server_thread._new_clients,
                                                         clients=self._server_thread._clients,
                                                         inactives=self._server_thread._inactives,
                                                         port_changes=self._server_thread._port_changes)
            self._keep_running = True

    def run(self):
        self._io_thread.start()
        self._server_thread.start()
        self._interceptor_thread.start()
        print("Started")
        while (self._keep_running):
            time.sleep(1)

        # clean up threads
        self._io_thread.stop()
        self._io_thread.join()
        errlog("io joined")
        self._server_thread.stop()
        self._server_thread.join()
        errlog("server joined")
        self._interceptor_thread.stop()
        self._interceptor_thread.join()
        errlog("interceptor joined")

    def stop(self):
        self._keep_running = False


class InterceptorServer(threading.Thread):

    def __init__(self, utilization, seed, send_spec, recv_spec, packet_spacing,
                 inbound_port, ip_addr, new_clients, clients, inactives,
                 port_changes, stun=True, packet_cap_start=500,
                 packet_cap_end=2000):
        threading.Thread.__init__(self)
        self._keep_running = True
        self._driver = WinDivert(r".\\lib\\1.0\\amd64\\WinDivert.dll")
        self._utilization = utilization
        self._seed = seed
        self._send_spec = send_spec
        self._recv_spec = recv_spec
        self._packet_spacing = packet_spacing
        self._inbound_port = inbound_port
        self._ip_addr = ip_addr
        self._new_clients = new_clients
        self._inactives = inactives
        self._clients = clients
        self._stun = stun
        self._port_changes = port_changes
        self._packet_cap_start = packet_cap_start
        self._packet_cap_end = packet_cap_end

    def run(self):
        if self._stun:
            self.run_stun()
        else:
            self.run_nonstun()

    def run_stun(self):
        errlog("starting")
        filter_string = "ip.SrcAddr == " + str(self._ip_addr) + " or " + " ip.DstAddr == " + str(self._ip_addr)
        handle = self._driver.open_handle(filter=filter_string, priority=1000)
        while self._keep_running:
            packet = handle.receive()

            try:
                if str(packet.src_addr) == self._ip_addr:
                    if not (packet.payload[0:4] == b'\xfe\xff\xff\xff'):

                        pid = str(packet.dst_addr) + str(packet.dst_port)

                        new_mapping, port = get_stun_mapping(packet.payload)
                        if new_mapping:
                            new_pid = str(packet.src_addr) + str(port)
                            if not pid == new_pid:
                                self._port_changes.put((pid, new_pid, port))

                        elif pid in self._clients:
                            packet.payload = self._clients[pid].stego_sender.insert(packet.payload)
                            self._driver.update_packet_checksums(packet)

                    handle.send(packet)

                elif str(packet.dst_addr) == self._ip_addr:

                    pid = str(packet.src_addr) + str(packet.src_port)

                    if not is_stun(packet.payload):
                        # handle inbound from known client
                        if pid in self._clients:
                            if not self._clients[pid].stego_receiver.extract(packet.payload):
                                handle.send(packet)


                        # handle inbound from known client that is not participating
                        elif pid in self._inactives:
                            handle.send(packet)

                        # inbound from new client
                        elif self._new_clients.empty():
                            self._new_clients.put(NewClient(id=pid, ip=packet.src_addr, port=packet.src_port))
                            handle.send(packet)
                    else:
                        handle.send(packet)

            except AttributeError:
                errlog("AttributeError")

    def run_nonstun(self):
        filter_string = "(ip.SrcAddr == " + str(self._ip_addr) + " or " + " ip.DstAddr == " + str(self._ip_addr) + ") and (udp.SrcPort == " + str(self._inbound_port) + " or udp.DstPort == " + str(self._inbound_port) + ")"
        handle = self._driver.open_handle(filter=filter_string, priority=1000)
        errlog("starting")
        while self._keep_running:
            packet = handle.receive()
            try:
                if str(packet.src_addr) == self._ip_addr:
                    pid = str(packet.dst_addr) + str(packet.dst_port)

                    if pid in self._clients:
                        c = self._clients[pid]
                        if c.stego_receiver is None or c.stego_sender is None:
                            c.send_payloads.append(packet.payload)
                            print(len(c.send_payloads), len(c.recv_payloads))

                        else:
                            altered = self._clients[pid].stego_sender.insert(packet.payload)
                            if altered != None:
                                packet.payload = altered
                                packet.payload = packet.payload[:9] + checksum.tf2_checksum(packet.payload[11:]) + packet.payload[11:]
                                self._driver.update_packet_checksums(packet)

                    handle.send(packet)

                elif str(packet.dst_addr) == self._ip_addr:

                    pid = str(packet.src_addr) + str(packet.src_port)

                    # handle inbound from known client
                    if pid in self._clients:
                        c = self._clients[pid]
                        if c.stego_receiver is None or c.stego_sender is None:
                            c.recv_payloads.append(packet.payload)
                            print(len(c.send_payloads), len(c.recv_payloads))
                        else:
                            self._clients[pid].stego_receiver.extract(packet.payload)

                    # handle inbound from known client that is not participating
                    elif pid in self._inactives:
                        x = 0

                    # inbound from new client
                    elif self._new_clients.empty():
                        self._new_clients.put(NewClient(id=pid, ip=packet.src_addr, port=packet.src_port))

                    handle.send(packet)

            except AttributeError:
                errlog("AttributeError")

    def stop(self):
        errlog("interceptor stopping!")
        self._keep_running = False


class RookOTRServer(threading.Thread):

    NEW_CLIENT_TIME = 100
    INACTIVE_TIME = 99999
    DISCONNECT_TIME = 1

    def __init__(self, keys, utilization, seed, send_spec, recv_spec,
                 packet_spacing, packet_cap_start, packet_cap_end):
        threading.Thread.__init__(self)
        self._keep_alive = True
        self._new_clients = Queue()
        self._clients = {}
        self._connecting_list = []
        self._inactives = []
        self._convos = {}
        self._clients_list = []
        self._keys = keys
        self._utilization = utilization
        self._seed = seed
        self._send_spec = send_spec
        self._recv_spec = recv_spec
        self._packet_spacing = packet_spacing
        self._port_changes = Queue()
        self._packet_cap_start = packet_cap_start
        self._packet_cap_end = packet_cap_end
        self._spec_building_list = []

    def run(self):
        while self._keep_alive:
            time.sleep(1)

            if not self._new_clients.empty():
                self._add_new_clients()

            for c in self._clients_list:
                if c == None:
                    continue
                elif c.status == Status.CONNECTED:
                    received_bytes = self.recv_ciphertext(c)
                    if received_bytes != None:
                        self._handle_msg(received_bytes, c)

            for c in self._spec_building_list:
                if c.stego_receiver is None and len(c.recv_payloads) > self._packet_cap_end + 50:
                    self._make_stego_recv(c)
                if c.stego_sender is None and len(c.send_payloads) > self._packet_cap_end + 50:
                    self._make_stego_send(c)

            for c in self._connecting_list:
                if c.status == Status.WAITING_FOR_FLAG:
                    if c.stego_receiver.flagged:
                        c.status = Status.WAITING_FOR_ACK
                        errlog("Saw Flag, sending IV!", c.iv)
                        self.send_plaintext(c, c.iv)
                    elif (time.time() - c.timestamp > self.NEW_CLIENT_TIME):
                        #errlog('inactivating', c.id)
                        self._move_to_inactive(c)

                elif c.status == Status.WAITING_FOR_ACK:
                    if c.key == None:
                        self._recv_index(c)
                    elif c.decipher == None:
                        self._recv_iv(c)
                    else:
                        received_string = self.recv_ciphertext(c)
                        if received_string != None:
                            errlog("receiving ACK!", received_string)
                            if received_string == ACK_MSG:
                                errlog("sending ACK!")
                                self.send_ciphertext(c, ACK_MSG)
                                errlog("Connected")
                                c.status = Status.CONNECTED
                                self._clients_list.append(c)
                                self._connecting_list.remove(c)
                        elif (time.time() - c.timestamp > self.NEW_CLIENT_TIME):
                            self._move_to_inactive(c)

            # Try old inactive clients again
            for i, inactive in enumerate(self._inactives):
                if time.time() - inactive.timestamp > self.INACTIVE_TIME:
                    self._new_clients.put(NewClient(inactive.id, inactive.ip, inactive.port))
                    self._inactives.pop(i)

            while not self._port_changes.empty():
                pid, new_pid, new_port = self._port_changes.get()
                if pid in self._clients:
                    c = self._clients[pid]
                    new_c = Client(c.write_buf, c.read_buf, c.stego_sender,
                                   c.stego_receiver, c.cur_msg, c.iv, c.key,
                                   c.cipher, c.decipher, c.username, c.id,
                                   c.ip, c.port, c.status, c.timestamp,
                                   recv_payloads=[], send_payloads=[])
                    self._clients[new_pid] = new_c
                    self._clients_list[self._clients_list.index(pid)] = new_c
                    self._clients.pop(pid)
                elif pid in self._inactives:
                    i = self._inactives[pid]
                    new_i = Inactive(id=i.id, ip=i.ip, port=c.port, timestamp=i.timestamp)
                    self._inactives[new_pid] = new_i
                    self._inactives.pop(pid)

    def _handle_msg(self, msg, c):
        errlog("received a message!", msg)
        actionable = False

        if not c.cur_msg.complete:
            c.cur_msg.add_more(msg)
            if c.cur_msg.complete:
                actionable = True
                m = c.cur_msg
        else:
            m = Message(message=msg)
            if m.complete:
                actionable = True
            else:
                c.cur_msg = m

        if actionable:
            if m.garbage:
                self._disconnect_client(c)
            elif m.server:
                if m.cmd == CMD.USER_LIST_QUERY:
                    errlog("list query!")
                    self.send_ciphertext(c, Message(server=True, cmd=CMD.USER_LIST, content=self._get_user_list()).bytestring())
                elif m.cmd == CMD.SET_USERNAME:
                    print("username set!", c.username, " is now", m.content)
                    c.username = m.content

                elif m.cmd == CMD.DISCONNECT:
                    self._disconnect_client(c)

            else:
                if m.cmd == CMD.SEND_MESSAGE:
                    self._handle_convo(m, c)
                elif m.cmd == CMD.SEND_OTR:
                    errlog("|||", m.dest, m.content)
                    self._handle_convo(m, c)
                elif m.cmd == CMD.START_CONVO:
                    self._handle_convo(m, c)

    def _handle_convo(self, msg, c):
        errlog("Convo ID:", c.username + msg.dest)
        if c.username + msg.dest not in self._convos:
            errlog("starting convo")
            self._start_convo(msg.dest, c)

        convo = self._convos[c.username + msg.dest]
        errlog("forwarding:", convo.client.id)
        self.send_ciphertext(convo.client, Message(server=False, cmd=msg.cmd, dest=convo.id, content=msg.content).bytestring())

    def _start_convo(self, desired_index, starter_client):
        other_client = self._clients_list[b2i(desired_index)]
        if other_client is not None:
            starter_index = i2b(self._clients_list.index(starter_client))
            self._convos[starter_client.username + desired_index] = Convo(other_client, starter_index)
            self._convos[other_client.username + starter_index] = Convo(starter_client, desired_index)
            errlog("all bytes?:", starter_client.username, desired_index, other_client.username, starter_index)
        else:
            self.send_ciphertext(starter_client, Message(server=True, cmd=CMD.CONVO_FAILED, content=desired_index).bytestring())

    def recv_plaintext(self, c, raw=False):
        if not c.read_buf.empty():
            received_bytes = c.read_buf.get_nowait()
            errlog("received_bytes:", received_bytes)
            if (not raw):
                received_bytes = strip(received_bytes, PADDING_BYTE)

            return received_bytes
        else:
            return None

    def recv_ciphertext(self, c, raw=False):
        r = self.recv_plaintext(c, raw=True)
        if r:
            r = c.decipher.decrypt(r)
            if (not raw):
                r = strip(r, PADDING_BYTE)

            return r
        else:
            return None

    def _recv_index(self, c):
        received = self.recv_plaintext(c)
        if received:
            if received in self._keys:
                c.key = self._keys[received]
                c.cipher = AES.new(c.key, AES.MODE_CFB, c.iv)

    def _recv_iv(self, c):
        received = self.recv_plaintext(c, raw=True)
        errlog("iv:", received)
        if received:
            c.decipher = AES.new(c.key, AES.MODE_CFB, received[:IV_LENGTH])

    def send_plaintext(self, c, msg):
        processed_msg = process_msg(msg)
        for p in processed_msg:
            errlog(">>>>>> sending", p)
            c.write_buf.put(p)

    def send_ciphertext(self, c, msg):
        processed_msg = process_msg(msg)
        for p in processed_msg:
            ep = c.cipher.encrypt(p)
            errlog("esending", ep)
            c.write_buf.put(ep)

    def stop(self):
        errlog("stopping OTRServer")
        self._keep_alive = False

    def _disconnect_client(self, c):
        print("Disconnecting", c.username)
        self._inactives.append(Inactive(id=c.id, ip=c.ip, port=c.port,
                                        timestamp=(time.time() - (
                                            self.INACTIVE_TIME - self.DISCONNECT_TIME))))
        self._clients.pop(c.id)
        self._clients_list[self._clients_list.index(c)] = None

    def _add_new_clients(self):
        while not self._new_clients.empty():
            c = self._new_clients.get_nowait()
            if str(c.ip) + str(c.port) not in self._clients:
                self._add_new_client(c.ip, c.port)

    def _add_new_client(self, ip, port):
        id = str(ip) + str(port)
        read_buf = Queue()
        write_buf = Queue()

        if self._send_spec is not None:
            stego_sender = StegoSender(self._seed, self._send_spec,
                                       self._utilization, self._packet_spacing, write_buf)
        else:
            stego_sender = None

        if self._recv_spec is not None:
            stego_receiver = StegoReceiver(self._seed, self._recv_spec,
                                           self._utilization, self._packet_spacing, read_buf)
        else:
            stego_receiver = None

        iv = self._iv = Random.new().read(AES.block_size)
        new_client = Client(write_buf, read_buf, stego_sender, stego_receiver,
                            cur_msg=Message(), iv=iv, key=None, cipher=None,
                            decipher=None, username=b"Anonymous",
                            id=str(ip) + str(port), ip=ip, port=port,
                            status=Status.WAITING_FOR_FLAG,
                            timestamp=time.time(), recv_payloads=[],
                            send_payloads=[])

        self._clients[id] = new_client
        if stego_sender is None or stego_receiver is None:
            self._spec_building_list.append(new_client)
        else:
            self._connecting_list.append(new_client)

    def _move_to_inactive(self, c):
        self._inactives.append(Inactive(id=c.id, ip=c.ip, port=c.port,
                                        timestamp=time.time()))
        self._clients.pop(c.id)
        self._connecting_list.remove(c)

    def _make_stego_send(self, c):
        print("Making send")
        parser = DummyParser(None, mode=Packet.SPEC, ngrams=1)
        counts = {}
        c.send_payloads = utils.trim_past_seq(c.send_payloads,
                                              seq=self._packet_cap_start)
        byte1 = Byte.bs2i(c.send_payloads[0][0:2], reverse_order=True)
        byte2 = Byte.bs2i(c.send_payloads[-1][0:2], reverse_order=True)
        print("Seq Range for Send:", byte1, "-", byte2)

        for p in c.send_payloads[:self._packet_cap_end - self._packet_cap_start]:
            parser.get_packet_type(p, blocks=None, counts=counts)

        send_filtered = make_blocks(counts)

        send_spec = DummyParser(send_filtered, Packet.BLOCKS)

        pkl.dump(send_spec, open("server_send.pkl", 'wb'))

        stego_sender = StegoSender(self._seed, send_spec,
                                   self._utilization, self._packet_spacing,
                                   c.write_buf)

        c.stego_sender = stego_sender

        if c.stego_receiver is not None:
            self._spec_building_list.remove(c)
            self._connecting_list.append(c)
            print("connecting?")

    def _make_stego_recv(self, c):
        print("Making recv")
        parser = DummyParser(None, mode=Packet.SPEC, ngrams=1)
        counts = {}
        print(type(c), type(c.recv_payloads))
        c.recv_payloads = utils.trim_past_seq(c.recv_payloads, seq=self._packet_cap_start)
        byte1 = Byte.bs2i(c.recv_payloads[0][0:2], reverse_order=True)
        byte2 = Byte.bs2i(c.recv_payloads[-1][0:2], reverse_order=True)
        print("Seq Range for Recv:", byte1, "-", byte2)
        for p in c.recv_payloads[:self._packet_cap_end - self._packet_cap_start]:
            parser.get_packet_type(p, blocks=None, counts=counts)

        recv_filtered = make_blocks(counts)

        recv_spec = DummyParser(recv_filtered, Packet.BLOCKS)

        pkl.dump(recv_spec, open("server_recv.pkl", 'wb'))

        stego_receiver = StegoReceiver(self._seed, recv_spec,
                                       self._utilization, self._packet_spacing,
                                       c.read_buf)

        c.stego_receiver = stego_receiver

        if c.stego_sender is not None:
            self._spec_building_list.remove(c)
            self._connecting_list.append(c)
            print("connecting?")

    def _get_user_list(self):
        s = b''
        for i,c in enumerate(self._clients_list):
            if c != None:
                if c.status == Status.CONNECTED and c.username != None:
                    s += c.username + b" " + i2b(i) + b'\n'

        return s
