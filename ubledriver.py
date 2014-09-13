import os
import sys
import struct
import udriver
import logging
import datahelper
import socket
import ctypes
import thread
import time
import ctypes.util

class uBleType(object):

    PKT_TYPE_HCI_CMD       = 0x1

    CMD_OPCODE_CREATE_CONN = 0x200d

class uBlePacketSend(datahelper.DataWriter):

    def write(self, handle, handle_target, value):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(9)
        self.set_ushort(5)
        self.set_ushort(4)
        self.set_ubyte(0x12)
        self.set_ushort(handle_target)
        self.set_ushort(1)
        self.send()

    def get_charrac(self, handle, char_handle):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(7)
        self.set_ushort(3)
        self.set_ushort(4)
        self.set_ubyte(0xa)
        self.set_ushort(char_handle)
        self.send()

    def find_info(self, handle):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(9)
        self.set_ushort(5)
        self.set_ushort(4)
        self.set_ubyte(0x4)
        self.set_ushort(0x0009)
        self.set_ushort(0xffff)
        self.send()

    def get_charrac_dec(self, handle, char_handle):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(11)
        self.set_ushort(7)
        self.set_ushort(4)
        self.set_ubyte(0xa)
        self.set_ushort(char_handle)
        self.set_ushort(0x2901)
        self.sock.send(self.data)
        self.data = ''

    def get_charrac_gatt(self, handle):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(11)
        self.set_ushort(7)
        self.set_ushort(4)
        self.set_ubyte(0x8)
        self.set_ushort(0x0001)
        self.set_ushort(0xffff)
        self.set_ushort(0x2803)
        self.sock.send(self.data)
        self.data = ''

    def get_service(self, handle, handle_target):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(9)
        self.set_ushort(5)
        self.set_ushort(4)
        self.set_ubyte(0x8)
        self.set_ushort(handle_target)


    def disconnect(self, handle):
        self.set_ubyte(uBleType.PKT_TYPE_HCI_CMD)
        self.set_ushort(0x0406)
        self.set_ubyte(0x03)
        self.set_ushort(handle)
        self.set_ubyte(0x13)
        self.send()

    def get_services(self, handle, hfrom = 0x0001):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(11)
        self.set_ushort(7)
        self.set_ushort(4)
        self.set_ubyte(0x10)
        self.set_ushort(hfrom)
        self.set_ushort(0xffff)
        self.set_ushort(0x2800)

        res = {}
        res['ended'] = None
        res['result'] = []

        def result(packet, data):
            if packet.opcode == 0x11:
                data['result'].append(packet.attributes)
                _, end, __ = packet.attributes[-1]
                if not end == 0xFFFF:
                    res = self.get_services(packet.handle, hfrom = end + 1)
                    data['result'] = data['result'] + res
            data['ended'] = True

        self.driver.register_handle(handle,
                                    result,
                                    res)

        self.send()

        while res['ended'] is None:
            time.sleep(1)

        return res['result']


    def _connect(self):
        self.set_ubyte(uBleType.PKT_TYPE_HCI_CMD)
        self.set_ushort(uBleType.CMD_OPCODE_CREATE_CONN)
        param = datahelper.DataWriter()
        param.set_ushort(0x0060) #scan interval
        param.set_ushort(0x0030) #scan window
        param.set_ubyte(0x0)     #Initiator Filter
        param.set_ubyte(0x1)     #Peer Address

        for index in range(6):
            param.set_ubyte(self.mac_to[5 - index])

        param.set_ubyte(0x0)     #Onw Address type
        param.set_ushort(0x0028) #Conn Inter Min
        param.set_ushort(0x0038) #Conn Inter Max
        param.set_ushort(0x0000) #Conn Lat
        param.set_ushort(0x002a) #Supervision Timeout
        param.set_ushort(0x0000) #Min CE Len
        param.set_ushort(0x0000) #Max CE Len

        self.set_ubyte(len(param.data))
        self.set_data(param.data)

        res = {}
        res['connected'] = None

        def result(status, data, packet):
            if status == 0x0 and packet.event_type == 0x0F:
                self.driver.register_cmd(uBleType.CMD_OPCODE_CREATE_CONN,
                                         result,
                                         data)
            elif packet.event_type == 0x3e and  packet.sub_event == 0x01:
                data['handle'] = packet.handle
                data['packet'] = packet
                data['connected'] = True
            else:
                logging.error('Command Disallowed')
                data['connected'] = False


        self.driver.register_cmd(uBleType.CMD_OPCODE_CREATE_CONN,
                                 result,
                                 res)
        self.send()

        while res['connected'] is None:
            time.sleep(1)

        return False if not res['connected'] else res


    def __init__(self, umsg, to, sock, driver):
        super(uBlePacketSend, self).__init__()
        self.umsg     = umsg
        self.mac_to   = to
        self.sender   = sock
        self.driver   = driver

    def connect(self):
        return self._connect()

class uBlePacketRecv(datahelper.DataReader):

    event_types = {
        0x0f : 'cmd_status',
        0x3e : 'le_meta'
    }

    packet_types = {
        0x11 : 'read_by_group'
    }

    def __init__(self, raw, driver):
        super(uBlePacketRecv, self).__init__(raw)
        self._driver = driver
        self._parse()

    def _call(self, msg):
        getattr(self, '_parse_' + msg)()


    def _parse_cmd_status(self):
        status = self.get_ubyte()
        self.get_ubyte()
        cmd    = self.get_ushort()
        self._driver.notify_cmd_status(cmd, status, self)

    def _parse_le_meta(self):
        self.sub_event = self.get_ubyte()

        if self.sub_event == 0x01:
            self.status = self.get_ubyte()
            self.handle = self.get_ushort()
            # some stuff remaining
            self._driver.notify_cmd_status(uBleType.CMD_OPCODE_CREATE_CONN,
                                           self.status,
                                           self)
        elif self.sub_event == 0x02:
            num_report = self.get_ubyte()
            for rep_n in range(num_report):
                ev_type   = self.get_ubyte()
                pa_type   = self.get_ubyte()
                mac       = self.get_mac()
                ev_len    = self.get_ubyte()
                data_len  = self.get_ubyte()
                data_type = self.get_ubyte()
                data      = self.get_data(data_len - 1)
                self.get_ubyte()
                self._driver.new_client(mac, data)
        else:
            logging.error('LE meta sub event not impl %x',
                          self.sub_event)
            return


    def _parse_event(self):
        self.event_type = self.get_ubyte()
        self.param_len  = self.get_ubyte()

        if not self.event_type in self.event_types:
            logging.error('Event %s not implemented', hex(self.event_type))
            return

        self._call(self.event_types[self.event_type])


    def _parse_packet(self):
        self.handle = self.get_ubyte() # ? Handle must be on 0xFFFF
        self.flags  = self.get_ubyte()
        self.data_total_len = self.get_ushort()
        self.data_len = self.get_ushort()
        self.cid = self.get_ushort()
        self.opcode = self.get_ubyte()

        if not self.opcode in self.packet_types:
            logging.error('Opcode %s not implemented', hex(self.opcode))
            return

        self._call(self.packet_types[self.opcode])


    def _parse_read_by_group(self):
        self.att_len = self.get_ubyte()
        self.attributes = []
        while self.get_len() >= self.att_len:
           handle = self.get_ushort()
           handle_end = self.get_ushort()
           value  = self.get_ushort()
           self.attributes.append((handle, handle_end, value))
        self._driver.notify_handle_status(self.handle, self)

    def _parse(self):
        pkt_type = self.get_ubyte()
        if pkt_type == 0x04:
            self._parse_event()
        elif pkt_type == 0x02:
            self._parse_packet()
        else:
            logging.error('Recv packet non hci event')
            return

    def get_mac(self):
        mac = []
        for count in range(6):
           mac.insert(0, self.get_ubyte())
        return mac



class uBleDriver(udriver.uDriver):

    _clients        = {}
    _cmd_waiting    = {}
    _handle_waiting = {}

    def __init__(self):
        super(uBleDriver, self).__init__('uBleReader')

    def init(self):
        btlib = ctypes.util.find_library('bluetooth')
        if not btlib:
            logging.error('Need to install \'bluez\' lib')
            return

        bluez  = ctypes.CDLL(btlib, use_errno = True)
        self._dev = bluez.hci_get_route(None)
        if self._dev == -1:
            logging.warning('No bluetooth device available')
            return

        self._sock = socket.socket(socket.AF_BLUETOOTH,
                                   socket.SOCK_RAW,
                                   socket.BTPROTO_HCI)
        self._sock.setsockopt(socket.SOL_HCI,
                              socket.HCI_FILTER,
                              struct.pack("IIIh2x", 0xffffffffL,0xffffffffL,0xffffffffL,0))
        self._sock.bind((self._dev,))

        self._is_init = True


###############################################################################
#   Callback from recv packets
###############################################################################

    def new_client(self, mac, name):
        if name in self._clients:
            return
        self._clients[name] = { 'mac' : mac, 'identification' : None }
        logging.info('new client nammed: %s', name)


    def register_cmd(self, cmd, callback, data):
        self._cmd_waiting[cmd] = (callback, data)


    def notify_cmd_status(self, cmd, status, packet):
        if cmd not in self._cmd_waiting:
            logging.info('recv status %x for %x, but nobody have register')
            return
        callback, data = self._cmd_waiting[cmd]
        del self._cmd_waiting[cmd]
        callback(status, data, packet)


    def register_handle(self, handle, callback, data):
        self._handle_waiting[handle] = (callback, data)


    def notify_handle_status(self, handle, packet):
        callback, data = self._handle_waiting[handle]
        del self._handle_waiting[handle]
        thread.start_new_thread(callback, (packet, data))

###############################################################################
#   API
###############################################################################

    def _run(self, _, __):
        if not self.is_init():
            logging.error('_run: driver not init')
            return
        while True:
            blepacket = uBlePacketRecv(self._sock.recv(4096), self)


    def run(self):
        thread.start_new_thread(self._run, (1, 1))


    def send_umsg(self, umsg):
        blepacket = uBlePacketSend(umsg,
                                   [ 0xea, 0x2a, 0xc2, 0x72, 0xed, 0x89 ],
                                   self._sock,
                                   self)
        result  = blepacket.connect()
        if not result:
            return
        services = blepacket.get_services(result['handle'])
        print services
        blepacket.disconnect(result['handle'])
