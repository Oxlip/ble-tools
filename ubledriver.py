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
        self.sock.send(self.data)

        while res['connected'] is None:
            time.sleep(1)

        return False if not res['connected'] else res


    def __init__(self, umsg, to, sock, driver):
        super(uBlePacketSend, self).__init__()
        self.umsg     = umsg
        self.mac_to   = to
        self.sock     = sock
        self.driver   = driver

    def connect(self):
        return self._connect()

class uBlePacketRecv(datahelper.DataReader):

    event_types = {
        0x0f : 'cmd_status',
        0x3e : 'le_meta'
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

    def _parse(self):
        pkt_type = self.get_ubyte()
        if not pkt_type == 0x04:
            logging.error('Recv packet non hci event')
            return

        self.event_type = self.get_ubyte()
        self.param_len  = self.get_ubyte()

        if not self.event_type in self.event_types:
            logging.error('Event %s not implemented', hex(self.event_type))
            return

        self._call(self.event_types[self.event_type])

    def get_mac(self):
        mac = []
        for count in range(6):
           mac.insert(0, self.get_ubyte())
        return mac



class uBleDriver(udriver.uDriver):

    _clients     = {}
    _cmd_waiting = {}

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

#        err = bluez.hci_le_set_scan_parameters(self._sock.fileno(),
#                                               0,
#                                               0x10,
#                                               0x10,
#                                               0,
#                                               0,
#                                               1000)
#        if err < 0:
#            logging.error('Unable to setup bluetooth')
#            return
#
#        self._sock.setsockopt(socket.SOL_HCI,
#                              socket.HCI_FILTER,
#                              self._hci_filter)
#
#        err = bluez.hci_le_set_scan_enable(self._sock.fileno(),
#                                           1,
#                                           0,
#                                           1000)
#        if err < 0:
#            logging.error('Unable to run the scan: %s',
#                          os.strerror(errnum))
#            return
        self._is_init = True

    def _run(self, _, __):
        if not self.is_init():
            logging.error('_run: driver not init')
            return
        while True:
            blepacket = uBlePacketRecv(self._sock.recv(4096), self)

    def run(self):
        thread.start_new_thread(self._run, (1, 1))


    def new_client(self, mac, name):
        if name in self._clients:
            return
        self._clients[name] = { 'mac' : mac, 'identification' : None }
        logging.info('new client nammed: %s', name)


    def register_cmd(self, cmd, callback, data):
        self._cmd_waiting[cmd] = (callback, data)

    def notify_cmd_status(self, cmd, status, packet):
        callback, data = self._cmd_waiting[cmd]
        del self._cmd_waiting[cmd]
        callback(status, data, packet)

    def send_umsg(self, umsg):
        blepacket = uBlePacketSend(umsg,
                                   [ 0xea, 0x2a, 0xc2, 0x72, 0xed, 0x89 ],
                                   self._sock,
                                   self)
        result = blepacket.connect()
        print "Connection: {}".format(result)
