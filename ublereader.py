import os
import sys
import struct
import ureader
import logging
import socket
import ctypes
import ctypes.util

class DataParser(object):

    def __init__(self, data):
        self.data = data
        self.pos  = 0

    def get_ubyte(self):
        (res,) = struct.unpack('>B', self.data[self.pos : self.pos + 1])
        self.pos += 1
        return res

    def get_ushort(self):
        (res,) = struct.unpack('>H', self.data[self.pos : self.pos + 2])
        self.pos += 2
        return res

    def get_uint(self):
        (res,) = struct.unpack('>I', self.data[self.pos : self.pos + 4])
        self.pos += 4
        return res

    def get_int(self):
        (res,) = struct.unpack('>i', self.data[self.pos : self.pos + 4])
        self.pos += 4
        return res

    def get_data(self, size):
        res = self.data[self.pos : self.pos + size]
        self.pos += size
        return res

    def get_mac(self):
        mac = []
        for count in range(6):
           mac.insert(0, self.get_ubyte())
        return mac

class uBlePacket(DataParser):

    event_types = {
        0x3e : 'le_meta'
    }

    def __init__(self, raw):
        super(uBlePacket, self).__init__(raw)
        self._parse()

    def _call(self, msg):
        getattr(self, '_parse_' + msg)()


    def _parse_le_meta(self):
        self.sub_event = self.get_ubyte()

        if self.sub_event == 0x02:
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
                print '[{type}][{len}][{data}]'.format(data = data,
                                                       type = data_type,
                                                       len  = data_len)
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
            logging.error('Event %x not implemented')
            return

        self._call(self.event_types[self.event_type])
        

class uBleReader(ureader.uReader):

    _hci_filter = struct.pack("<IQH",
                              0x00000010,
                              0x4000000000000000,
                              0)

    def __init__(self):
        super(uBleReader, self).__init__('uBleReader')

    def open(self):
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
        self._sock.bind((self._dev,))

        err = bluez.hci_le_set_scan_parameters(self._sock.fileno(),
                                               0,
                                               0x10,
                                               0x10,
                                               0,
                                               0,
                                               1000)
        if err < 0:
            logging.error('Unable to setup bluetooth')
            return

        self._sock.setsockopt(socket.SOL_HCI,
                              socket.HCI_FILTER,
                              self._hci_filter)

        err = bluez.hci_le_set_scan_enable(self._sock.fileno(),
                                           1,
                                           0,
                                           1000)
        if err < 0:
            logging.error('Unable to run the scani: %s',
                          os.strerror(errnum))
            return
        self._is_open = True

    def close(self):
        pass

    def receiv_packet(self):
        if not self.is_open():
            logging.error('receiv_packet: blereader not open')
            return
        blepacket = uBlePacket(self._sock.recv(1024))

    def send_packet(self, upacket):
        pass
