import os
import sys
import struct
import udriver
import logging
import datahelper
import socket
import ctypes
import ctypes.util

class uBlePacketSend(datahelper.DataWriter):

    def __init__(self, umsg):
        super(uBlePacketSend, self).__init__()
        self.umsg = umsg

class uBlePacketRecv(datahelper.DataReader):

    event_types = {
        0x3e : 'le_meta'
    }

    def __init__(self, raw):
        super(uBlePacketRecv, self).__init__(raw)
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
                macstr = ':'.join(chr(c).encode('hex') for c in mac)
                print '[LE adv][{mac}][{data}]'.format(data = data, mac = macstr)
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

    def get_mac(self):
        mac = []
        for count in range(6):
           mac.insert(0, self.get_ubyte())
        return mac

    

class uBleDriver(udriver.uDriver):

    _hci_filter = struct.pack("<IQH",
                              0x00000010,
                              0x4000000000000000,
                              0)

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
        self._is_init = True

    def run(self):
        if not self.is_init():
            logging.error('receiv_packet: blereader not open')
            return
        #should be running in thread/gevent
        blepacket = uBlePacketRecv(self._sock.recv(1024))

    def send_umsg(self, umsg):
        blepacket = uBlePacketSend(umsg)
