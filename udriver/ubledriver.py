import os
import sys
import json
import struct
import udriver
import logging
import progressbar
import datahelper
import socket
import ctypes
import thread
import time
import ctypes.util
import bleevent

class BleUUID(object):

    DEVINCE_NAME = 0x2A00

    UDEVICE        = '\xC0\xF4\x10\x00\x93\x24\x40\x85\xAB\xA0\x09\x02\xC0\xE8\x95\x0A'
    UDEVICE_INFOS  = '\xC0\xF4\x10\x01\x93\x24\x40\x85\xAB\xA0\x09\x02\xC0\xE8\x95\x0A'
    UDEVICE_OUTLET = '\xC0\xF4\x10\x02\x93\x24\x40\x85\xAB\xA0\x09\x02\xC0\xE8\x95\x0A'
    UDEVICE_SENSOR = '\xC0\xF4\x10\x03\x93\x24\x40\x85\xAB\xA0\x09\x02\xC0\xE8\x95\x0A'

    DFU            = '\xC0\xF4\x16\x64\x93\x24\x40\x85\xAB\xA0\x09\x02\xC0\xE8\x95\x0A'
    DFU_PACKET     = '\xC0\xF4\x16\x65\x93\x24\x40\x85\xAB\xA0\x09\x02\xC0\xE8\x95\x0A'
    DFU_CONTROLE   = '\xC0\xF4\x16\x66\x93\x24\x40\x85\xAB\xA0\x09\x02\xC0\xE8\x95\x0A'

    knowed_uuid = {
        DEVINCE_NAME : 'DEVINCE_NAME',
        UDEVICE : 'uDevice',
        UDEVICE_INFOS  : 'uDevice Infos',
        UDEVICE_OUTLET : 'uDevice Outlet',
        UDEVICE_SENSOR : 'uDevice Sensor',
    }

    def __init__(self, raw):
        self.raw = raw

    def is_know(self):
        return self.raw in self.knowed_uuid

    def __repr__(self):
        if self.is_know():
            return self.knowed_uuid[self.raw]
        try:
            len(self.raw)
            uuidt = []
            uuidd = datahelper.DataReader(self.raw)
            for count in range(len(self.raw) / 2):
                uuidt.append(uuidd.get_ushort())
            uuid_fmt = '{0:04X}{1:04X}-{2:04X}-{3:04X}-{4:04X}-{5:04X}{6:04X}{7:04X}'
            return uuid_fmt.format(uuidt[0],
                                   uuidt[1],
                                   uuidt[2],
                                   uuidt[3],
                                   uuidt[4],
                                   uuidt[5],
                                   uuidt[6],
                                   uuidt[7])
        except:
            return '{uuid}'.format(uuid = hex(self.raw))

class uBleDest(object):

    def __init__(self, mac):
        self.mac = mac

class uBleType(object):

    PKT_TYPE_HCI_CMD       = 0x1

    CMD_OPCODE_CREATE_CONN = 0x200d

class uBlePacketSend(datahelper.DataWriter):

    def write_ubyte_value(self, handle, handle_target, value, write_type = 0x12):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(8)
        self.set_ushort(4)
        self.set_ushort(4)
        self.set_ubyte(write_type)
        self.set_ushort(handle_target)
        self.set_ubyte(value)
        self.send()
        if write_type == 0x12:
            time.sleep(2)

    def write_ushort_value(self, handle, handle_target, value, write_type = 0x12):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(9)
        self.set_ushort(5)
        self.set_ushort(4)
        self.set_ubyte(write_type)
        self.set_ushort(handle_target)
        self.set_ushort(value)
        self.send()
        if write_type == 0x12:
            time.sleep(1)

    def write_uint_value(self, handle, handle_target, value, write_type = 0x12):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(11)
        self.set_ushort(7)
        self.set_ushort(4)
        self.set_ubyte(write_type)
        self.set_ushort(handle_target)
        self.set_uint(value)
        self.send()
        if write_type == 0x12:
            time.sleep(1)


    def write_data_value(self, handle, handle_target, value, write_type = 0x12):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(len(value) + 7)
        self.set_ushort(len(value) + 3)
        self.set_ushort(4)
        self.set_ubyte(write_type)
        self.set_ushort(handle_target)
        self.set_data(value)
        self.send()
        if write_type == 0x12:
            time.sleep(1)


    def find_info(self, handle, hfrom = 0x0001):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(9)
        self.set_ushort(5)
        self.set_ushort(4)
        self.set_ubyte(0x4)
        self.set_ushort(hfrom)
        self.set_ushort(0xffff)

        res = {}
        res['ended'] = None
        res['attributes'] = []

        def result(packet, data):
            if packet.opcode == 0x5:
                data['attributes'] += packet.attributes
                data['attributes'] += self.find_info(packet.handle, packet.attributes[-1][0] + 1)
            data['ended'] = True

        self.driver.register_handle(handle,
                                    result,
                                    res)

        self.send()

        while res['ended'] is None:
            time.sleep(.1)

        return res['attributes']




    def read_value(self, handle, char_handle):
        self.set_ubyte(0x02)
        self.set_ushort(handle)
        self.set_ushort(7)
        self.set_ushort(3)
        self.set_ushort(4)
        self.set_ubyte(0xa)
        self.set_ushort(char_handle)

        res = {}
        res['ended'] = None
        res['value'] = None

        def result(packet, data):
            if packet.opcode == 0xb:
                data['value'] = packet.value
            data['ended'] = True

        self.driver.register_handle(handle,
                                    result,
                                    res)

        self.send()

        while res['ended'] is None:
            time.sleep(.1)

        return res['value']

    def get_char_for_group(self, handle, begin, end, uuid = 0x2803, get_err = False):
        self.set_ubyte(0x02)
        self.set_ushort(handle)

        param = datahelper.DataWriter()
        param.set_ubyte(0x8)
        param.set_ushort(begin)
        param.set_ushort(end)
        if uuid == 0x2803:
            param.set_ushort(0x2803)
        else:
            param.set_data(uuid[::-1])

        self.set_ushort(len(param.data) + 4)
        self.set_ushort(len(param.data))
        self.set_ushort(4)
        self.set_data(param.data)

        res = {}
        res['ended'] = None
        res['result'] = []

        def result(packet, data):
            if packet.opcode == 0x9:
                data['result'].append(packet.attributes)
            elif get_err:
                data['result'] = packet
            data['ended'] = True

        self.driver.register_handle(handle,
                                    result,
                                    res)

        self.send()

        while res['ended'] is None:
            time.sleep(.1)

        return res['result']


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
            time.sleep(.1)

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

        self.send()

        opt = { 'handle' : uBleType.CMD_OPCODE_CREATE_CONN }
        bleevent.wait_for_event(options = opt, debug = True)


        self.disconnect()
        sys.exit(1)
        return False


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
        0x11 : 'read_by_group',
        0x09 : 'read_by_type',
        0x0b : 'read',
        0x05 : 'find_info'
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
        bleevent.manager.notify(self)
        self._driver.notify_cmd_status(cmd, status, self)

    def _parse_le_meta(self):
        self.sub_event = self.get_ubyte()

        if self.sub_event == 0x01:
            self.status = self.get_ubyte()
            self.handle = self.get_ushort()
            # some stuff remaining
            bleevent.manager.notify(self)
            self._driver.notify_cmd_status(uBleType.CMD_OPCODE_CREATE_CONN,
                                           self.status,
                                           self)
        elif self.sub_event == 0x02:
            data = ''
            num_report = self.get_ubyte()
            for rep_n in range(num_report):
                ev_type   = self.get_ubyte()
                pa_type   = self.get_ubyte()
                mac       = self.get_mac()
                ev_len    = self.get_ubyte()
                data_len  = self.get_ubyte()
                if data_len != 0:
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
            logging.info('Event %s not implemented', hex(self.event_type))
            return

        self._call(self.event_types[self.event_type])


    def _parse_packet(self):
        self.handle = self.get_ubyte() # ? Handle must be on 0xFFFF
        self.flags  = self.get_ubyte()
        self.data_total_len = self.get_ushort()
        self.data_len = self.get_ushort()
        self.cid = self.get_ushort()
        self.opcode = self.get_ubyte()

        if self.opcode == 0x01:
            self._driver.notify_handle_status(self.handle, self)
            return
        elif self.opcode == 0x1B:
            self._driver.notify_handle_status(self.handle, self)
            return
        elif not self.opcode in self.packet_types:
            logging.info('Opcode %s not implemented', hex(self.opcode))
            return


        self._call(self.packet_types[self.opcode])


    def _parse_read(self):
        self.value_len = self.data_len - 1
        self.value = self.get_data(self.value_len)
        self._driver.notify_handle_status(self.handle, self)

    def _parse_find_info(self):
        self.uuid_type = self.get_ubyte()
        self.attributes = []
        while self.get_len() != 0:
            handle = self.get_ushort()
            if self.uuid_type == 0x1:
                uuid = BleUUID(self.get_ushort())
            else:
                uuid = BleUUID(self.get_data(16)[::-1])
            self.attributes.append((handle, uuid))
        self._driver.notify_handle_status(self.handle, self)

    def _parse_read_by_type(self):
        self.att_len = self.get_ubyte()
        self.attributes = []
        while self.get_len() >= self.att_len:
           handle = self.get_ushort()
           value  = self.get_data(self.att_len - 2)
           self.attributes.append((handle, value))
        self._driver.notify_handle_status(self.handle, self)


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
            logging.info('Recv packet non hci event')
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

    def value_to_char_fmt(self, value_raw):

        att_len = len(value_raw)

        value = datahelper.DataReader(value_raw)
        data   = {
            'flags' : value.get_ubyte(),
            'handle': value.get_ushort()
        }
        if value.get_len() == 2:
            data['uuid'] = BleUUID(value.get_ushort())
        else:
            data['uuid'] = BleUUID(value.get_data(value.get_len())[::-1])

        return data


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
        if handle not in self._handle_waiting:
            logging.info('recv status %x for %x, but nobody have register')
            return
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

    def _act_discovery(self, result, blepacket):
        gp_services = blepacket.get_services(result['handle'])

        for services  in gp_services:
            for begin, end, value in services:
                chars = blepacket.get_char_for_group(result['handle'],
                                                     begin,
                                                     end)
                if len(chars) == 0:
                    continue
                for _, char in chars[0]:
                    char = self.value_to_char_fmt(char)
                    if char['uuid'].is_know():
                        value = blepacket.read_value(result['handle'],
                                                     char['handle'])
                        logging.warning('{uuid}: {value}'.format(uuid = char['uuid'],
                                                                 value = value))


    def _act_infos(self, umsg, result, blepacket):
        infos = blepacket.find_info(result['handle'])

        board = { 'services' : [] }

        service = None

        for info in infos:
            infojson = { 'handle' : info[0], 'uuid' : repr(info[1]) }
            if info[1].raw == 0x2800:
                if service is not None:
                    board['services'].append(service)
                infojson['char'] = []
                service = infojson
                char = None
            elif info[1].raw == 0x2803:
                service['char'].append(infojson)
                char = infojson
                char['value'] = None
                char['desc'] = []
            elif info[1].raw == 0x2902:
                char['desc'].append(infojson)
            else:
                char['value'] = infojson
        board['services'].append(service)
        print json.dumps(board, sort_keys=True, indent=4)


    _dest_available = {
        '#fake_serial' : uBleDest([ 0xea, 0x2a, 0xc2, 0x72, 0xed, 0x89 ])
    }

    def _get_dest_info(self, dest_id):
        if not dest_id in self._dest_available:
            return None
        return self._dest_available[dest_id]

    def _act_outlet_get_power(self, umsg, result, blepacket):
        handle = result['handle']
        outlet_pkt = blepacket.get_char_for_group(handle,
                                                  0x0001,
                                                  0xFFFF,
                                                  uuid = BleUUID.UDEVICE_OUTLET,
                                                  get_err = True)

        #enable notif
        outlet_handle = outlet_pkt[0][0][0]
        blepacket.write_ushort_value(handle, outlet_handle + 1, 0x0001)
        blepacket.write_ushort_value(handle, outlet_handle, 0x0001)

        time.sleep(2)

    def _act_dfu(self, umsg, result, blepacket):
        time.sleep(1)
        handle = result['handle']
        dfu_ctrl = blepacket.get_char_for_group(result['handle'],
                                                0x0001,
                                                0xFFFF,
                                                uuid = BleUUID.DFU_CONTROLE,
                                                get_err = True)
        dfu_pkt = blepacket.get_char_for_group(result['handle'],
                                               0x0001,
                                               0xFFFF,
                                               uuid = BleUUID.DFU_PACKET,
                                               get_err = True)

        # We are not able to read, but the handle is in error responce :)
        dfu_pkt.get_ubyte()
        dfu_pkt_handle = dfu_pkt.get_ushort()
        dfu_ctrl.get_ubyte()
        dfu_ctrl_handle = dfu_ctrl.get_ushort()

        # Enable notification
        blepacket.write_ushort_value(handle, dfu_ctrl_handle + 1, 0x0001)

        # Setup wait for notification
        res = {}
        res['received'] = None
        def wait_for_notif(packet, data):
            data['handle'] = packet.get_ushort()
            data['reqoc'] = packet.get_ubyte()
            data['repoc'] = packet.get_ubyte()
            data['value'] = packet.get_ubyte()
            if packet.get_len() == 1:
                data['data'] = packet.get_ubyte()
            elif packet.get_len() == 2:
                data['data'] = packet.get_ushort()
            elif packet.get_len() == 4:
                data['data'] = packet.get_uint()
            data['received'] = True

        self.register_handle(handle, wait_for_notif, res)

        # Start dfu
        param = datahelper.DataWriter()
        param.set_ubyte(0x01)
        param.set_ubyte(0x04)
        blepacket.write_data_value(handle, dfu_ctrl_handle, param.data)


        # Write bin size
        param = datahelper.DataWriter()
        param.set_uint(0x00)
        param.set_uint(0x00)
        param.set_uint(umsg['file_size'])
        blepacket.write_data_value(handle, dfu_pkt_handle, param.data, 0x52)



        # Wait for notification
        while res['received'] is None:
            time.sleep(.01)

        if res['value'] != 0x01:
            logging.error('Size not validated validated [%d][%d][%d]',
                          res['reqoc'],
                          res['repoc'],
                          res['value'])
            return
        logging.warning('size of the file has been validated [%d][%d][%d]',
                        res['reqoc'],
                        res['repoc'],
                        res['value'])

        # Enable notification each 20 pkt
        # param = datahelper.DataWriter()
        # param.set_ubyte(0x08)
        # param.set_ubyte(20)
        # blepacket.write_data_value(handle, dfu_ctrl_handle, param.data)

        # Start transmission
        blepacket.write_ubyte_value(handle, dfu_ctrl_handle, 0x3)

        # Begin transfert
        widgets = [
            'Something: ',
            progressbar.Percentage(),
            ' ',
            progressbar.Bar(marker = '-'),
            ' ',
            progressbar.ETA()
        ]
        pbar = progressbar.ProgressBar(widgets=widgets, maxval=umsg['file_size'])
        bytes_send = 0
        with open(umsg['file'], 'rb') as f:
            pbar.start()
            pkt_send = 0
            res = { 'received' : None }
            for i in range((umsg['file_size'] / 20) + 1):
                if pkt_send == 0:
                    res['received'] = None
                    self.register_handle(handle, wait_for_notif, res)

                data = f.read(20)
                blepacket.write_data_value(handle,
                                           dfu_pkt_handle,
                                           data,
                                           0x52)

                bytes_send += len(data)
                pkt_send += 1
                time.sleep(.02)
                if pkt_send == 20:
                    res = { 'received' : None }
                    self.register_handle(handle, wait_for_notif, res)
                    blepacket.write_ubyte_value(handle, dfu_ctrl_handle, 0x07)
                    while res['received'] is None:
                        pass
                    pkt_send = 0
                    if res['data'] != bytes_send:
                        logging.error('DFU Target don\' have receive all the packet [%d][%d]',
                                      res['data'],
                                      bytes_send)
                    else:
                        pbar.update(bytes_send)


            pbar.finish()

        res = { 'received' : None }
        self.register_handle(handle, wait_for_notif, res)
        blepacket.write_ubyte_value(handle, dfu_ctrl_handle, 0x07)
        while res['received'] is None:
            time.sleep(.01)
        if res['repoc'] == 0x3 and res['value'] == 0x1:
            logging.error('DFU Target said us that all is alright')

        elif res['data'] != umsg['file_size']:
            logging.error('DFU Target don\' have receive all the packet [%d][%d]',
                          res['data'],
                          umsg['file_size'])
            return

        logging.warning('DFU Target agree to have received all the firmware')

        # Start validation
        res = { 'received' : None }
        self.register_handle(handle, wait_for_notif, res)

        blepacket.write_ubyte_value(handle, dfu_ctrl_handle, 0x4)


        # Wait for notification
        while res['received'] is None:
            time.sleep(.01)

        if res['value'] != 0x01:
            logging.error('Firmware not validated [%d][%d][%d]',
                          res['reqoc'],
                          res['repoc'],
                          res['value'])
            return
        logging.warning('Firmware has been validated [%d][%d][%d]',
                        res['reqoc'],
                        res['repoc'],
                        res['value'])


        # Start activation
        blepacket.write_ubyte_value(handle, dfu_ctrl_handle, 0x5)

        logging.warning('DFU Target try to reboot')
	time.sleep(20)

    def _act_write(self, umsg, result, blepacket):
        handle = result['handle']
        outlet_pkt = blepacket.get_char_for_group(handle,
                                                  0x0001,
                                                  0xFFFF,
                                                  uuid = umsg['uuid'],
                                                  get_err = True)

        #enable notif
        outlet_handle = outlet_pkt[0][0][0]
        if 'notif' in umsg:
            blepacket.write_ushort_value(handle, outlet_handle + 1, 0x0001)
        blepacket.write_ushort_value(handle, outlet_handle, umsg['value'])

        time.sleep(2)



    def send_umsg(self, umsg):

        dest_info = self._get_dest_info(umsg['dest_id'])
        if dest_info is None:
            return False

        addr_mac = dest_info.mac

        blepacket = uBlePacketSend(umsg,
                                   addr_mac,
                                   self._sock,
                                   self)
        result  = blepacket.connect()
        if not result:
            return False

        try:
            if umsg['action'] == 'disc':
                self._act_discovery(result, blepacket)

            if umsg['action'] == 'infos':
                self._act_infos(umsg, result, blepacket)

            if umsg['action'] == 'dfu':
                self._act_dfu(umsg, result, blepacket)

            if umsg['action'] == 'write':
                self._act_write(umsg, result, blepacket)

            if umsg['action'] == 'outlet':
                self._act_outlet_get_power(umsg, result, blepacket)
        except Exception, e:
            logging.exception(e)

        blepacket.disconnect(result['handle'])
        return True
