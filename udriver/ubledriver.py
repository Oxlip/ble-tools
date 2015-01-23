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

    DFU           = '\x00\x00\x15\x30\x12\x12\xEF\xDE\x15\x23\x78\x5F\xEA\xBC\xD1\x23'
    DFU_PACKET    = '\x00\x00\x15\x32\x12\x12\xEF\xDE\x15\x23\x78\x5F\xEA\xBC\xD1\x23'
    DFU_CONTROLE  = '\x00\x00\x15\x31\x12\x12\xEF\xDE\x15\x23\x78\x5F\xEA\xBC\xD1\x23'

    # This should be our version
    #DFU            = '\xC0\xF4\x16\x64\x93\x24\x40\x85\xAB\xA0\x09\x02\xC0\xE8\x95\x0A'
    #DFU_PACKET     = '\xC0\xF4\x16\x65\x93\x24\x40\x85\xAB\xA0\x09\x02\xC0\xE8\x95\x0A'
    #DFU_CONTROLE   = '\xC0\xF4\x16\x66\x93\x24\x40\x85\xAB\xA0\x09\x02\xC0\xE8\x95\x0A'

    knowed_uuid = {
        DEVINCE_NAME : 'DEVINCE_NAME',
        UDEVICE : 'uDevice',
        UDEVICE_INFOS  : 'uDevice Infos',
        UDEVICE_OUTLET : 'uDevice Outlet',
        UDEVICE_SENSOR : 'uDevice Sensor',
        DFU : 'DFU',
        DFU_PACKET : 'DFU packet',
        DFU_CONTROLE : 'DFU control'
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

    PKT_OPCODE_VALUE_NOTIF = 0x1b

    CMD_OPCODE_CREATE_CONN = 0x200d

class uBlePacketSend(datahelper.DataWriter):

    def write_ubyte_value(self, handle_target, value, write_type = 0x12):
        self.set_ubyte(0x02)
        self.set_ushort(self.handle)
        self.set_ushort(8)
        self.set_ushort(4)
        self.set_ushort(4)
        self.set_ubyte(write_type)
        self.set_ushort(handle_target)
        self.set_ubyte(value)
        self.send()

        if write_type == 0x52:
           return True

        opt = { 'opcode' : write_type + 1 }
        resp = bleevent.wait_for_event(options = opt, opcode = write_type)

        if resp is None or resp.opcode == 0x01:
           return False
        return True

    def write_ushort_value(self, handle_target, value, write_type = 0x12):
        self.set_ubyte(0x02)
        self.set_ushort(self.handle)
        self.set_ushort(9)
        self.set_ushort(5)
        self.set_ushort(4)
        self.set_ubyte(write_type)
        self.set_ushort(handle_target)
        self.set_ushort(value)
        self.send()

        if write_type == 0x52:
           return True

        opt = { 'opcode' : write_type + 1 }
        resp = bleevent.wait_for_event(options = opt, opcode = write_type)
        print resp.handle

        if resp is None or resp.opcode == 0x01:
           return False
        return True

    def write_uint_value(self, handle_target, value, write_type = 0x12):
        self.set_ubyte(0x02)
        self.set_ushort(self.handle)
        self.set_ushort(11)
        self.set_ushort(7)
        self.set_ushort(4)
        self.set_ubyte(write_type)
        self.set_ushort(handle_target)
        self.set_uint(value)
        self.send()

        if write_type == 0x52:
           return True

        opt = { 'opcode' : write_type + 1 }
        resp = bleevent.wait_for_event(options = opt, opcode = write_type)

        if resp is None or resp.opcode == 0x01:
           return False
        return True

    def write_data_value(self, handle_target, value, write_type = 0x12):
        self.set_ubyte(0x02)
        self.set_ushort(self.handle)
        self.set_ushort(len(value) + 7)
        self.set_ushort(len(value) + 3)
        self.set_ushort(4)
        self.set_ubyte(write_type)
        self.set_ushort(handle_target)
        self.set_data(value)
        self.send()

        if write_type == 0x52:
           return True

        opt = { 'opcode' : write_type + 1 }
        resp = bleevent.wait_for_event(options = opt, opcode = write_type)

        if resp is None or resp.opcode == 0x01:
           return False
        return True

    def find_info(self, hfrom = 0x0001):

        def forge_find_info(self, hfrom = 0x0001):
            self.set_ubyte(0x02)
            self.set_ushort(self.handle)
            self.set_ushort(9)
            self.set_ushort(5)
            self.set_ushort(4)
            self.set_ubyte(0x4)
            self.set_ushort(hfrom)
            self.set_ushort(0xffff)

        opt = { 'handle' : self.handle }
        forge_find_info(self)
        self.send()
        attributes = []

        responce = bleevent.wait_for_event(options = opt)

        while responce is not None and responce.opcode == 0x5:
            attributes += responce.attributes
            forge_find_info(self, responce.attributes[-1][0] + 1)
            self.send()
            responce = bleevent.wait_for_event(options = opt)

        return attributes


    def read_value(self, char_handle):
        self.set_ubyte(0x02)
        self.set_ushort(self.handle)
        self.set_ushort(7)
        self.set_ushort(3)
        self.set_ushort(4)
        self.set_ubyte(0xa)
        self.set_ushort(char_handle)

        self.send()

        opt = { 'opcode' : 0xb }
        resp = bleevent.wait_for_event(options = opt)

        return resp.value

    def get_char_for_group(self, begin, end, uuid = 0x2803, get_err = False):
        self.set_ubyte(0x02)
        self.set_ushort(self.handle)

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

        self.send()

        opt = { 'opcode' : 0x9 }
        resp = bleevent.wait_for_event(options = opt, opcode = 0x8)

        data = {}
        data['att'] = None
        data['pkt'] = None

        if resp is None:
           logging.error('get_char_for_group: Unable to get any responce')
           return data

        if resp.opcode == 0x9:
           data['att'].append(resp.attributes)
        data['pkt'] = resp


        return data


    def disconnect(self):
        self.set_ubyte(uBleType.PKT_TYPE_HCI_CMD)
        self.set_ushort(0x0406)
        self.set_ubyte(0x03)
        self.set_ushort(self.handle)
        self.set_ubyte(0x13)
        self.send()

        opt = { 'event_type' : 0x5 }
        resp = bleevent.wait_for_event(options = opt, opcode = 0x8)

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


    def connect(self):
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

        opt_result = { 'event_type' : 0x3e }
        opt = { 'cmd_opcode' : uBleType.CMD_OPCODE_CREATE_CONN }
        responce = bleevent.wait_for_event(options = opt)

        if not responce or responce.status != 0x0:
            logging.error('Ble stack not accept the connection')
            return False

        responce = bleevent.wait_for_event(options = opt_result)
        if responce is None:
            #Send creation cancel
            return False
        self.handle = responce.handle
        return True

    def __init__(self, umsg, to, sock, driver):
        super(uBlePacketSend, self).__init__()
        self.umsg     = umsg
        self.mac_to   = to
        self.sender   = sock
        self.driver   = driver


class uBlePacketRecv(datahelper.DataReader):

    event_types = {
        0x0f : 'cmd_status',
        0x05 : 'disconnect',
        0x13 : 'packet_complet',
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
        self.status = self.get_ubyte()
        self.get_ubyte()
        self.cmd_opcode = self.get_ushort()
        bleevent.manager.notify(self)

    def _parse_disconnect(self):
        logging.info('Board disconnected')
        bleevent.manager.notify(self)

    def _parse_packet_complet(self):
        logging.debug('Packet complet receive')

    def _parse_le_meta(self):
        self.sub_event = self.get_ubyte()

        if self.sub_event == 0x01:
            self.status = self.get_ubyte()
            self.handle = self.get_ushort()
            # some stuff remaining
            bleevent.manager.notify(self)
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
            logging.debug('LE meta sub event not impl %x',
                          self.sub_event)
            return


    def _parse_event(self):
        self.event_type = self.get_ubyte()
        self.param_len  = self.get_ubyte()

        if not self.event_type in self.event_types:
            logging.debug('Event %s not implemented', hex(self.event_type))
            return

        self._call(self.event_types[self.event_type])


    def _parse_packet(self):
        self.handle = self.get_ubyte() # ? Handle must be on 0xFFFF
        self.flags  = self.get_ubyte()
        self.data_total_len = self.get_ushort()
        self.data_len = self.get_ushort()
        self.cid = self.get_ushort()

        # CID: 0x04 -> attribute protocole
        if self.cid != 0x04:
           return
        self.opcode = self.get_ubyte()

        if self.opcode == 0x01:
            self.req_opcode = self.get_ubyte()
            bleevent.manager.notify(self)
            return
        elif self.opcode == 0x1B:
            logging.debug('Recv notification')
            bleevent.manager.notify(self)
            return
        elif self.opcode == 0x13:
            logging.debug('Recv write responce')
            bleevent.manager.notify(self)
            return
        elif not self.opcode in self.packet_types:
            logging.debug('Opcode %s not implemented', hex(self.opcode))
            return


        self._call(self.packet_types[self.opcode])


    def _parse_read(self):
        self.value_len = self.data_len - 1
        self.value = self.get_data(self.value_len)
        bleevent.manager.notify(self)

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
        bleevent.manager.notify(self)


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
                        value = blepacket.read_value(char['handle'])
                        logging.warning('{uuid}: {value}'.format(uuid = char['uuid'],
                                                                 value = value))


    def _act_infos(self, umsg, blepacket):
        infos = blepacket.find_info()

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
        return board


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

    def _act_dfu(self, umsg, blepacket):
        time.sleep(1)
        dfu_ctrl = blepacket.get_char_for_group(0x0001,
                                                0xFFFF,
                                                uuid = BleUUID.DFU_CONTROLE,
                                                get_err = True)

        if dfu_ctrl is None or dfu_ctrl['pkt'] is None:
           logging.error('Unable to get the control handle')
           return

        dfu_pkt = blepacket.get_char_for_group(0x0001,
                                               0xFFFF,
                                               uuid = BleUUID.DFU_PACKET,
                                               get_err = True)

        if dfu_pkt is None or dfu_pkt['pkt'] is None:
           logging.error('Unable to get the control handle')
           return

        # We are not able to read, but the handle is in error responce :)
        dfu_pkt_handle = dfu_pkt['pkt'].get_ushort()
        if dfu_pkt['pkt'].get_ubyte() == 0x0a:
           logging.error('The board don\'t have the dfu pkthandle char')
           return
        logging.debug('DFU Packet handle: %s', hex(dfu_pkt_handle))

        dfu_ctrl_handle = dfu_ctrl['pkt'].get_ushort()
        if dfu_ctrl['pkt'].get_ubyte() == 0x0a:
           logging.error('The board don\'t have the dfu ctrlhandle char')
        logging.debug('DFU Control handle: %s', hex(dfu_ctrl_handle))

        # Enable notification
        logging.info('Enable Notification')
        if not blepacket.write_ushort_value(dfu_ctrl_handle + 1, 0x0001):
           logging.error('Failed to enable the notification')
           return

        # Start dfu
        logging.info('Start DFU')
        param = datahelper.DataWriter()
        param.set_ubyte(0x01)
        param.set_ubyte(0x04)
        if not blepacket.write_data_value(dfu_ctrl_handle, param.data):
           logging.error('Failed to start the dfu mode')
           return

        # Write bin size
        logging.info('Send binary size to the board')
        param = datahelper.DataWriter()
        param.set_uint(0x00)
        param.set_uint(0x00)
        param.set_uint(umsg['file_size'])
        blepacket.write_data_value(dfu_pkt_handle, param.data, 0x52)

        # Wait for notification
        logging.info('Waiting for validation notification')
        opt = { 'opcode' : uBleType.PKT_OPCODE_VALUE_NOTIF }
        packet = bleevent.wait_for_event(options = opt)

        if packet is None:
           logging.error('Unable to receive the notification')
           return

        def get_notif_data(packet):

            data = {}
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

            return data

        data = get_notif_data(packet)
        if data['value'] != 0x01:
            logging.error('Size not validated validated [%d][%d][%d]',
                          data['reqoc'],
                          data['repoc'],
                          data['value'])
            return
        logging.info('size of the file has been validated [%d][%d][%d]',
                     data['reqoc'],
                     data['repoc'],
                     data['value'])

        # Enable notification each 20 pkt
        # param = datahelper.DataWriter()
        # param.set_ubyte(0x08)
        # param.set_ubyte(20)
        # blepacket.write_data_value(handle, dfu_ctrl_handle, param.data)

        # Start transmission
        logging.info('Start transmission')
        blepacket.write_ubyte_value(dfu_ctrl_handle, 0x3)

        logging.info('Device allow to start the update')

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
                data = f.read(20)
                blepacket.write_data_value(dfu_pkt_handle, data, 0x52)

                bytes_send += len(data)
                pkt_send += 1
                if pkt_send == 10:
                    blepacket.write_ubyte_value(dfu_ctrl_handle, 0x07)
                    # Wait for notification
                    logging.debug('Waiting for validation notification')
                    opt = { 'opcode' : uBleType.PKT_OPCODE_VALUE_NOTIF }
                    packet = bleevent.wait_for_event(options = opt, timeout = 20)

                    pkt_send = 0
                    res = get_notif_data(packet)
                    if res['data'] != bytes_send:
                        logging.error('DFU Target don\' have receive all the packet [%d][%d]',
                                      res['data'],
                                      bytes_send)
                    else:
                        pbar.update(bytes_send)


            pbar.finish()

        blepacket.write_ubyte_value(dfu_ctrl_handle, 0x07)
        # Wait for notification
        logging.debug('Waiting for validation notification')
        opt = { 'opcode' : uBleType.PKT_OPCODE_VALUE_NOTIF }
        packet = bleevent.wait_for_event(options = opt)

        res = get_notif_data(packet)

        if res['repoc'] == 0x3 and res['value'] == 0x1:
            logging.info('DFU Target said us that all is alright')

        elif res['data'] != umsg['file_size']:
            logging.error('DFU Target don\' have receive all the packet [%d][%d]',
                          res['data'],
                          umsg['file_size'])
            return

        logging.info('DFU Target agree to have received all the firmware')

        # Start validation
        blepacket.write_ubyte_value(dfu_ctrl_handle, 0x4)

        # Wait for notification
        logging.debug('Waiting for validation notification')
        opt = { 'opcode' : uBleType.PKT_OPCODE_VALUE_NOTIF }
        packet = bleevent.wait_for_event(options = opt)

        res = get_notif_data(packet)

        if res['value'] != 0x01:
            logging.error('Firmware not validated [%d][%d][%d]',
                          res['reqoc'],
                          res['repoc'],
                          res['value'])
            return
        logging.info('Firmware has been validated [%d][%d][%d]',
                        res['reqoc'],
                        res['repoc'],
                        res['value'])


        # Start activation
        blepacket.write_ubyte_value(dfu_ctrl_handle, 0x5)

        logging.info('DFU Target try to reboot')
        time.sleep(4)

        return True

    def _act_read(self, umsg, blepacket):
        return blepacket.read_value(umsg['handle'])

    def _act_write(self, umsg, blepacket):
        outlet_pkt = blepacket.get_char_for_group(self.handle,
                                                  0x0001,
                                                  0xFFFF,
                                                  uuid = umsg['uuid'],
                                                  get_err = True)

        #enable notif
        outlet_handle = outlet_pkt[0][0][0]
        if 'notif' in umsg:
            blepacket.write_ushort_value(self.handle, outlet_handle + 1, 0x0001)
        blepacket.write_ushort_value(self.handle, outlet_handle, umsg['value'])

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
        if not blepacket.connect():
            logging.error('Unable to connect to the board')
            return False

        res = False

        try:
            if umsg['action'] == 'infos':
                res = self._act_infos(umsg, blepacket)

            if umsg['action'] == 'dfu':
                res = self._act_dfu(umsg, blepacket)

            if umsg['action'] == 'read':
                res = self._act_read(umsg, blepacket)

            if umsg['action'] == 'write':
                res = self._act_write(umsg, blepacket)

        except Exception, e:
            logging.exception(e)

        blepacket.disconnect()
        return res
