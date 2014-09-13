import struct

class DataWriter(object):

    def __init__(self):
        self.data = ''

    def set_ubyte(self, i):
        self.data += struct.pack('<B', i)

    def set_ushort(self, i):
        self.data += struct.pack('<H', i)

    def set_uint(self, i):
        self.data += struct.pack('<I', i)

    def set_int(self, i):
        self.data += struct.pack('<i', i)

    def set_data(self, data):
        self.data += data

class DataReader(object):

    def __init__(self, data):
        self.data = data
        self.pos  = 0

    def get_ubyte(self):
        (res,) = struct.unpack('<B', self.data[self.pos : self.pos + 1])
        self.pos += 1
        return res

    def get_ushort(self):
        (res,) = struct.unpack('<H', self.data[self.pos : self.pos + 2])
        self.pos += 2
        return res

    def get_uint(self):
        (res,) = struct.unpack('<I', self.data[self.pos : self.pos + 4])
        self.pos += 4
        return res

    def get_int(self):
        (res,) = struct.unpack('<i', self.data[self.pos : self.pos + 4])
        self.pos += 4
        return res

    def get_data(self, size):
        res = self.data[self.pos : self.pos + size]
        self.pos += size
        return res


