import logging

class uReader(object):

    def __init__(self, name):
        self._name    = name
        self._is_open = False

    def open(self):
        logging.info('%s: open not implemented', self.name)

    def is_open(self):
        return self._is_open

    def close(self):
        logging.info('%s: close not implemented', self.name)

    def receiv_packet(self):
        logging.info('%s: receiv_packet not implemented', self.name)

    def send_packet(self, upacket):
        logging.info('%s: send_packet not implemented', self.name)
