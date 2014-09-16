import logging

class uDriver(object):

    def __init__(self, name):
        self._name    = name
        self._is_init = False

    def init(self):
        logging.info('%s: open not implemented', self.name)

    def is_init(self):
        return self._is_init

    def fini(self):
        logging.info('%s: close not implemented', self.name)

    def get_name(self):
        return self._name

    def run(self):
        logging.info('%s: receiv_packet not implemented', self.name)

    def send_umsg(self, umsg):
        logging.info('%s: send_packet not implemented', self.name)
