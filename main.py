#!/bin/env python

import tools
import logging
from  udriver import ubledriver
import time


def main():
    driver = ubledriver.uBleDriver()
    driver.init()

    if not driver.is_init():
        logging.error('Unable to get driver')
        return

    packet = driver.run()

#    umsg = { 'action' : 'disc' }
    umsg = { 'dest_id' : '#fake_serial', 'action' : 'infos' }
#    umsg = { 'action' : 'led', 'on' : True }

    if not driver.send_umsg(umsg):
        logging.error('Unable to found dest %s', umsg['dest_id'])

if __name__ == '__main__':
    main()
