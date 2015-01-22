#!/bin/env python

import os
import sys
import tools
import logging
from  udriver import ubledriver
import time


def main():
    driver = ubledriver.uBleDriver()
    driver.init()

    if not driver.is_init():
        logging.error('Unable to initialize ble driver')
        return

    packet = driver.run()

    umsg = {
        'dest_id' : '#fake_serial',
        'action'  : 'dfu',
        'file'   : sys.argv[1]
    }

    if not os.path.exists(umsg['file']):
        logging.error('Unable to found the file \'%s\'', umsg['file'])
        return

    file_stat = os.stat(umsg['file'])
    umsg['file_size'] = file_stat.st_size

    if not driver.send_umsg(umsg):
        logging.error('Unable to send msg to the dest %s', umsg['dest_id'])

if __name__ == '__main__':
    main()
