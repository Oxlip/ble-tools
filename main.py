#!/bin/env python

import json
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

    res = driver.send_umsg(umsg)
    if res is False:
       logging.error('Unable to found dest %s', umsg['dest_id'])
    else:
       print json.dumps(res, sort_keys=True, indent=4)

if __name__ == '__main__':
    main()
