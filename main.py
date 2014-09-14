#!/bin/env python

import tools
import logging
import ubledriver
import time


def main():
    driver = ubledriver.uBleDriver()
    driver.init()

    if not driver.is_init():
        logging.error('Unable to get driver')
        return

    packet = driver.run()

#    umsg = { 'action' : 'disc' }
    umsg = { 'action' : 'led', 'on' : True }

    driver.send_umsg(umsg)

if __name__ == '__main__':
    main()
