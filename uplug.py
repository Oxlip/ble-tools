#!/bin/env python

import os
import sys
import time
import tools
import logging
import argparse

from  udriver import ubledriver
from  udriver import datahelper

def process_command_line():
    """
    Process command line arguments and assign to appropriate variable
    """
    parser = argparse.ArgumentParser(description='Outlet management.')
    parser.add_argument('--power', default=False, help='Set power level of the outlet.')
    parser.add_argument('--consume', default=False, help='Get the consumation.')
    parser.add_argument('--serial', default='#fake_serial', help='Set the serial for the dest.')
    return parser.parse_args()

def get_umsg_for_dim(args):
    umsg = {
        'dest_id' : args.serial,
        'action'  : 'write'
    }

    umsg['uuid'] = ubledriver.BleUUID.UDEVICE_OUTLET

    umsg['value'] = (int(args.power) << 8) + 0x01

    return umsg


def get_umsg_for_consume(args):
    return {}

def main():
    args = process_command_line()

    driver = ubledriver.uBleDriver()
    driver.init()

    if not driver.is_init():
        logging.error('Unable to initialize ble driver')
        return

    umsg = {}

    if args.power is not False:
        umsg = get_umsg_for_dim(args)

    if args.consume is not False:
        umsg = get_umsg_for_consume(args)

    if not umsg:
        logging.error('Not implemented yet')
        sys.exit(1)

    packet = driver.run()
    if not driver.send_umsg(umsg):
        logging.error('Unable to found dest %s', umsg['dest_id'])

if __name__ == '__main__':
    main()
