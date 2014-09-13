#!/bin/env python

import logging
import ublereader


def main():
    reader = ublereader.uBleReader()
    reader.open()

    if not reader.is_open():
        logging.error('Unable to get reader')
        return

    while True:
        packet = reader.receiv_packet()

if __name__ == '__main__':
    main()
