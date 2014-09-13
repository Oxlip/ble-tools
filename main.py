#!/bin/env python

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
    driver.send_umsg(None)

    time.sleep(220)

if __name__ == '__main__':
    main()
