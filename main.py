#!/bin/env python

import logging
import ubledriver


def main():
    driver = ubledriver.uBleDriver()
    driver.init()

    if not driver.is_init():
        logging.error('Unable to get driver')
        return

    while True:
        packet = driver.run()
        driver.send_umsg(None)

if __name__ == '__main__':
    main()
