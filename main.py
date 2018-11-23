#!/usr/bin/env python

""" Hlavni soubor aplikace """

import logging
import sandbox
import scan

# Nastavi logovani
logging.basicConfig(filename='netmon.log',
                    level=logging.INFO,
                    format='%(asctime)s (%(name)s) [%(threadName)s] %(levelname)s: %(message)s')
LOGGER = logging.getLogger(__name__)

if __name__ == "__main__":
    # sandbox.main()
    scan.main()
