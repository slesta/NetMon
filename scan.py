#!/usr/bin/env python

""" Hlavni modul ktery spousti NetMon. Nastav sit ke skenovani a pripadne uprav definice pro detekci
v souborech networks_to_scan.json a config.json a potom pres main.py spust tento soubor """

import logging
import sys
import http.server
import socketserver
import os
from tools import load_json
import netgraph
import scanobjects
import connectobject

# Nastavi logovani
LOGGER = logging.getLogger(__name__)


def main():
    """ Ridi celkovy prubeh programu """

    netconfig = load_json('networks_to_scan.json')
    print('Choose network to scan from available configurations: [ {} ]'.format(
        ', '.join(netconfig.keys())))
    print('Network name: ', end='', flush=True)
    selected_network = str(sys.stdin.readline()).strip('\n\r \t')
    print('')
    scans = scanobjects.ScanNetwork(selected_network)  # Oskenuje sit
    saved_devices = connectobject.Connect(scans)  # Pripoji se k zarizenim a ziska data
    saved_devices.network.find_infrastructure_devices()  # Najde paterni zarizeni
    saved_devices.network.create_subnets()  # Vytvori seznam podsiti
    # Zaloguje vsechny podsite
    for subnet in saved_devices.network.subnets:
        LOGGER.info('subnet: %s mainGw: %s gws: %s', subnet.subnet, subnet.main_gateway,
                    [iface.parent.hostname for iface in subnet.gateways])
    saved_devices.network.connect_generic_devs()  # Zjisti brany ke generickym zarizenim
    saved_devices.network.create_connection_route()  # Vytvori spojeni z rout
    # Zaloguje vsechna vytvorena spojeni
    for conn in saved_devices.network.connections:
        LOGGER.info('%s - %s %s %s', conn.conn_from, conn.conn_to, conn.name, type(conn.conn_from))
    #  Z naskenovanych dat udela sitovy graf
    netgraph.Graf(saved_devices.network)
    #  Spusti webserver s prezentaci vysledku skenovani
    host = 'localhost'
    port = 8000
    web_dir = os.path.join(os.path.dirname(__file__), 'html')
    os.chdir(web_dir)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        print("See result at http://{}:{}/chart.html".format(host, port))
        httpd.serve_forever()


if __name__ == "__main__":
    main()
