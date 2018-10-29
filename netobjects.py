#!/usr/bin/env python
# coding=utf8

from socket import *
import subprocess
import nmap


class PortObject(object):

    def __init__(self):
        self.port = 0
        self.name = ''
        self.state = ''
        self.product = ''
        self.version = ''
        self.extrainfo = ''
        self.cpe = ''


class IpObject(object):

    def __init__(self, config, ip='127.0.0.1'):
        self.ip = ip
        self.active = False
        self.pingable = False
        self.ping_done = False
        self.scan_done = False
        self.ports_to_scan = config['ports_to_scan']
        self.detections = config['detect']
        self.min = 0
        self.avg = 0
        self.max = 0
        self.mdev = 0
        self.total = 0
        self.loss = 0
        self.active_ports = list()
        self.errors = list()
        self.os = ''  # Other, Linux, Windows, AirOS, IOS, RouterOS
        self.os_info = ''
        self.device = ''  # Other, Cisco, Mikrotik, UBNT, PC, Printer
        self.device_info = ''
        self.ping()
        # self.scan_ports()
        self.scan_nmap()
        self.detect_device()

    def ping(self, w=1, c=1):
        cmd = "ping -c {} -W {} {}".format(c, w, self.ip).split(' ')
        try:
            output = subprocess.check_output(cmd).decode().strip()
            lines = output.split("\n")
            total = lines[-2].split(',')[3].split()[1]
            loss = lines[-2].split(',')[2].split()[0]
            timing = lines[-1].split()[3].split('/')
            self.min = float(timing[0])
            self.avg = float(timing[1])
            self.max = float(timing[2])
            self.mdev = float(timing[3])
            self.total = float(total.replace('ms', ''))
            self.loss = float(loss.replace('%', ''))
            self.pingable = True
            self.active = True
            self.ping_done = True
        except Exception as e:
            self.errors.append(e)
            self.pingable = False
            self.ping_done = True

    def scan_ports(self):
        for port in self.ports_to_scan:
            try:
                s = socket(AF_INET, SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((self.ip, port))
                if result == 0:
                    self.active_ports.append(port)
                    self.active = True
                s.close()
                self.scan_done = True
            except Exception as e:
                self.errors.append(e)
                self.scan_done = True

    def scan_nmap(self):

        def to_str(itm):
            return str(itm)+','

        nm = nmap.PortScanner()
        sc = nm.scan(self.ip, ''.join(map(to_str, self.ports_to_scan)))  # Oskenuje porty, arguments="-O", sudo=True
        if self.ip in sc['scan'].keys():  # Pokud je IP aktivni, tak zapise porty
            # print(sc['scan'][self.ip]['hostnames'][0]['name'])
            if 'tcp' in sc['scan'][self.ip].keys():
                for port in sc['scan'][self.ip]['tcp']:
                    if sc['scan'][self.ip]['tcp'][port]['state'] == 'open':
                        port_obj = PortObject()
                        port_obj.port = port
                        port_obj.name = sc['scan'][self.ip]['tcp'][port]['name']
                        port_obj.state = sc['scan'][self.ip]['tcp'][port]['state']
                        port_obj.product = sc['scan'][self.ip]['tcp'][port]['product']
                        port_obj.version = sc['scan'][self.ip]['tcp'][port]['version']
                        port_obj.extrainfo = sc['scan'][self.ip]['tcp'][port]['extrainfo']
                        port_obj.cpe = sc['scan'][self.ip]['tcp'][port]['cpe']
                        self.active_ports.append(port_obj)
                        self.active = True

    def detect_device(self):  # Dle infa z naskenovanych portu zjisti OS a device
        for detect in self.detections:  # projde vsechny sablony pro detekci
            conditions_result = 0  # pocet shodnych podminek
            for condition in detect['conditions']:
                for portup in self.active_ports:
                    if portup.port == condition['port_num']:
                        if condition['contain'] in vars(portup)[condition['item']]:  # kontrola shody podminky
                            conditions_result += 1
            if conditions_result == len(detect['conditions']):  # pokud byly shodne vsechny, tak zapise vysledek
                if detect['result']['os']:
                    self.os = detect['result']['os']
                if detect['result']['dev']:
                    self.device = detect['result']['dev']
                if detect['result']['os_info']:
                    if detect['result']['os_info_port']:  # Test jestli ma nahradit osInfo textem zadane polozky portu
                        for p in self.active_ports:
                            if p.port == detect['result']['os_info_port']:
                                self.os_info = vars(p)[detect['result']['os_info']]
                    else:
                        self.os_info = detect['result']['os_info']
                if detect['result']['dev_info']:
                    if detect['result']['dev_info_port']:  # Test jestli ma nahradit devInfo textem zadane polozky portu
                        for p in self.active_ports:
                            if p.port == detect['result']['dev_info_port']:
                                self.device_info = vars(p)[detect['result']['dev_info']]
                    else:
                        self.device_info = detect['result']['dev_info']


class GenericDevice(object):

    def __init__(self):
        self.ip = None
        self.os = None  # Other, Linux, Windows, AirOS, IOS, RouterOS
        self.os_info = ''
        self.device = ''  # Other, Cisco, Mikrotik, UBNT, PC, Printer
        self.device_info = ''
        self.active = False
        self.pingable = False
        self.min = 0
        self.avg = 0
        self.max = 0
        self.mdev = 0
        self.total = 0
        self.loss = 0
        self.active_ports = list()
        self.errors = list()


class Device(GenericDevice):

    def __init__(self):
        super(GenericDevice).__init__()
        self.hostname = None
        self.uid = None
        self.firmware = None
        self.model = None
        self.manufacturer = None
        self.category = None
        self.username = None
        self.password = None
        self.interface = dict()
        self.bridge = dict()

    def __str__(self):
        return self.hostname + ' - ' + self.model

    def add_interface(self, objectitem):
        self.interface[str(objectitem)] = objectitem

    def add_bridge(self, objectitem):
        self.bridge[str(objectitem)] = objectitem

    def print(self):
        print('####################################################################################################')
        print('|==== Hostname: {}'.format(self.hostname))
        print('|==== Model: {}, Manufacturer: {}, Firmware: {}, Uid: {}, Username: {}, Password: {}'.format(
            self.model, self.manufacturer, self.firmware, self.uid, self.username, self.password))
        # print('Interfaces: {}'.format(', '.join(self.interface.keys())))
        for item in self.interface.keys():
            self.interface[item].print()
        if len(self.bridge):
            for item in self.bridge.keys():
                self.bridge[item].print()


class Interface(object):

    def __init__(self):
        self.name = None
        self.mac = None
        self.mtu = None
        self.state = None
        self.ip = dict()
        self.route = dict()
        self.wireless = None
        self.wireless_virt = None
        self.arp = dict()

    def __str__(self):
        return self.name

    def add_ip(self, objectitem):
        self.ip[str(objectitem)] = objectitem

    def add_route(self, objectitem):
        self.route[str(objectitem)] = objectitem

    # def add_wireless(self, objectitem):
    #     self.wireless[str(objectitem)] = objectitem
    #
    # def add_wireless_virt(self, objectitem):
    #     self.wireless_virt[str(objectitem)] = objectitem

    def add_arp(self, objectitem):
        self.arp[str(objectitem)] = objectitem

    def print(self):
        # print('----------------------------------------------------------------------------------------------------')
        print('|  ')
        print('|-{}'.format(self.name))
        print('|  |-MAC: {}  MTU: {}  State: {}'.format(self.mac, self.mtu, self.state))

        if len(self.ip):
            print('|  |')
            print('|  |-IP:')
            for item in self.ip.keys():
                self.ip[item].print()

        if len(self.route):
            print('|  |')
            print('|  |-Route:')
            for item in self.route.keys():
                self.route[item].print()

        if self.wireless:
            print('|  |')
            print('|  |-Wireless:')
            self.wireless.print()

        if self.wireless_virt:
            print('|  |')
            print('|  |-Wireless virtual:')
            self.wireless_virt.print()

        if len(self.arp):
            print('|  |')
            print('|  |-Arp:')
            for item in self.arp.keys():
                self.arp[item].print()


class Bridge(object):

    def __init__(self):
        self.bridge = Interface
        self.interface = {}

    def __str__(self):
        return str(self.bridge)

    def add_interface(self, objectitem):
        self.interface[str(objectitem)] = objectitem

    def print(self):
        print('|  ')
        print('|--Bridge: {}'.format(self.bridge))
        print('|  |-Interfaces: {}'.format(', '.join(self.interface.keys())))


class Ip:

    def __init__(self):
        self.ip = None
        self.mask = None
        self.brd = None

    def __str__(self):
        return self.ip

    def print(self):
        print('|  |  |-{}/{} brd {}'.format(self.ip, self.mask, self.brd))


class Route(object):

    def __init__(self):
        self.net = None
        self.gw = None

    def __str__(self):
        return self.net

    def print(self):
        print('|  |  |-{} gateway {}'.format(self.net, self.gw))


class Wireless(object):

    def __init__(self):
        self.essid = None
        self.mode = None
        self.frequency = None
        self.band = None
        self.virtual = dict()

    def __str__(self):
        return self.essid

    def add_interface(self, objectitem):
        self.virtual[str(objectitem)] = objectitem

    def print(self):
        print('|  |  |-{} mode: {}  frequency: {}  band: {}'.format(self.essid, self.mode, self.frequency, self.band))

        if len(self.virtual):
            print('|  |  |')
            print('|  |  | Wireless virtual:')
            for item in self.virtual.keys():
                self.virtual[item].print()


class WirelessVirtual(object):

    def __init__(self):
        self.essid = None
        self.mode = None
        self.master = Wireless

    def __str__(self):
        return self.essid

    def print(self):
        print('|  |  |-{} mode: {}'.format(self.essid, self.mode,))


class Arp(object):

    def __init__(self):
        self.ip = None
        self.mac = None
        self.manufacturer = None

    def __str__(self):
        return self.ip

    def print(self):
        print('|     |-{}  \tMAC: {}  Manufacturer: {}'.format(self.ip, self.mac, self.manufacturer))
