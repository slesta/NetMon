# !/usr/bin/env python

"""

Modul nacita data z Linux zarizeni pres SSH a vytvori objekt Device s jeho atributy jako je
hostname, interfejsy, adresy, routy a podobne.

"""

import logging
import re
from typing import Dict, List, Union
import os
import time
import netobjects
import scanobjects
from tools import SshClient, get_fresh_manufacturers, load_json

# Nastavi logovani
LOGGER = logging.getLogger(__name__)


def refresh_manufacturers():
    """ Jestlize je seznam vyrobcu starsi nez 30 dni, tak ho obcerstvi """

    if (int(time.time()) - int(os.stat(
            'config/manufacturers.json').st_atime)) / 60 / 60 / 24 > 30:
        get_fresh_manufacturers()


class Linux:
    """ Trida Linux ziskava data pres ssh z Linux zarizeni """

    def __init__(self, ip_obj: scanobjects.IpScan, accounts: List,
                 networkobject: netobjects.Network):
        self.manufacturers = None  # Seznam vyrobcu dle MAC
        self.accounts = accounts
        self.ip_obj = ip_obj
        self.client = None  # SSH client
        self.account = {'username': None, 'password': None}
        self.network = networkobject
        self.device = None
        self.run()

    def run(self):
        """ Pripravi data, pripoji klienta, nacte data a vytvori objekt device """

        self.connect_ssh()
        # Jestlize je pripojeno zarizeni pripojeno pres SSH
        if self.client:
            refresh_manufacturers()
            self.manufacturers = load_json('manufacturers.json')  # Nacte seznam vyrobcu do promenne
            self.device = self.create_device()
            if self.device:
                self.set_device_generic_data(self.device)

            self.client.close_ssh()
            LOGGER.info('Device created from IP %s', self.ip_obj.ipaddr)

    def connect_ssh(self):
        """ Najde funkcni kombinaci pristupovych udaju a vytvori SSH spojeni na zarizeni """

        for account in self.accounts:

            self.client = SshClient(self.ip_obj.ipaddr, 22, account['username'],
                                    account['password'])
            self.account = account
            if not self.client.error:
                break
            else:
                self.client.close_ssh()
                if self.client.error == "Connection Error":
                    self.client = False
                    break
                self.client = False
                time.sleep(15)

    def get_host_data(self) -> Dict:
        """ Ziska device info """

        host_data = {'ubnt': '', 'uid': '', 'hostname': '', 'firmware': '', 'model': ''}

        # Zjisti jedinecny identifikator, hostname, model, fw z UBNT
        cmd = 'mca-status'
        out = self.client.command_exec(cmd)
        if out:
            host_data['ubnt'] = True
            line = out.split('\n')[0]
            host_data['hostname'] = line.split(',')[0].split('=')[1]
            host_data['uid'] = line.split(',')[1].split('=')[1]
            host_data['firmware'] = line.split(',')[2].split('=')[1]
            host_data['model'] = line.split(',')[3].split('=')[1]

        if not host_data['ubnt']:
            # Zkusi hostname z Linux uname -a
            cmd = 'uname -a'
            out = self.client.command_exec(cmd)
            if out:
                host_data['hostname'] = out.split(' ')[1]

            # Z Debian based zjisti release
            cmd = 'lsb_release -a'
            out = self.client.command_exec(cmd).split('\n')
            if out:
                for line in out:
                    if 'Description' in line:
                        host_data['firmware'] = line.split(':')[1].strip(' \n\r\t')

            # Zjisti jedinecny identifikator
            cmd = 'cat /var/lib/dbus/machine-id'
            out = self.client.command_exec(cmd)
            if out:
                host_data['uid'] = out.strip(' \r\n\t')

            if not host_data['uid']:
                # Zjisti jedinecny identifikator ze synology
                cmd = 'cat /etc/synoinfo.conf'
                out = self.client.command_exec(cmd)
                if out:
                    out = out.split('\n')
                    host_data['uid'] = out[0].split('=')[1].strip(' \r\n\t"')
        return host_data

    def get_interfaces(self) -> List[dict]:
        """ Ziska seznam interfejsu z Linux zarizeni """

        def linux_iplink_to_keys(item: str) -> List[Dict]:
            """ Pomoci regexp rozparsuje vystup prikazu do slovniku"""

            regex = (r"\S+:\s+(?P<interface>\S+):\s+<\S+\smtu\s+(?P<mtu>\d+)\sqdisc\s"
                     r"(?P<qdisc>\S+)\s(state\s(?P<state>\S+)|\S+\s)[ 0-9a-zA-Z\\]+"
                     r"/ether\s+(?P<mac>[:0-9a-fA-F]+)")
            matches = re.finditer(regex, item, re.MULTILINE)
            outlist = []
            for match in matches:
                match = match.groupdict()
                if 'state' not in match.keys():
                    match['state'] = 'UP'
                outlist.append(match)
            return outlist

        cmd = 'ip -o -f inet link'
        out = self.client.command_exec(cmd)
        interfaces = list()
        if out:
            interfaces = linux_iplink_to_keys(out)
        return interfaces

    def get_routes(self) -> List[dict]:
        """ Ziska routovaci tabulku z Linux zarizeni """

        def clean_item(item: str) -> str:
            """ Vycisti retezec od nepotrebnych znaku a pripravi ho na rozparsovani """

            return item.replace('\t', ' ').replace('   ', ' ').replace('  ', ' ') \
                .replace('\n', '').replace('  ', ' ').replace('   ', ' ').replace('  ', ' ')

        cmd = 'ip route ls table all'
        out = self.client.command_exec(cmd)
        route_list = list()
        if out:
            out = map(clean_item, out.split('\n'))
            for line in out:
                linesplit = line.split(' ')
                if linesplit[1] == 'via':
                    route_list.append(
                        {'interface': linesplit[4],
                         'net': linesplit[0].replace('default', '0.0.0.0/0'),
                         'gateway': linesplit[2]})
        return route_list

    def get_ips(self) -> List[dict]:
        """ Ziska seznam IP adres z Linux zarizeni """

        def linux_ipaddr_to_keys(item: str) -> Union[List[Dict], None]:
            """ Pomoci regexp rozparsuje vystup prikazu do slovniku"""

            regex = (r"\S+:\s+(?P<interface>\S+)\s+inet\s+(?P<ip>[0-9.]+)/(?P<mask>[0-9]+)\s+"
                     r"brd\s+(?P<broadcast>[0-9.]+)")
            matches = re.finditer(regex, item, re.MULTILINE)
            outlist = []
            for match in matches:
                outlist.append(match.groupdict())
            return outlist

        cmd = 'ip -o -f inet address'
        out = self.client.command_exec(cmd)
        ips = list()
        if out:
            ips = linux_ipaddr_to_keys(out)
        return ips

    def get_wireless(self) -> List[dict]:
        """ Ziska wireless int z ubnt """

        def linux_iwconfig_to_keys(item: str) -> List[Dict]:
            """ Pomoci regexp rozparsuje vystup prikazu do slovniku"""

            regex = (r"(?P<iface>\S+)\s+IEEE[ ]+(?P<ieee>\S+)\s+ESSID:\"(?P<essid>"
                     r"\S+)(\s+\S+\n|\s+\n)\s+Mode:(?P<mode>\S+)\s+Frequency:(?P<frequency>\S+)\s")
            matches = re.finditer(regex, item, re.MULTILINE)
            outlist = []
            for match in matches:
                outlist.append(match.groupdict())
            return outlist

        cmd = 'iwconfig'
        out = self.client.command_exec(cmd)
        wireless = list()
        if out:
            wireless = linux_iwconfig_to_keys(out)
        return wireless

    def get_bridges(self) -> List[dict]:
        """ Ziska bridge ints z linux """

        def linux_bridge_to_keys(item: str) -> List[Dict[str, List]]:
            """ Rozparsuje vystup prikazu do listu"""

            item = item.split('\n')
            outdict = {'bridge': '', 'ports': []}
            outlist = []
            item.append('')
            for line in item[1:]:
                if 'No such device' not in line:
                    line = line.replace('\t', '        ').replace('no', '        '). \
                        replace('yes', '        ')
                    brif = line[0:12].replace(' ', '').replace('\n', '')
                    portif = line[-12:].replace(' ', '').replace('\n', '')
                    if brif:
                        if outdict['bridge'] != '':
                            outlist.append(dict(outdict))
                            outdict = {'bridge': '', 'ports': []}
                        outdict['ports'] = [portif]
                        outdict['bridge'] = brif
                    else:
                        if not (brif + portif) and outdict['bridge']:
                            outlist.append(dict(outdict))
                        else:
                            outdict['ports'].append(portif)
            return outlist

        cmd = 'brctl show'
        out = self.client.command_exec(cmd)
        bridge = list()
        if out:
            bridge = linux_bridge_to_keys(out)
        return bridge

    def get_arp(self, interface: netobjects.Interface, ubnt: bool) -> List[dict]:
        """ Ziska arp z linux (nejdriv poskadli broadcast pingem
         aby naplnil tabulku vsim dostupnym) """

        def linux_arp_to_keys(item: str) -> List[Dict[str, str]]:
            """ Rozparsuje vystup prikazu do listu """

            item = item.split('\n')
            listout = []
            for line in item[1:]:
                line = line.replace(' ', '').replace('0x1', ' ').replace('0x2', ' ') \
                    .replace('*', ' ').replace('  ', ' ').split(' ')
                listout.append({'interface': line[2], 'ip': line[0], 'mac': line[1]})
            return listout

        # XS5 firmware ma problem s parametrama pingu, tak vynechame
        dev = interface.parent
        if 'XS5' not in dev.firmware:
            if not ubnt:
                cmd = 'ping 255.255.255.255 -c7'
                self.client.command_exec(cmd)
            else:
                cmd = 'ping 255.255.255.255 -b'
                self.client.command_exec(cmd)
        cmd = 'cat /proc/net/arp'
        out = self.client.command_exec(cmd)
        arp = list()
        if out:
            arp = linux_arp_to_keys(out)
        return arp

    def create_device(self) -> Union[netobjects.Device, None]:
        """ Vytvori objekt device a prida do nej interfejsy, bridge do nich ip,
        wireless, routy a pod. """

        host = self.get_host_data()
        device = None
        if host:
            device = netobjects.Device(account=self.account, host=host)
            self.device_add_interfaces(device, host['ubnt'])
            self.device_add_bridges(device)
        return device

    def device_add_interfaces(self, device: netobjects.Device, ubnt: bool) -> netobjects.Device:
        """ Vytvori interfejs objekty pro dane zarizeni """

        for item_int in self.get_interfaces():
            interface = netobjects.Interface()
            interface.name = item_int['interface']
            interface.state = item_int['state']
            interface.mac = item_int['mac']
            interface.parent = device
            device.add_interface(interface)
            self.interface_add_ips(interface)
            self.interface_add_routes(interface)
            self.interface_add_wireless(interface)
            self.interface_add_arp(interface, ubnt)

        return device

    def interface_add_ips(self, interface: netobjects.Interface):
        """ Vytvori ip objekty pro dany interfejs """

        for item_ip in self.get_ips():
            if interface.name == item_ip['interface']:
                ipaddr = netobjects.Ip()
                ipaddr.ipaddr = item_ip['ip']
                ipaddr.mask = item_ip['mask']
                ipaddr.brd = item_ip['broadcast']
                ipaddr.parent = interface
                interface.add_ip(ipaddr)

    def interface_add_routes(self, interface: netobjects.Interface):
        """ Vytvori route objekty pro dany interfejs """

        for item_route in self.get_routes():
            if interface.name == item_route['interface']:
                route = netobjects.Route()
                route.net = item_route['net']
                route.gate = item_route['gateway']
                route.parent = interface
                interface.add_route(route)

    def interface_add_wireless(self, interface: netobjects.Interface):
        """ Vytvori wireless objekt pro dany interfejs """

        for item_wireless in self.get_wireless():
            if interface.name == item_wireless['iface']:
                wireless = netobjects.Wireless()
                wireless.essid = item_wireless['essid']
                wireless.mode = item_wireless['mode']
                wireless.frequency = item_wireless['frequency']
                wireless.band = item_wireless['ieee']
                wireless.parent = interface
                interface.wireless = wireless

    def interface_add_arp(self, interface: netobjects.Interface, ubnt: bool):
        """ Vytvori arp objekty pro dany interfejs """

        for item_arp in self.get_arp(interface, ubnt):
            if interface.name == item_arp['interface']:
                arp = netobjects.Arp()
                arp.ipaddr = item_arp['ip']
                arp.mac = item_arp['mac']
                # jestli zna vyrobce
                if item_arp['mac'].replace(':', '')[0:6].upper() in self.manufacturers.keys():
                    arp.manufacturer = self.manufacturers[item_arp['mac'].replace
                                                          (':', '')[0:6].upper()]
                arp.parent = interface
                interface.add_arp(arp)

    def device_add_bridges(self, device: netobjects.Device):
        """ Vytvori bridge objekt a namapuje do nej interfejs objekty """

        for item_br in self.get_bridges():
            bridge = netobjects.Bridge()
            bridge.parent = device
            for bint in device.interface:
                if bint == item_br['bridge']:
                    bridge.bridge = device.interface[bint]
            for br_port in item_br['ports']:
                bridge.add_interface(device.interface[br_port])
            device.add_bridge(bridge)

    def set_device_generic_data(self, device: netobjects.Device):
        """ Prepise data ze skenu do zarizeni """

        device.ipaddr = self.ip_obj.ipaddr
        device.os = self.ip_obj.operating_system
        device.os_info = self.ip_obj.os_info
        device.device = self.ip_obj.device
        device.device_info = self.ip_obj.device_info
        device.active = self.ip_obj.active
        device.pingable = self.ip_obj.pingable
        device.min = self.ip_obj.min
        device.avg = self.ip_obj.avg
        device.max = self.ip_obj.max
        device.loss = self.ip_obj.loss
        device.active_ports = self.ip_obj.active_ports
