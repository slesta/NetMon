#!/usr/bin/env python

"""

Modul nacita data z Mikrotik zarizeni pres SSH a vytvori objekt Device s jeho atributy jako je
hostname, interfejsy, adresy, routy a podobne.

"""

import logging
import re
import time
import os
from typing import Dict, List, Tuple
import ipcalc
import netobjects
import scanobjects
from tools import SshClient, get_fresh_manufacturers, load_json

# Nastavi logovani
LOGGER = logging.getLogger(__name__)


def mikrotik_line_to_keys(item: str) -> Dict[str, str]:
    """ Prevede polozku konfigurace do slovniku """

    regex = r"[a-zA-Z0-9-_]+="
    subst = r"||\g<0>"
    result = re.sub(regex, subst, item, ).replace(' \r\n', '').split(' ||')[1:]
    result_dict = dict()
    for i in result:
        result_dict[str(i.split('=')[0])] = i.split('=')[1].strip(' \r\n\t')
    result_dict['interface_state'] = 'DOWN'
    if 'R' in item[:5]:
        result_dict['interface_state'] = 'UP'
    return result_dict


def refresh_manufacturers():
    """ Jestlize je seznam vyrobcu starsi nez 30 dni, tak ho obcerstvi """

    if (int(time.time()) - int(os.stat(
            'config/manufacturers.json').st_atime)) / 60 / 60 / 24 > 30:
        get_fresh_manufacturers()


class Mikrotik:
    """ Trida Mikrotik ziskava data pres ssh z Mikrotik zarizeni """

    def __init__(self, ip_obj: scanobjects.IpObject, accounts: List,
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

            # print(account)
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
                time.sleep(2)

    def get_host_data(self) -> Dict:
        """ Ziska device info z mikrotik """

        def mikrotik_line_to_keys_lite(item: List) -> Dict[str, str]:
            """ Prevede viceradkovy vystup prikazu do slovniku"""

            result_dict = {}
            for line in item:
                line = line.replace(' ', '').replace('"', '').replace('\r', '')
                result_dict[str(line.split(':')[0])] = line.split(':')[1]
            return result_dict

        device_dict = dict()
        cmd = '/system identity print'
        out = self.client.command_exec(cmd).replace('\r', '')
        if out:
            device_dict = mikrotik_line_to_keys_lite(out.split('\n')[:-1])

        cmd = '/system routerboard print'
        out = self.client.command_exec(cmd)
        if out:
            out = mikrotik_line_to_keys_lite(out.split('\n')[:-1])
            device_dict.update(out)

        cmd = '/system resource print'
        out = self.client.command_exec(cmd)
        if out:
            out = mikrotik_line_to_keys_lite(out.split('\n')[:-1])
            device_dict.update(out)

        cmd = '/system license print'
        out = self.client.command_exec(cmd)
        if out:
            out = mikrotik_line_to_keys_lite(out.split('\n')[:-1])
            device_dict.update(out)

        hostname = device_dict['name']
        model = device_dict['board-name']
        # Pro routeboard
        if device_dict['routerboard'] == 'yes':
            uid = device_dict['serial-number']
            firmware = device_dict['current-firmware']
        # Pro PC, treba DUDE
        else:
            uid = device_dict['system-id']
            firmware = device_dict['version']
        return {'hostname': hostname, 'model': model, 'uid': uid, 'firmware': firmware}

    def get_routes(self) -> List[dict]:
        """ ziska routy z mikrotik """

        cmd = '/ip route print terse'
        out = self.client.command_exec(cmd)
        route_list = list()
        if out:
            out = out.split('\n')[:-1]
            out_no_connect = list()  # odfiltruje lokalni routy interfejsu
            for rou in out:  # odfiltruje lokalni a disabled routy interfejsu
                if 'C' not in rou[0:7] and 'X' not in rou[0:7]:
                    out_no_connect.append(rou)
            out = list(map(mikrotik_line_to_keys, out_no_connect))
            for line in out:
                if 'unreachable' not in line['gateway-status']:
                    route_list.append(line)
        return route_list

    def get_interfaces(self) -> List[dict]:
        """ Ziska ints z mikrotik """

        cmd = '/interface print terse'
        out = self.client.command_exec(cmd).split('\n')
        int_list = list()
        if out:
            int_list = list(map(mikrotik_line_to_keys, out[:-1]))
        return int_list

    def get_ethernets(self) -> List[dict]:
        """ Ziska ethernet ints z mikrotik """

        cmd = '/interface ethernet print terse'
        out = self.client.command_exec(cmd).split('\n')
        ethernet_list = list()
        if out:
            out = list(map(mikrotik_line_to_keys, out[:-1]))
            ethernet_list = out

        return ethernet_list

    def get_ips(self) -> List[dict]:
        """ Ziska ip z mikrotik """

        cmd = '/ip address print terse where !disabled'
        out = self.client.command_exec(cmd)
        ip_list = list()
        if out:
            ip_list = list(map(mikrotik_line_to_keys, out.split('\n')[:-1]))
        return ip_list

    def get_wireless(self) -> Tuple[List[dict], List[dict]]:
        """ Ziska wireless int z mikrotik """

        def mikrotik_filter_virtual(wlist: List) -> Tuple[List[dict], List[dict]]:
            """ Odfiltruje virtualni a hw wireless intrfejsy """

            virtual = list()
            master = list()
            for item in wlist:
                if item['interface-type'] in ['virtual', 'virtual-AP']:
                    virtual.append(item)
                else:
                    master.append(item)
            return master, virtual

        cmd = '/interface wireless print terse'
        out = self.client.command_exec(cmd).split('\n')
        wireless_list = list()
        wireless_virtual_list = list()
        if out:
            wireless_list = list(map(mikrotik_line_to_keys, out[:-1]))
            wireless_list, wireless_virtual_list = mikrotik_filter_virtual(wireless_list)
        return wireless_list, wireless_virtual_list

    def get_bridges(self) -> List[dict]:
        """ Ziska bridge ints z mikrotik """

        cmd = '/interface bridge print terse'
        out = self.client.command_exec(cmd).split('\n')
        bridge_list = list()
        if out:
            bridge_list = list(map(mikrotik_line_to_keys, out[:-1]))

        return bridge_list

    def get_bridge_ports(self) -> List[dict]:
        """ Ziska bridge ports z mikrotik """

        cmd = '/interface bridge port print terse'
        out = self.client.command_exec(cmd).split('\n')
        bridgeports_list = list()
        if out:
            bridgeports_list = list(map(mikrotik_line_to_keys, out[:-1]))
        return bridgeports_list

    def get_arp(self) -> List[dict]:
        """ Ziska arp z mikrotik (nejdriv poskadli broadcast pingem aby naplnil tabulku
         vsim dostupnym) """

        cmd = 'ping 255.255.255.255 count=7'
        self.client.command_exec(cmd).split('\n')
        cmd = '/ip arp print terse '
        out = self.client.command_exec(cmd).split('\n')
        arp_list = list()
        if out:
            arp_list = list(map(mikrotik_line_to_keys, out[:-1]))
        return arp_list

    def create_device(self) -> netobjects.Device:
        """ Vytvori objekt device a prida do nej interfejsy, bridge do nich ip,
        wireless, routy a pod. """

        host = self.get_host_data()
        device = None
        if host:
            device = netobjects.Device(account=self.account, host=host)
            self.device_add_interfaces(device)
            self.device_add_bridges(device)

        return device

    def device_add_interfaces(self, device: netobjects.Device):
        """ Vytvori interfejs objekty pro dane zarizeni """

        int_list = self.get_interfaces()
        wirlv_list = self.get_wireless()[1]
        for int_item in int_list:  # Vytvori interfejs objekty pro dane zarizeni
            interface = netobjects.Interface()
            interface.name = int_item['name']
            interface.state = int_item['interface_state']
            interface.mtu = int_item['mtu']
            interface.parent = device
            device.add_interface(interface)

            for item in self.get_ethernets():  # Najde mac v ethernet ints
                if item['name'] == int_item['name']:
                    interface.mac = item['mac-address']

            self.interface_add_ips(interface)
            self.interface_add_routes(interface)
            self.interface_add_wireless(interface)
            self.interface_add_wireless_virtual(interface, device, wirlv_list)
            self.interface_add_arp(interface)

        # Namapuje virtual wireless objekty na wireless objekty
        for wirlv_item in wirlv_list:
            device.interface[wirlv_item['name']].wireless_virt.master = \
                device.interface[wirlv_item['master-interface']].wireless

            device.interface[wirlv_item['master-interface']].wireless.add_interface(
                device.interface[wirlv_item['name']].wireless_virt)

    def interface_add_ips(self, interface: netobjects.Interface):
        """ Vytvori ip objekty pro dany interfejs """

        for ip_item in self.get_ips():
            if interface.name == ip_item['interface']:
                ipaddr = netobjects.Ip()
                ipaddr.ipaddr = ip_item['address'].split('/')[0]
                ipaddr.mask = ip_item['address'].split('/')[1]
                ipaddr.brd = ipcalc.Network(ip_item['address']).broadcast()
                ipaddr.parent = interface
                interface.add_ip(ipaddr)

    def interface_add_routes(self, interface: netobjects.Interface):
        """ Vytvori route objekty pro dany interfejs """

        for route_item in self.get_routes():
            if interface.name == route_item['gateway-status'].split(' reachable via  ')[1]:
                route = netobjects.Route()
                route.net = route_item['dst-address']
                route.gate = route_item['gateway']
                route.parent = interface
                interface.add_route(route)

    def interface_add_wireless(self, interface: netobjects.Interface):
        """ Vytvori wireless objekt pro dany interfejs """

        for wireless_item in self.get_wireless()[0]:
            if interface.name == wireless_item['name']:
                wireless = netobjects.Wireless()
                wireless.essid = wireless_item['ssid']
                wireless.mode = wireless_item['mode']
                wireless.frequency = wireless_item['frequency']
                wireless.band = wireless_item['band']
                wireless.parent = interface
                interface.wireless = wireless
                interface.mac = wireless_item['mac-address']

    @staticmethod
    def interface_add_wireless_virtual(interface: netobjects.Interface,
                                       device: netobjects.Device, wirlv_list: list):
        """ Vytvori wireless virtual objekt pro dany interfejs """

        for wireless_v_item in wirlv_list:
            if interface.name == wireless_v_item['name']:
                wireless_virt = netobjects.WirelessVirtual()
                wireless_virt.essid = wireless_v_item['ssid']
                if 'mode' not in wireless_v_item.keys():
                    wireless_virt.mode = device.interface[
                        wireless_v_item['master-interface']].wireless.mode
                else:
                    wireless_virt.mode = wireless_v_item['mode']
                wireless_virt.parent = interface
                interface.wireless_virt = wireless_virt
                interface.mac = wireless_v_item['mac-address']

    def interface_add_arp(self, interface: netobjects.Interface):
        """ Vytvori arp objekty pro dany interfejs """

        for arp_item in self.get_arp():
            if interface.name == arp_item['interface']:
                if 'mac-address' in arp_item.keys():  # Jestli tam neni jen IP bez MAC
                    arp = netobjects.Arp()
                    arp.ipaddr = arp_item['address']
                    arp.mac = arp_item['mac-address']
                    # jestli zna vyrobce
                    if arp_item['mac-address'].replace(':', '')[0:6].upper() in self.manufacturers:
                        arp.manufacturer = self.manufacturers[arp_item['mac-address'].replace
                                                              (':', '')[0:6].upper()]
                    arp.parent = interface
                    interface.add_arp(arp)

    def device_add_bridges(self, device: netobjects.Device):
        """ Vytvori bridge objekt a namapuje do nej interfejs objekty """

        for item_br in self.get_bridges():
            bridge = netobjects.Bridge()
            bridge.parent = device
            for br_int in device.interface.keys():
                if br_int == item_br['name']:
                    bridge.bridge = device.interface[br_int]
                    device.interface[br_int].mac = item_br['mac-address']
            for br_port in self.get_bridge_ports():
                if br_port['bridge'] == str(bridge.bridge):
                    if br_port['interface'] in device.interface.keys():
                        bridge.add_interface(device.interface[br_port['interface']])
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
