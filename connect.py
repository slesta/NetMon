#!/usr/bin/env python
# coding=utf8

import paramiko
import re
import time
from typing import List, Dict
import pickle
from netobjects import *
import json
import requests


class SshClient:

    def __init__(self, connect_host, port, user, password):
        self.host = connect_host
        self.port = port
        self.user = user
        self.password = password
        self.ssh_client = paramiko.SSHClient()
        self.e = None
        self.chan = None
        self.connect_ssh()

    # Vytvori ssh spojeni a ulozi klienta pro dalsi pouziti
    def connect_ssh(self):
        # logging.basicConfig()
        # logging.getLogger('paramiko.transport').setLevel(logging.DEBUG)
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(hostname=self.host, port=self.port, username=self.user, password=self.password)
        except paramiko.AuthenticationException as erro:
            self.e = erro
        except paramiko.BadHostKeyException as erro:
            self.e = erro
        except paramiko.SSHException as erro:
            self.e = erro
        except Exception as erro:
            self.e = erro.args[1]
        if not self.e:
            self.chan = self.ssh_client.invoke_shell()  # Nasledujici vycisti banner po prihlaseni
            time.sleep(0.1)
            self.chan.recv(9999)
            self.chan.send("\n")
            time.sleep(0.1)
        else:
            raise Exception(self.e)

    # Pro prikazy v invoke_shell, kdyz je treba vicekrokove provedeni (sudo a pak heslo)
    def cmd_exec(self, cmd: str) -> str:
        self.chan.send(cmd+'\r')
        while not self.chan.recv_ready():
            time.sleep(0.1)
        time.sleep(0.5)
        output = self.chan.recv(9999)
        # output = output.decode('utf-8')
        output = output.decode('ascii')
        return output

    # Provede prikaz a vrati vysledek
    def command_exec(self, cmd: str) -> str:
        stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
        output = stdout.read().decode('ascii').strip('\n').replace('\r', '')
        # err = stderr.read().decode('ascii').strip('\n')
        # print(cmd)
        # print(output)
        return output

    # Zavre spojeni
    def close_ssh(self):
        self.ssh_client.close()

    def __del__(self):
        self.close_ssh()


def get_fresh_manufacturers():
    # Stahne seznam vyrobcu podle mac a nacpe ho do slovniku
    r = requests.get('http://standards-oui.ieee.org/oui/oui.txt')
    lines = r.text.split('\n')
    manufacturers_dict = dict()
    for line in lines:
        if '(base 16)' in line:
            manufacturers_dict[line.split('(base 16)')[0].strip(' ')] = line.split('(base 16)')[1].strip('\r\t ')
    with open('manufacturers.json', 'w') as fp:
        json.dump(manufacturers_dict, fp)


def save_object(object_to_save, filename):
    with open(filename, 'wb') as output:  # prepise soubor
        pickle.dump(object_to_save, output, pickle.HIGHEST_PROTOCOL)


def load_object(filename):
    with open(filename, 'rb') as input_file:
        return pickle.load(input_file)


def clean_item(item):
    return str(item).replace('\t', ' ').replace('   ', ' ').replace('  ', ' ').replace('\n', '').replace('  ', ' ') \
        .replace('   ', ' ').replace('  ', ' ')


def clean_item_mikrotik(item):
    if item[0] == ' ':
        item = item[1:-3]
    return item


def mikrotik_line_to_keys(item: str) -> Dict[str, str]:
    regex = r"[a-zA-Z0-9-_]+="
    subst = r"||\g<0>"
    result = re.sub(regex, subst, item, ).replace(' \r\n', '').split(' ||')[1:]
    result_dict = {}
    for i in result:
        result_dict[str(i.split('=')[0])] = i.split('=')[1].strip(' \r\n\t')
    result_dict['interface_state'] = 'DOWN'
    if 'R' in item[:5]:
        result_dict['interface_state'] = 'UP'
    return result_dict


def mikrotik_line_to_keys_lite(item: List) -> Dict[str, str]:
    result_dict = {}
    for line in item:
        line = line.replace(' ', '').replace('"', '').replace('\r', '')
        result_dict[str(line.split(':')[0])] = line.split(':')[1]
    return result_dict


def linux_iwconfig_to_keys(item):
    regex = (r"(?P<iface>\S+)\s+IEEE[ ]+(?P<ieee>\S+)\s+ESSID:\"(?P<essid>\S+)(\s+\S+\n|\s+\n)"
             r"\s+Mode:(?P<mode>\S+)\s+Frequency:(?P<frequency>\S+)\s")
    matches = re.finditer(regex, item, re.MULTILINE)
    outlist = []
    for match in matches:
        outlist.append(match.groupdict())
    return outlist


def linux_ipaddr_to_keys(item):
    regex = r"\S+:\s+(?P<interface>\S+)\s+inet\s+(?P<ip>[0-9.]+)/(?P<mask>[0-9]+)\s+brd\s+(?P<broadcast>[0-9.]+)"
    matches = re.finditer(regex, item, re.MULTILINE)
    outlist = []
    for match in matches:
        outlist.append(match.groupdict())
    return outlist


def linux_iplink_to_keys(item):
    regex = (r"\S+:\s+(?P<interface>\S+):\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+state\s"
             r"(?P<state>\S+)[ a-zA-Z0-9]+\\\s+link/ether\s+(?P<mac>[0-9a-f:]+)")
    matches = re.finditer(regex, item, re.MULTILINE)
    outlist = []
    for match in matches:
        outlist.append(match.groupdict())
    return outlist


def linux_bridge_to_keys(item: str) -> List[Dict[str, List]]:
    item = item.split('\n')
    outdict = {'bridge': '', 'ports': []}
    outlist = []
    item.append('')
    for line in item[1:]:
        if 'No such device' not in line:
            line = line.replace('\t', '        ').replace('no', '        ').replace('yes', '        ')
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


def linux_arp_to_keys(item: str) -> List[Dict[str, str]]:
    item = item.split('\n')
    listout = []
    for line in item[1:]:
        line = line.replace(' ', '').replace('0x1', ' ').replace('0x2', ' ')\
            .replace('*', ' ').replace('  ', ' ').split(' ')
        listout.append({'interface': line[2], 'ip': line[0], 'mac': line[1]})
    return listout


def linux_data(c, manufacturers_dict):
    # ziska device info z Linux zarizeni
    firmware = ''
    model = 'Unknown'
    serial = ''
    hostname = ''

    cmd = 'uname -a'  # Zkusi hostname z Linux uname -a
    out = c.command_exec(cmd)
    if out:
        hostname = out.split(' ')[1]

    cmd = 'lsb_release -a'  # Z Debian based zjisti release
    out = c.command_exec(cmd).split('\n')
    if out:
        for line in out:
            if 'Description' in line:
                firmware = line.split(':')[1].strip(' \n\r\t')

    cmd = 'cat /etc/machine-id'  # Zjisti jedinecny identifikator
    out = c.command_exec(cmd)
    if out:
        serial = out.strip(' \r\n\t')

    cmd = 'mca-status'  # Zjisti jedinecny identifikator, hostname, model, fw z UBNT
    out = c.command_exec(cmd)
    if out:
        line = out.split('\n')[0]
        hostname = line.split(',')[0].split('=')[1]
        serial = line.split(',')[1].split('=')[1]
        firmware = line.split(',')[2].split('=')[1]
        model = line.split(',')[3].split('=')[1]

    # ziska seznam interfejsu z Linux zarizeni
    cmd = 'ip -o -f inet link'
    out = c.command_exec(cmd)
    interface_list = list()
    if out:
        interface_list = linux_iplink_to_keys(out)

    # ziska routovaci tabulku z Linux zarizeni
    cmd = 'ip route sh'
    out = c.command_exec(cmd)
    route_list = list()
    if out:
        out = map(clean_item, out.split('\n'))
        for line in out:
            linesplit = line.split(' ')
            if linesplit[1] == 'via':
                route_list.append({'interface': linesplit[4], 'net': linesplit[0].replace('default', '0.0.0.0/0'),
                                   'gateway': linesplit[2]})

    # ziska seznam IP adres z Linux zarizeni
    cmd = 'ip -o -f inet address'
    out = c.command_exec(cmd)
    ip_list = list()
    if out:
        ip_list = linux_ipaddr_to_keys(out)

    # ziska wireless int z ubnt
    cmd = 'iwconfig'
    out = c.command_exec(cmd)
    wireless_list = list()
    if out:
        wireless_list = linux_iwconfig_to_keys(out)

    # ziska bridge ints z linux
    cmd = 'brctl show'
    out = c.command_exec(cmd)
    bridge_list = list()
    if out:
        bridge_list = linux_bridge_to_keys(out)

    # ziska arp z linux (nejdriv poskadli broadcast pingem aby naplnil tabulku vsim dostupnym)
    cmd = 'ping 255.255.255.255 -c1'
    c.command_exec(cmd)
    cmd = 'ping 255.255.255.255 -b'
    c.command_exec(cmd)
    cmd = 'cat /proc/net/arp'
    out = c.command_exec(cmd)
    arp_list = list()
    if out:
        arp_list = linux_arp_to_keys(out)

    # Vytvori objek device a prida do nej interfejsy, bridge do nich ip, wireless, routy a pod...
    device_obj = Device()
    device_obj.hostname = hostname
    device_obj.model = model
    device_obj.uid = serial
    device_obj.firmware = firmware

    for item_int in interface_list:  # Vytvori interfejs objekty pro dane zarizeni
        interface_obj = Interface()
        interface_obj.name = item_int['interface']
        interface_obj.state = item_int['state']
        interface_obj.mac = item_int['mac']
        for item_ip in ip_list:  # Vytvori ip objekty pro dany interfejs
            if interface_obj.name == item_ip['interface']:
                ip_obj = Ip()
                ip_obj.ip = item_ip['ip']
                ip_obj.mask = item_ip['mask']
                ip_obj.brd = item_ip['broadcast']
                interface_obj.add_ip(ip_obj)
        for item_route in route_list:  # Vytvori route objekty pro dany interfejs
            if interface_obj.name == item_route['interface']:
                route_obj = Route()
                route_obj.net = item_route['net']
                route_obj.gw = item_route['gateway']
                interface_obj.add_route(route_obj)
        for item_wireless in wireless_list:  # Vytvori wireless objekty pro dany interfejs
            if interface_obj.name == item_wireless['iface']:
                wireless_obj = Wireless()
                wireless_obj.essid = item_wireless['essid']
                wireless_obj.mode = item_wireless['mode']
                wireless_obj.frequency = item_wireless['frequency']
                wireless_obj.band = item_wireless['ieee']
                interface_obj.add_wireless(wireless_obj)
        for item_arp in arp_list:  # Vytvori arp objekty pro dany interfejs
            if interface_obj.name == item_arp['interface']:
                arp_obj = Arp()
                arp_obj.ip = item_arp['ip']
                arp_obj.mac = item_arp['mac']
                if item_arp['mac'].replace(':', '')[0:6].upper() in manufacturers_dict.keys():  # jestli zna vyrobce
                    arp_obj.manufacturer = manufacturers_dict[item_arp['mac'].replace(':', '')[0:6].upper()]
                interface_obj.add_arp(arp_obj)
        device_obj.add_interface(interface_obj)

    # Vytvori bridge objekt a namapuje do nej interfejs objekty
    for item_br in bridge_list:
        br_obj = Bridge()
        for bint_obj in device_obj.interface.keys():
            if bint_obj == item_br['bridge']:
                br_obj.bridge = device_obj.interface[bint_obj]
        for br_port in item_br['ports']:
            br_obj.add_interface(device_obj.interface[br_port])
        device_obj.add_bridge(br_obj)

    device_obj.print()


def mikrotik(c, manufacturers_dict):
    # ziska device info z mikrotik
    cmd = '/system identity print'
    out = c.command_exec(cmd).replace('\r', '')
    device_dict = dict()
    if out:
        device_dict = mikrotik_line_to_keys_lite(out.split('\n')[:-1])

    cmd = '/system routerboard print'
    out = c.command_exec(cmd)
    if out:
        out = mikrotik_line_to_keys_lite(out.split('\n')[:-1])
        device_dict.update(out)

    # ziska routy z mikrotik
    cmd = '/ip route print terse where !pref-src'
    out = c.command_exec(cmd)
    route_list = list()
    if out:
        out = list(map(mikrotik_line_to_keys, out.split('\n')[:-1]))
        for line in out:
            if 'unreachable' not in line['gateway-status']:
                route_list.append(line)

    # ziska ip z mikrotik
    cmd = '/ip address print terse where !disabled'
    out = c.command_exec(cmd)
    ip_list = list()
    if out:
        ip_list = list(map(mikrotik_line_to_keys, out.split('\n')[:-1]))

    # ziska wireless int z mikrotik
    cmd = '/interface wireless print terse where !disabled'
    out = c.command_exec(cmd).split('\n')
    wireless_list = list()
    if out:
        wireless_list = list(map(mikrotik_line_to_keys, out[:-1]))

    # ziska ints z mikrotik
    cmd = '/interface print terse where !disabled'
    out = c.command_exec(cmd).split('\n')
    int_list = list()
    if out:
        int_list = list(map(mikrotik_line_to_keys, out[:-1]))

    # ziska ethernet ints z mikrotik
    cmd = '/interface ethernet print terse where !disabled'
    out = c.command_exec(cmd).split('\n')
    ethernet_list = list()
    if out:
        out = list(map(mikrotik_line_to_keys, out[:-1]))
        ethernet_list = out

    # ziska bridge ints z mikrotik
    cmd = '/interface bridge print terse where !disabled'
    out = c.command_exec(cmd).split('\n')
    bridge_list = list()
    if out:
        bridge_list = list(map(mikrotik_line_to_keys, out[:-1]))

    # ziska bridge ports z mikrotik
    cmd = '/interface bridge port print terse'
    out = c.command_exec(cmd).split('\n')
    bridgeports_list = list()
    if out:
        bridgeports_list = list(map(mikrotik_line_to_keys, out[:-1]))

    # ziska arp z mikrotik (nejdriv poskadli broadcast pingem aby naplnil tabulku vsim dostupnym)
    cmd = 'ping 255.255.255.255 count=7'
    c.command_exec(cmd).split('\n')
    cmd = '/ip arp print terse '
    out = c.command_exec(cmd).split('\n')
    arp_list = list()
    if out:
        arp_list = list(map(mikrotik_line_to_keys, out[:-1]))

    # Vytvori objekt device a prida do nej interfejsy, bridge do nich ip, wireless, routy a pod...
    device_obj = Device()
    device_obj.hostname = device_dict['name']
    device_obj.model = device_dict['model']
    device_obj.uid = device_dict['serial-number']
    device_obj.firmware = device_dict['current-firmware']
    for int_item in int_list:  # Vytvori interfejs objekty pro dane zarizeni
        int_obj = Interface()
        int_obj.name = int_item['name']
        int_obj.state = int_item['interface_state']
        int_obj.mtu = int_item['mtu']
        for item in wireless_list:  # Najde mac ve wireless ints
            if item['name'] == int_item['name']:
                int_obj.mac = item['mac-address']
        for item in ethernet_list:  # Najde mac ve ethernet ints
            if item['name'] == int_item['name']:
                int_obj.mac = item['mac-address']
        for item in bridge_list:  # Najde mac ve bridge ints
            if item['name'] == int_item['name']:
                int_obj.mac = item['mac-address']

        for ip_item in ip_list:  # Vytvori ip objekty pro dany interfejs
            if int_obj.name == ip_item['interface']:
                ip_obj = Ip()
                ip_obj.ip = ip_item['address'].split('/')[0]
                ip_obj.mask = ip_item['address'].split('/')[1]
                ip_obj.brd = ip_item['broadcast']
                int_obj.add_ip(ip_obj)

        for route_item in route_list:  # Vytvori route objekty pro dany interfejs
            if int_obj.name == route_item['gateway-status'].split(' reachable ')[1]:
                route_obj = Route()
                route_obj.net = route_item['dst-address']
                route_obj.gw = route_item['gateway']
                int_obj.add_route(route_obj)

        for wireless_item in wireless_list:  # Vytvori wireless objekty pro dany interfejs
            if int_obj.name == wireless_item['name']:
                wireless_obj = Wireless()
                wireless_obj.essid = wireless_item['ssid']
                wireless_obj.mode = wireless_item['mode']
                wireless_obj.frequency = wireless_item['frequency']
                wireless_obj.band = wireless_item['band']
                int_obj.add_wireless(wireless_obj)

        for arp_item in arp_list:  # Vytvori arp objekty pro dany interfejs
            if int_obj.name == arp_item['interface']:
                arp_obj = Arp()
                arp_obj.ip = arp_item['address']
                arp_obj.mac = arp_item['mac-address']
                # jestli zna vyrobce
                if arp_item['mac-address'].replace(':', '')[0:6].upper() in manufacturers_dict.keys():
                    arp_obj.manufacturer = manufacturers_dict[arp_item['mac-address'].replace(':', '')[0:6].upper()]
                int_obj.add_arp(arp_obj)
        device_obj.add_interface(int_obj)

    # Vytvori bridge objekt a namapuje do nej interfejs objekty
    for item_br in bridge_list:
        br_obj = Bridge()
        for bint_obj in device_obj.interface.keys():
            if bint_obj == item_br['name']:
                br_obj.bridge = device_obj.interface[bint_obj]
        for br_port in bridgeports_list:
            if br_port['bridge'] == str(br_obj.bridge):
                br_obj.add_interface(device_obj.interface[br_port['interface']])
        device_obj.add_bridge(br_obj)

    device_obj.print()

# get_fresh_manufacturers()


with open('manufacturers.json') as json_data_file:
    manufacturers = json.load(json_data_file)

with open('accounts.json') as json_data_file:
    accounts = json.load(json_data_file)


hosts = [
    {'host': '10.60.60.1', 'port': 22, 'os': 'Linux'},
    {'host': '10.60.60.241', 'port': 22, 'os': 'Linux'},
    {'host': '10.60.64.230', 'port': 22, 'os': 'RouterOS'},
]

for host in hosts:
    cl = None
    for account in accounts:
        try:
            cl = SshClient(host['host'], host['port'], account['user'], account['password'])
            break
        except Exception as er:
            print(er)
            cl = False
            pass

    if cl:
        if host['os'] == 'Linux':
            linux_data(cl, manufacturers)
        if host['os'] == 'RouterOS':
            mikrotik(cl, manufacturers)
    cl.close_ssh()
