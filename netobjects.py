#!/usr/bin/env python

""" Modul s objekty reprezentujicimy sit. Od site pres zarizeni az po jejich interfejsy a
 jejich atributy. """

import logging
from typing import Any, List, NoReturn, Union
import uuid
import ipcalc
import scanobjects

# Nastavi logovani
LOGGER = logging.getLogger(__name__)


# TODO: Predlat to co jde na list comprehensions

class Ip:
    """ Objekt predstavuje IP adresu interfejsu """

    def __init__(self):
        self.parent = None
        self.ipaddr = None
        self.mask = None
        self.brd = None

    def __str__(self):
        return self.ipaddr

    def get_html_dev_info(self):
        """ Vrati info o objektu v html podobe """

        out = '&nbsp;&nbsp;&nbsp;|-{}/{} brd {}<br>'.format(self.ipaddr, self.mask, self.brd)
        return out

    def print(self):
        """ Vytiskne info o objektu """

        print('|  |  |-{}/{} brd {}'.format(self.ipaddr, self.mask, self.brd))


class Route:
    """ Objekt predstavuje routu interfejsu """

    def __init__(self):
        self.parent = None
        self.net = None
        self.gate = None

    def __str__(self):
        return self.net

    def get_html_dev_info(self):
        """ Vrati info o objektu v html podobe """

        out = '&nbsp;&nbsp;&nbsp;|-{} gateway {}<br>'.format(self.net, self.gate)
        return out

    def print(self):
        """ Vytiskne info o objektu """

        print('|  |  |-{} gateway {}'.format(self.net, self.gate))


class Wireless:
    """ Predstavuje hw wireless vrstvu interfejsu """
    def __init__(self):
        self.parent = None
        self.essid = None
        self.mode = None
        self.frequency = None
        self.band = None
        self.virtual = dict()

    def __str__(self):
        return self.essid

    def add_interface(self, objectitem) -> NoReturn:
        """ Prida vazbu virtual wireless vrstvu nalezejici k teto hw wireess vrstve """

        self.virtual[str(objectitem)] = objectitem

    def get_html_dev_info(self) -> str:
        """ Vrati info o objektu v html podobe """

        return ('&nbsp;&nbsp;<i>Wireless:</i> {}<br>'
                '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{}'
                ' {} {}<br>').format(self.essid, self.mode, self.frequency, self.band)

    def print(self) -> NoReturn:
        """ Vytiskne info o objektu """

        print('|  |  |-{} mode: {}  frequency: {}  band: {}'
              .format(self.essid, self.mode, self.frequency, self.band))

        if self.virtual:
            print('|  |  |')
            print('|  |  | Wireless virtual:')
            for item in self.virtual:
                self.virtual[item].print()


class WirelessVirtual:
    """ Objekt udrzuje info o Virtualni wireless vrstve interfejsu """

    def __init__(self):
        self.parent = None
        self.essid = None
        self.mode = None
        self.master = Wireless

    def __str__(self):
        return self.essid

    def get_html_dev_info(self) -> str:
        """ Vrati info o objektu v html podobe """

        out = ('&nbsp;&nbsp;<i>WirelessVirt:</i> {} <br>'
               '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
               '|-{} {}<br>').format(self.essid, self.mode, str(self.master))
        return out

    def print(self) -> NoReturn:
        """ Vytiskne info o objektu """

        print('|  |  |-{} mode: {}'.format(self.essid, self.mode, ))


class Arp:
    """ Objekt predstavuje radek z ARP tabulky interfejsu """

    def __init__(self):
        self.parent = None
        self.ipaddr = None
        self.mac = None
        self.manufacturer = None

    def __str__(self):
        return self.ipaddr

    def get_html_dev_info(self):
        """ Vrati info o objektu v html podobe """

        return ('&nbsp;&nbsp;&nbsp;'
                '|-<span title="{}">{} {}</span><br>').format(self.manufacturer,
                                                              self.ipaddr, self.mac)

    def print(self):
        """ Vytiskne info o objektu """

        print('|     |-{}  \tMAC: {}  Manufacturer: {}'.format(self.ipaddr,
                                                               self.mac, self.manufacturer))


class Interface:
    """ Sdruzuje informace o interfejsu, tedy jeho IP, Routy, Wireless a pod."""

    def __init__(self):
        self.parent = None
        self.name = None
        self.mac = None
        self.mtu = None
        self.state = None
        self.layers = {'ipaddr': dict(), 'route': dict(), 'wireless': None,
                       'wireless_virt': None, 'arp': dict()}
        # self.ipaddr = dict()
        # self.route = dict()
        # self.wireless = None
        # self.wireless_virt = None
        # self.arp = dict()

    def __str__(self):
        return self.name

    def add_ip(self, objectitem):
        """ Prida objekt IP do slovniku interfejsu """

        self.layers['ipaddr'][str(objectitem)] = objectitem

    def add_route(self, objectitem):
        """ Prida objekt Route do slovniku interfejsu """

        self.layers['route'][str(objectitem)] = objectitem

    def add_arp(self, objectitem):
        """ Prida objekt ARP do slovniku interfejsu """

        self.layers['arp'][str(objectitem)] = objectitem

    def add_wireless(self, objectitem):
        """ Prida objekt Wireless do slovniku interfejsu """

        self.layers['wireless'] = objectitem

    def add_wireless_virt(self, objectitem):
        """ Prida objekt Wireless_virt do slovniku interfejsu """

        self.layers['wireless_virt'] = objectitem

    def get_html_dev_info(self):
        """ Vrati informace o interfejsu v html podobe """

        out = '<b>{}</b> - {} {} {}<br>'.format(self.name, self.mac, self.mtu, self.state)
        if self.layers['ipaddr']:
            out += '&nbsp;&nbsp;<i>IP:</i><br>'
            for item in self.layers['ipaddr']:
                out += self.layers['ipaddr'][item].get_html_dev_info()
        if self.layers['route']:
            out += '&nbsp;&nbsp;<i>Route:</i><br>'
            for item in self.layers['route']:
                out += self.layers['route'][item].get_html_dev_info()
        if self.layers['wireless']:
            out += self.layers['wireless'].get_html_dev_info()
        if self.layers['wireless_virt']:
            out += self.layers['wireless_virt'].get_html_dev_info()
        if self.layers['arp']:
            out += '&nbsp;&nbsp;<i>ARP:</i><br>'
            for item in self.layers['arp']:
                out += self.layers['arp'][item].get_html_dev_info()
        return out

    def print(self):
        """ Vytiskne informace o interfejsu """

        print('|  ')
        print('|-{}'.format(self.name))
        print('|  |-MAC: {}  MTU: {}  State: {}'.format(self.mac, self.mtu, self.state))

        if self.layers['ipaddr']:
            print('|  |')
            print('|  |-IP:')
            for item in self.layers['ipaddr']:
                self.layers['ipaddr'][item].print()

        if self.layers['route']:
            print('|  |')
            print('|  |-Route:')
            for item in self.layers['route']:
                self.layers['route'][item].print()

        if self.layers['wireless']:
            print('|  |')
            print('|  |-Wireless:')
            self.layers['wireless'].print()

        if self.layers['wireless_virt']:
            print('|  |')
            print('|  |-Wireless virtual:')
            self.layers['wireless_virt'].print()

        if self.layers['arp']:
            print('|  |')
            print('|  |-Arp:')
            for item in self.layers['arp']:
                self.layers['arp'][item].print()


class Bridge:
    """ Objekt sdruzuje informace o bridgi """

    def __init__(self):
        self.parent = None
        self.bridge = Interface
        self.interface = {}

    def __str__(self):
        return str(self.bridge)

    def add_interface(self, objectitem):
        """ Prida port bridge (interfejs) do slovniku"""

        self.interface[str(objectitem)] = objectitem

    def get_html_dev_info(self):
        """ Vrati informace o bridgi v html podobe """

        out = '<b>{}</b> ports: {}<br>'.format(self.bridge, ', '.join(self.interface.keys()))
        return out

    def print(self):
        """ Vytiskne informace o bridgi """

        print('|  ')
        print('|--Bridge: {}'.format(self.bridge))
        print('|  |-Interfaces: {}'.format(', '.join(self.interface.keys())))


class GenericDevice(scanobjects.Ping):  # pylint: disable-msg=too-many-instance-attributes
    """ Objekt predstavujici obecne zarizeni, tedy takove ke kteremu se numime pripojit a
    ziskat jeho data. Informace o tomto zarizeni byla ziskana skenem, nebo vyplivaji z informaci
    o siti zjistenych. """

    def __init__(self):
        scanobjects.Ping.__init__(self)
        self.parent = None
        self.ipaddr = None
        self.uuid = str(uuid.uuid4())
        self.operating_system = None  # Other, Linux, Windows, AirOS, IOS, RouterOS
        self.os_info = ''
        self.device = ''  # Other, Cisco, Mikrotik, UBNT, PC, Printer
        self.device_info = ''
        self.active = False
        self.active_ports = list()
        self.errors = list()
        self.infrastructure_device = False
        self.default_route = None

    def get_html_info(self):
        """ Vrati informace o obecnem zarizeni v html podobe """

        out = ('<ul><li>ip: <a href="http://{0}" target="_blank">{0}</a></li>'
               '<li>device: {1}</li>'
               '<li>device-info: {3}</li>'
               '<li>os: {2}</li>'
               '<li>os-info: {4}</li>'
               '').format(self.ipaddr, self.device, self.operating_system, self.device_info,
                          self.os_info)
        if self.active_ports:
            out += '<li>open ports:<ul>'
            for port in self.active_ports:
                out += port.get_html_info()
            out += '</ul></li>'
        out += '</ul>'
        return out


class Device(GenericDevice):
    """ Objekt reprezentujici zarizeni a sdruzujici jeho interfejsy, adresy, routy a pod. """

    def __init__(self, account: dict, host: dict):
        GenericDevice.__init__(self)
        self.hostname = host['hostname']
        self.uid = host['uid']
        self.firmware = host['firmware']
        self.model = host['model']
        self.account = account
        self.interface = dict()
        self.bridge = dict()

    def __str__(self):
        return self.hostname + ' - ' + self.model

    def add_interface(self, objectitem):
        """ Prida interfejs do seznamu v zarizeni """

        self.interface[str(objectitem)] = objectitem

    def add_bridge(self, objectitem):
        """ Prida objek bridge do seznamu v zarizeni """

        self.bridge[str(objectitem)] = objectitem

    def get_default_route(self) -> Union[Route, None]:
        """" Vrati defaultni routu zarizeni, pokud existuje """

        for int_key in self.interface:
            for route_key in self.interface[int_key].layers['route']:
                if self.interface[int_key].layers['route'][route_key].net == '0.0.0.0/0':
                    return self.interface[int_key].layers['route'][route_key]
        return None

    def get_gateways(self) -> List:
        """ Vrati jeden Route objekt pro kazdou branu zarizeni v seznamu """

        out = list()
        hlp = list()
        for int_key in self.interface:
            for route_key in self.interface[int_key].layers['route'].keys():
                if self.interface[int_key].layers['route'][route_key].gate not in hlp:
                    out.append(self.interface[int_key].layers['route'][route_key])
                    hlp.append(self.interface[int_key].layers['route'][route_key].gate)
        return out

    def get_routes(self) -> List:
        """ Vrati routy zarizeni v seznamu """

        out = list()
        for int_key in self.interface:
            for route_key in self.interface[int_key].layers['route'].keys():
                out.append(self.interface[int_key].layers['route'][route_key])
        return out

    def get_ips(self) -> List:
        """ Vrati IP objeky zarizeni v seznamu """

        out = list()
        for int_key in self.interface:
            for ip_key in self.interface[int_key].layers['ipaddr']:
                out.append(self.interface[int_key].layers['ipaddr'][ip_key])
        return out

    def get_html_dev_info(self):
        """ Vrati info o zarizeni v html podobe """

        out = ('<h2>{}</h2>'
               '<ul>'
               '<li>Model: {}</li>'
               '<li>Firmware: {}</li>'
               '<li>Uid: {}</li>'
               '<li>Account: {}/{}</li>'
               '').format(self.hostname, self.model, self.firmware, self.uid,
                          self.account['username'], self.account['password'])
        if self.bridge:
            out += '<li>Bridges:</li>'
            for item in self.bridge:
                out += self.bridge[item].get_html_dev_info()
            out += ''

        if self.interface:
            out += '<li>Interfaces:</li>'
            for item in self.interface:
                out += self.interface[item].get_html_dev_info()
            out += ''

        out += '</ul>'
        return out

    def print(self):
        """ Vytiskne info o zarizeni """

        print('##################################################################################')
        print('|==== Hostname: {}'.format(self.hostname))
        print('|==== Model: {}, Firmware: {}, '
              'Uid: {}, Username: {}, Password: {}'.format(self.model,
                                                           self.firmware, self.uid,
                                                           self.account['username'],
                                                           self.account['password']))
        if self.interface:
            for item in self.interface:
                self.interface[item].print()
        if self.bridge:
            for item in self.bridge:
                self.bridge[item].print()


class Subnet:
    """ Udrzuje informace o subnetech jejich branach nalezenych v siti """

    def __init__(self):
        self.subnet = None
        self.gateways = list()
        self.main_gateway = None

    def add_gateway(self, interface: Interface):
        """ Prida interfejs reprezentujici branu v danem subnetu """

        self.gateways.append(interface)

    def is_ipaddr_in_subnet(self, ipaddr: str) -> bool:
        """ Zjisti jesli predana IP patri do teto podsite """

        out = False
        if ipaddr in ipcalc.Network(self.subnet):
            out = True
        return out


class ConnectionDev:
    """ Predstavuje spoje mezi interfejsy """

    def __init__(self):
        self.name = None
        self.conn_from = None
        self.conn_to = None
        self.uuid = str(uuid.uuid4())
        self.category = None  # default, local, wireless, ethernet
        self.count = None

    def get_dev_from(self) -> Union[str, None]:
        """ Vrati jedinecny identifikator vychoziho zarizeni """

        out = None
        if isinstance(self.conn_from, Interface):
            out = self.conn_from.parent
        if isinstance(self.conn_from, GenericDevice):
            out = self.conn_from
        if isinstance(self.conn_from, Device):
            out = self.conn_from
        if isinstance(self.conn_from, Wireless):
            out = self.conn_from.parent.parent
        if isinstance(self.conn_from, WirelessVirtual):
            out = self.conn_from.parent.parent
        return out

    def get_dev_to(self) -> Union[str, None]:
        """ Vrati jedinecny identifikator ciloveho zarizeni """

        out = None
        if isinstance(self.conn_to, Interface):
            out = self.conn_to.parent
        if isinstance(self.conn_to, GenericDevice):
            out = self.conn_to
        if isinstance(self.conn_to, Device):
            out = self.conn_to
        if isinstance(self.conn_to, Wireless):
            out = self.conn_to.parent.parent
        if isinstance(self.conn_to, WirelessVirtual):
            out = self.conn_to.parent.parent
        return out


class Network:
    """ Sdruzuje vsechny sitove objekty """

    def __init__(self, network: str = None):
        self.network = network
        self.devices = list()
        self.duplicate_device = list()
        self.subnets = list()
        self.connections = list()

    def add_device(self, objectitem):

        """ Prida zarizeni """

        self.devices.append(objectitem)

    def add_duplicate_device(self, objectitem):
        """ Prida zarizeni pokud bylo oznaceno jako duplikat
        - kontrolni seznam vyrazenych z nacitani"""

        self.duplicate_device.append(objectitem)

    def add_subnet(self, objectitem: Subnet):
        """ Prida subnet do seznamu """

        self.subnets.append(objectitem)

    def add_connection(self, objectitem: ConnectionDev):
        """ Prida subnet do seznamu """

        self.connections.append(objectitem)

    def find_interface_by_ip(self, ipadr: str) -> Union[Interface, None]:
        """ Pro zadanou IP najde v siti ji odpovidajici interfejs pokud existuje """

        iface = None
        for device in self.devices:
            if isinstance(device, Device):
                for interface_key in device.interface:
                    for ip_key in device.interface[interface_key].layers['ipaddr']:
                        if ipadr == device.interface[interface_key].layers['ipaddr'][ip_key].ipaddr:
                            iface = device.interface[interface_key]
        return iface

    def get_uid_list(self) -> List[str]:
        """ Vrati seznam jedinecnych identifikatoru nactenych ze zarizeni v siti """

        uid_list = list()
        for device in self.devices:
            if isinstance(device, Device):
                uid_list.append(device.uid)
        return uid_list

    def get_dev_ip_list(self) -> List[str]:
        """ Vrati seznam ip pro pripojeni vsech zarizeni v siti """

        return [device.ipaddr for device in self.devices]

    def get_dev_by_uuid(self, uuidh: str) -> Union[Device, GenericDevice, None]:
        """ Vrati zarizeni podle jedinecneho identifikatoru """

        devout = None
        for dev in self.devices:
            if dev.uuid == uuidh:
                devout = dev
        return devout

    def get_ips_same_net(self, ipaddr: str) -> List[Any]:
        """ Vrati objekty IP z cele site, ktere patri do zadaneho subnetu """

        out = list()
        for device in self.devices:
            if isinstance(device, Device):
                for ip_item in device.get_ips():
                    if ipaddr in ipcalc.Network('{}/{}'.format(ip_item.ipaddr, ip_item.mask)):
                        out.append(ip_item)
        return out

    def get_ips(self) -> List[Ip]:
        """ Vrati vsechny objekty IP v siti """

        out = list()
        for device in self.devices:
            if isinstance(device, Device):
                for ip_item in device.get_ips():
                    out.append(ip_item)
        return out

    def get_default_routes(self):
        """ Vrati seznam defaultnich rout z cele site """

        return [device.get_default_route() for device in self.devices if
                isinstance(device, Device) and device.get_default_route()]

    def get_routes(self):
        """ Vrati seznam rout z cele site """

        out = list()
        for device in self.devices:
            if isinstance(device, Device):
                out += device.get_routes()
        return out

    def get_subnets(self) -> List[str]:
        """ Vrati seznam subnet jako seznam jejich nazvu"""

        return [subnet.subnet for subnet in self.subnets]

    def get_subnet_by_name(self, subnet: str) -> Union[Subnet, None]:
        """ Vrati objekt subnet odpovidajici nazvu, tedy textovenu zapisu rozsahu podsite """

        subnetout = None
        for subnet_obj in self.subnets:
            if subnet_obj.subnet == subnet:
                subnetout = subnet_obj
        return subnetout

    def create_subnets(self):
        """ Podle ip adres interfejsu paternich zarizeni vytvori Subnet objekty, tedy seznam
        v siti pouzitych adresnich rozsahu """

        for device in self.devices:
            if device.infrastructure_device and isinstance(device, Device):
                for ip_addr in device.get_ips():
                    subnet_str = str(ipcalc.Network('{}/{}'.format(ip_addr.ipaddr,
                                                                   ip_addr.mask)).guess_network())
                    # Pokud tato subnet jeste neexistuje, tak vytvorime novou
                    if subnet_str not in self.get_subnets():
                        subnet_new = Subnet()
                        subnet_new.subnet = subnet_str
                        subnet_new.add_gateway(ip_addr.parent)
                        self.add_subnet(subnet_new)
                    # Pokud existuje, tak do ni pridame dalsi branu
                    else:
                        subnet = self.get_subnet_by_name(subnet_str)  # vyhleda objekt
                        print(subnet_str)
                        print(subnet)
                        # Pokud interface jeste neni v seznamu bran, tak ho prida
                        if subnet and ip_addr.parent not in subnet.gateways:
                            print(ip_addr.parent)
                            subnet.gateways.append(ip_addr.parent)
        self.set_main_gw_for_subnets()

    def set_main_gw_for_subnets(self):
        """ Nastavi pro kazdy subnet main_gateway, tedy tu branu,
        ktera se v nem pouziva jako defaultni """

        for subnet in self.subnets:
            for def_route in self.get_default_routes():
                if def_route.gate in ipcalc.Network(subnet.subnet):
                    subnet.main_gateway = self.find_interface_by_ip(def_route.gate)
            # Pokud nenašel vhodnou branu z default rout, tak ji nahradi prvni branou
            # z bran v teto podsiti
            if not subnet.main_gateway:
                if subnet.gateways:
                    subnet.main_gateway = subnet.gateways[0]

    def find_infrastructure_devices(self):
        """ Najde vsechny routy v siti a podle jejich bran vyhleda zarizeni, ktera oznaci jako
          soucast paterni sitove infrastruktury"""

        gateways = set()
        for route in self.get_routes():
            # Overi, ze to neni lokalni routa interfejsu
            if route.parent != self.find_interface_by_ip(route.gate):
                gateways.add(route.gate)
        for gate in gateways:
            iface = self.find_interface_by_ip(gate)
            if iface:
                iface.parent.infrastructure_device = True

    def create_connection_route(self):
        """ Podle rout vytvori spojeni predstavujici propojeni jednotlivych zarizeni"""

        for device in self.devices:
            count = 2
            if isinstance(device, Device):
                for route in device.get_routes():
                    remote_iface = self.find_interface_by_ip(route.gate)
                    if remote_iface:
                        conn = ConnectionDev()
                        conn.conn_from = route.parent
                        conn.conn_to = remote_iface
                        conn.name = route.net
                        conn.count = count
                        # Pro defaultni routu
                        if route.net == '0.0.0.0/0':
                            conn.category = 'default-route'
                        # pro ostatni routy
                        else:
                            conn.category = 'route'
                        self.add_connection(conn)
                        count += 1
            # Pro genericka zarizeni pouzijeme odhadnutou branu
            if isinstance(device, GenericDevice):
                if device.default_route:
                    conn = ConnectionDev()
                    conn.conn_from = device
                    conn.conn_to = device.default_route.parent
                    conn.name = '0.0.0.0/0'
                    conn.count = count
                    conn.category = 'default-route'
                    self.add_connection(conn)

    def connect_generic_devs(self):
        """ Podle prislusnosti do podsite urci branu pro genericke zarizeni """

        for dev in self.devices:
            if isinstance(dev, GenericDevice):
                for sub in self.subnets:
                    if sub.is_ipaddr_in_subnet(dev.ipaddr):
                        dev.default_route = sub.main_gateway
