#!/usr/bin/env python

"""Modul pro skenovani IP adres a jejich portu"""

import logging
import subprocess
from multiprocessing.dummy import Pool
import tqdm
import nmap
import ipcalc
from tools import load_json, save_object

# Nastavi logovani
LOGGER = logging.getLogger(__name__)


class Ping:
    """ Drzi data o odezve zarizeni na ping """

    def __init__(self):
        self.pingable = False
        self.min = 0
        self.avg = 0
        self.max = 0
        self.loss = 0

    def is_good(self):
        """ Vraci true kdyz ma zarizeni dobrou odezvu """

        out = False
        if self.min < 10 and self.avg < 10 and self.max < 10 and self.loss == 0:
            out = True
        return out

    def ping(self, ipaddr: str, time_out: int = 1, count: int = 1):
        """ Pingne danou ip a ulozi vystup"""

        cmd = "ping -c {} -W {} {}".format(count, time_out, ipaddr).split(' ')
        try:
            output = subprocess.check_output(cmd).decode().strip()
        except subprocess.CalledProcessError:
            self.pingable = False
        else:
            lines = output.split('\n')
            loss = lines[-2].split(',')[2].split()[0]
            timing = lines[-1].split()[3].split('/')
            self.min = float(timing[0])
            self.avg = float(timing[1])
            self.max = float(timing[2])
            self.loss = float(loss.replace('%', ''))
            self.pingable = True
            LOGGER.info('Ping %s avg: %s', ipaddr, self.avg)


class PortObject:
    """ Obsahuje info o naskenovanem portu """

    def __init__(self):
        self.port = 0
        self.name = ''
        self.state = ''
        self.product = ''
        self.version = ''
        self.exinfo = ''
        self.cpe = ''

    def get_html_info(self):
        """ Vrati info v html """

        out = '<li>{}:{} {}</li>'.format(self.port, self.name, self.cpe)
        return out

    def print(self):
        """ Vrati retezec k vytisknuti """

        return ('Port: {}\tName: {}\tProduct: {}\tVer: {}\tInfo: '
                '{} Cpe: {}').format(self.port, self.name, self.product, self.version,
                                     self.exinfo, self.cpe)


class IpScan(Ping):
    """ Obsahuje informace o naskenovane IP """

    def __init__(self, ip: str = '127.0.0.1'):
        Ping.__init__(self)
        self.ipaddr = ip
        self.active = False
        self.active_ports = list()
        self.operating_system = ''  # Other, Linux, Windows, AirOS, IOS, RouterOS
        self.os_info = ''
        self.device = ''  # Other, Cisco, Mikrotik, UBNT, PC, Printer
        self.device_info = ''
        # self.run()

    def run(self):
        """ Pingne, naskenuje a zkusi rozpoznat zarizeni """

        # Nalouduje definice pro identifikaci ruznych sitovych zarizeni
        config = load_json('config.json')
        self.ping(self.ipaddr)
        self.active = self.pingable
        self.scan_nmap(config['ports_to_scan'])
        self.detect_device(config['detect'])

    def get_html_info(self):
        """ Vrati info v html """

        out = '<tr><td>{0}</td>'.format(self.ipaddr)
        return out

    def scan_nmap(self, ports_to_scan: dict):
        """ Oskenuje IP """

        def to_str(itm: str) -> str:
            return str(itm) + ','

        # Oskenuje porty
        netmap = nmap.PortScanner()
        nmap_scan = netmap.scan(self.ipaddr, ''.join(map(to_str, ports_to_scan)))
        # Pokud je IP aktivni, tak zapise porty
        if self.ipaddr in nmap_scan['scan'].keys():
            if 'tcp' in nmap_scan['scan'][self.ipaddr].keys():
                for port in nmap_scan['scan'][self.ipaddr]['tcp']:
                    if nmap_scan['scan'][self.ipaddr]['tcp'][port]['state'] == 'open':
                        port_obj = PortObject()
                        port_obj.port = port
                        port_obj.name = nmap_scan['scan'][self.ipaddr]['tcp'][port]['name']
                        port_obj.state = nmap_scan['scan'][self.ipaddr]['tcp'][port]['state']
                        port_obj.product = nmap_scan['scan'][self.ipaddr]['tcp'][port]['product']
                        port_obj.version = nmap_scan['scan'][self.ipaddr]['tcp'][port]['version']
                        port_obj.exinfo = nmap_scan['scan'][self.ipaddr]['tcp'][port]['extrainfo']
                        port_obj.cpe = nmap_scan['scan'][self.ipaddr]['tcp'][port]['cpe']
                        self.active_ports.append(port_obj)
                        self.active = True
                LOGGER.info('Scanned IP %s open ports: %s', self.ipaddr,
                            len(nmap_scan['scan'][self.ipaddr]['tcp']))

    def detect_device(self, detections: dict):
        """ Dle infa z naskenovanych portu zjisti podle sablon pro detekci OS a typ zarizeni """

        def device_os(detected: dict):
            """ Zapise detekovany operacni system """

            if detected['result']['os']:
                self.operating_system = detected['result']['os']

        def device_dev(detected: dict):
            """ Zapise detekovane zarizeni """

            if detected['result']['dev']:
                self.device = detected['result']['dev']

        def device_os_info(detected: dict):
            """ Zapise info o operacnim systemu """

            # Test jestli ma nahradit osInfo textem zadane polozky portu
            if detected['result']['os_info'] and detected['result']['os_info_port']:
                for port in self.active_ports:
                    if port.port == detected['result']['os_info_port']:
                        self.os_info = vars(port)[detected['result']['os_info']]
            else:
                self.os_info = detected['result']['os_info']

        def device_dev_info(detected: dict):
            """ Zapise info o detekovanem zarizeni """

            # Test jestli ma nahradit devInfo textem zadane polozky portu
            if detected['result']['dev_info'] and detected['result']['dev_info_port']:
                for port in self.active_ports:
                    if port.port == detected['result']['dev_info_port']:
                        self.device_info = vars(port)[detected['result']['dev_info']]
            else:
                self.device_info = detected['result']['dev_info']

        for detect in detections:  # projde vsechny sablony pro detekci
            conditions_result = 0  # pocet shodnych podminek
            for condition in detect['conditions']:
                for portup in self.active_ports:
                    # kontrola shody podminky
                    if portup.port == condition['port_num'] and condition['contain'] in vars(
                            portup)[condition['item']]:
                        conditions_result += 1

            # pokud byly shodne vsechny, tak zapise vysledek
            if conditions_result == len(detect['conditions']):
                device_os(detect)
                device_dev(detect)
                device_os_info(detect)
                device_dev_info(detect)

    def print(self):
        """ Vytiskne naskenovanou IP i s portama """
        print('----------------------------------------------------------------------------------')

        print(('IP: {} \tOS: {} \tDev: {} \tOS-info: {} '
               '\tDev-info: {}').format(self.ipaddr, self.operating_system, self.device,
                                        self.os_info, self.device_info))
        for port_info in self.active_ports:
            print(port_info)
        print('----------------------------------------------------------------------------------')


class ScanNetwork:
    """ Sdruzuje funkce a atributy pro skenovani site """

    def __init__(self, net_name: str):
        self.net_name = net_name
        self.ips_to_scan = list()  # Adresy ke skenovani
        self.ip_objects = list()  # Naskenovane objekty
        self.ip_objects_active = list()  # Naskenovane objekty aktivni
        self.ip_objects_nonactive = list()  # Naskenovane objekty neaktivni
        self.accounts = None  # Ucty pro prihlaseni na zarizeni
        # self.load_net_config()  # Nalouduje site ke skenovani
        # self.scan_ips()
        # self.save_to_file()

    def run_scan(self):
        """ Spusti skenovani dle nactene konfigurace """

        self.load_net_config()  # Nalouduje site ke skenovani
        self.scan_ips()
        self.save_to_file()

    def load_net_config(self):
        """ Pripravi seznam IP ke skenovani """
        hlp = load_json('networks_to_scan.json')  # Nalouduje site ke skenovani
        if self.net_name in hlp.keys():
            # Projde site ke skenovani a udela znich seznam ipecek
            for net in hlp[self.net_name]['networks']:
                self.ips_to_scan += map(str, ipcalc.Network(net))
            self.ips_to_scan = list(set(self.ips_to_scan))  # Zbavime se duplicit
            self.accounts = hlp[self.net_name]['accounts']  # Nacte ucty pro prihlaseni na zarizeni
        else:
            raise Exception("Network name doesn't exist. Check network_to_scan.json"
                            " configuration file.")

    @staticmethod
    def create_ipobject(ipaddr: str) -> IpScan:
        """Vytvori novy IP objekt"""

        out = IpScan(ip=ipaddr)
        out.run()
        return out

    @staticmethod
    def clean_non_active(ip_ob: IpScan) -> IpScan:
        """ Vraci pouze aktivni zarizeni """

        out = None
        if ip_ob.active:
            out = ip_ob
        return out

    @staticmethod
    def clean_active(ip_ob: IpScan) -> IpScan:
        """ Vraci pouze neaktivni zarizeni """

        out = None
        if not ip_ob.active:
            out = ip_ob
        return out

    def scan_ips(self):
        """ Spusti sken IP ve vlaknech"""

        hlp_ip_obj_list = list()
        pool = Pool(24)  # Vytvori pool o danem poctu vlaken
        # Vytvori IP objekty z daneho seznamu adres a zobrazi progress bar
        text = 'Scanning network'
        for item in tqdm.tqdm(pool.imap_unordered(self.create_ipobject, self.ips_to_scan),
                              total=len(self.ips_to_scan), desc=text, unit='device'):
            hlp_ip_obj_list.append(item)
        pool.close()  # Udelame poradek
        pool.join()

        self.ip_objects = list(hlp_ip_obj_list)
        self.ip_objects_active = list(filter(self.clean_non_active, self.ip_objects))
        self.ip_objects_nonactive = list(filter(self.clean_active, self.ip_objects))
        print('')
        print('Scan found {} active devices on the network.'.format(len(self.ip_objects_active)))
        print('')

    def print(self):
        """ Vytiskne vsechny naskenovane adresy """

        for ip_obj in self.ip_objects:
            ip_obj.print()

    def print_active(self):
        """ Vytiskne vsechny aktivni naskenovane adresy """

        for ip_obj in self.ip_objects_active:
            ip_obj.print()

    def print_nonactive(self):
        """ Vytiskne vsechny neaktivni naskenovane adresy """

        for ip_obj in self.ip_objects_nonactive:
            ip_obj.print()

    def save_to_file(self):
        """ Ulozi celou naskenovanou sit do souboru pro pozdejsi pouziti """

        save_object(self, self.net_name + '.pkl')
