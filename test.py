#!/usr/bin/env python

"""  Testy pro modul scanobjects  """

import unittest
from unittest.mock import patch
import scanobjects
import tools


class TestScanNetwork(unittest.TestCase):
    """ test tridy scanobjects.ScanNetwork """

    def setUp(self):
        self.scan_net = scanobjects.ScanNetwork('TestNetwork')

    def test_init(self):
        """ Otestuje __init__ """

        self.assertEqual(self.scan_net.net_name, 'TestNetwork')

    @patch('scanobjects.load_json')
    def test_load_net_config(self, mocked_fnc):
        """ Otestuje pripravenost dat na skenovani - load_net_config() """

        mocked_fnc.return_value = {
            "TestNetwork": {
                "networks": [
                    "10.0.0.0/24",
                    "10.0.0.0/24",
                    "192.168.0.0/24",
                    "10.1.1.1/32"
                ],
                "accounts": [
                    {
                        "username": "admin",
                        "password": "secret"
                    },
                    {
                        "username": "root",
                        "password": "secret"
                    }
                ]
            }
        }
        self.scan_net.load_net_config()
        # print("mocked function called: {c}".format(c=mocked_fnc.called))
        # Test jestli byly odstraneny pripadne duplicitni IP
        self.assertEqual(len(self.scan_net.ips_to_scan), 254 * 2 + 1,
                         'Neodstraneni duplicitnich IP!')
        # Test jestli jsou nacteny ucty pro pripojeni
        expected = [
            {
                "username": "admin",
                "password": "secret"
            },
            {
                "username": "root",
                "password": "secret"
            }
        ]
        self.assertEqual(self.scan_net.accounts, expected, 'Nebyly nacteny uzivatelske ucty!')

    @patch('scanobjects.load_json', name='load_json')
    @patch('scanobjects.ScanNetwork.create_ipobject', name='create_ipobject')
    def test_scan_ips(self, mocked_create_ipobj, mocked_json_load):
        """ Oskenovani IP do IpScanu - scan_ips() """

        def crt_ip_hndl(ipaddr: str) -> scanobjects.IpScan:
            """ Vytvori jakoby naskenovany IpScan """

            out = scanobjects.IpScan(ip=ipaddr)
            out.active = True
            return out

        mocked_create_ipobj.side_effect = crt_ip_hndl
        mocked_json_load.return_value = {
            "TestNetwork": {
                "networks": [
                    "10.0.0.1/32",
                    "10.0.0.2/32",
                    "192.168.0.1/32"
                ],
                "accounts": [
                    {
                        "username": "admin",
                        "password": "secret"
                    },
                    {
                        "username": "root",
                        "password": "secret"
                    }
                ]
            }
        }

        self.scan_net.load_net_config()
        self.scan_net.scan_ips()
        print("mocked function called: {c}".format(c=mocked_create_ipobj.called))
        self.assertEqual(len(self.scan_net.ip_objects_active), 3, 'Spatne prirazene aktivni IP!')


class TestIpScan(unittest.TestCase):
    """ test tridy scanobjects.IpScan """

    def setUp(self):
        self.ip_scan = scanobjects.IpScan('127.0.0.1')
        self.config = tools.load_json('config.json')

    def test_ping(self):
        """ Otestuje ping na localhost """

        self.ip_scan.ping(self.ip_scan.ipaddr)
        self.assertNotEqual(self.ip_scan.min, 0, 'Problem s pingem (min)!')
        self.assertNotEqual(self.ip_scan.avg, 0, 'Problem s pingem (avg)!')
        self.assertNotEqual(self.ip_scan.max, 0, 'Problem s pingem (max)!')
        self.assertNotEqual(self.ip_scan.loss, 100, 'Problem s pingem (loss)!')
        self.assertEqual(self.ip_scan.pingable, True, 'Problem s pingem (pingable)!')

    @patch('scanobjects.nmap.PortScanner', name='nmap_scan')
    def test_nmap_scan(self, nmap_scan_mock):
        """test skenovani portu nmapem a vytvoreni objektu port v IpScan"""

        nmap_scan_mock.return_value.scan.return_value = {'nmap': {
            'command_line': 'nmap -oX - -p 20,21,22,25,53,67,68,80,88,110,111,135,139,143,161,389,443,445,464,465,548,587,593,636,993,995,1024,1110,2000,2049,3128,3268,3269,3389,5357,8291,8080,8888,14000, -sV 127.0.0.1',
            'scaninfo': {'tcp': {'method': 'connect',
                                 'services': '20-22,25,53,67-68,80,88,110-111,135,139,143,161,389,443,445,464-465,548,587,593,636,993,995,1024,1110,2000,2049,3128,3268-3269,3389,5357,8080,8291,8888,14000'}},
            'scanstats': {'timestr': 'Tue Dec  4 10:49:45 2018', 'elapsed': '83.56', 'uphosts': '1',
                          'downhosts': '0', 'totalhosts': '1'}}, 'scan': {
            '127.0.0.1': {'hostnames': [{'name': 'localhost', 'type': 'PTR'}],
                          'addresses': {'ipv4': '127.0.0.1'}, 'vendor': {},
                          'status': {'state': 'up', 'reason': 'syn-ack'}, 'tcp': {
                    22: {'state': 'open', 'reason': 'syn-ack', 'name': 'ssh', 'product': 'OpenSSH',
                         'version': '7.6p1 Ubuntu 4ubuntu0.1',
                         'extrainfo': 'Ubuntu Linux; protocol 2.0', 'conf': '10',
                         'cpe': 'cpe:/o:linux:linux_kernel'},
                    25: {'state': 'open', 'reason': 'syn-ack', 'name': 'smtp',
                         'product': 'Postfix smtpd', 'version': '', 'extrainfo': '', 'conf': '10',
                         'cpe': 'cpe:/a:postfix:postfix'},
                    80: {'state': 'open', 'reason': 'syn-ack', 'name': 'http',
                         'product': 'Apache httpd', 'version': '2.4.29', 'extrainfo': '(Ubuntu)',
                         'conf': '10', 'cpe': 'cpe:/a:apache:http_server:2.4.29'},
                    8888: {'state': 'open', 'reason': 'syn-ack', 'name': 'sun-answerbook',
                           'product': '', 'version': '', 'extrainfo': '', 'conf': '3',
                           'cpe': ''}}}}}
        self.ip_scan.scan_nmap(self.config['ports_to_scan'])
        self.assertEqual(self.ip_scan.active, True, 'Problem s nmap scannem (active nenastaveno)!')
        self.assertEqual(len(self.ip_scan.active_ports), 4, 'Nmap scan nenacetl vsechny porty!')
        self.assertEqual(self.ip_scan.active_ports[0].name, 'ssh', 'Nmap scan nenacetl port name!')
        self.assertEqual(self.ip_scan.active_ports[0].state, 'open',
                         'Nmap scan nenacetl port state!')
        self.assertEqual(self.ip_scan.active_ports[0].port, 22, 'Nmap scan nenacetl port!')
        self.assertEqual(self.ip_scan.active_ports[0].product, 'OpenSSH',
                         'Nmap scan nenacetl port product!')
        self.assertEqual(self.ip_scan.active_ports[0].version, '7.6p1 Ubuntu 4ubuntu0.1',
                         'Nmap scan nenacetl port version!')
        self.assertEqual(self.ip_scan.active_ports[0].exinfo, 'Ubuntu Linux; protocol 2.0',
                         'Nmap scan nenacetl port extrainfo!')
        self.assertEqual(self.ip_scan.active_ports[0].cpe, 'cpe:/o:linux:linux_kernel',
                         'Nmap scan nenacetl port cpe!')

    @patch('scanobjects.nmap.PortScanner', name='nmap_scan')
    def test_detect_device(self, nmap_scan_mock):
        """test detekce zarizeni a OS dle naskenovanych dat"""

        nmap_scan_mock.return_value.scan.return_value = {'nmap': {
            'command_line': 'nmap -oX - -p 20,21,22,25,53,67,68,80,88,110,111,135,139,143,161,389,443,445,464,465,548,587,593,636,993,995,1024,1110,2000,2049,3128,3268,3269,3389,5357,8291,8080,8888,14000, -sV 127.0.0.1',
            'scaninfo': {'tcp': {'method': 'connect',
                                 'services': '20-22,25,53,67-68,80,88,110-111,135,139,143,161,389,443,445,464-465,548,587,593,636,993,995,1024,1110,2000,2049,3128,3268-3269,3389,5357,8080,8291,8888,14000'}},
            'scanstats': {'timestr': 'Tue Dec  4 10:49:45 2018', 'elapsed': '83.56', 'uphosts': '1',
                          'downhosts': '0', 'totalhosts': '1'}}, 'scan': {
            '127.0.0.1': {'hostnames': [{'name': 'localhost', 'type': 'PTR'}],
                          'addresses': {'ipv4': '127.0.0.1'}, 'vendor': {},
                          'status': {'state': 'up', 'reason': 'syn-ack'}, 'tcp': {
                    22: {'state': 'open', 'reason': 'syn-ack', 'name': 'ssh', 'product': 'OpenSSH',
                         'version': '7.6p1 Ubuntu 4ubuntu0.1',
                         'extrainfo': 'Ubuntu Linux; protocol 2.0', 'conf': '10',
                         'cpe': 'cpe:/o:linux:linux_kernel'},
                    25: {'state': 'open', 'reason': 'syn-ack', 'name': 'smtp',
                         'product': 'Postfix smtpd', 'version': '', 'extrainfo': '', 'conf': '10',
                         'cpe': 'cpe:/a:postfix:postfix'},
                    80: {'state': 'open', 'reason': 'syn-ack', 'name': 'http',
                         'product': 'Apache httpd', 'version': '2.4.29', 'extrainfo': '(Ubuntu)',
                         'conf': '10', 'cpe': 'cpe:/a:apache:http_server:2.4.29'},
                    8888: {'state': 'open', 'reason': 'syn-ack', 'name': 'sun-answerbook',
                           'product': '', 'version': '', 'extrainfo': '', 'conf': '3',
                           'cpe': ''}}}}}
        self.ip_scan.scan_nmap(self.config['ports_to_scan'])
        self.ip_scan.detect_device(self.config['detect'])
        self.assertEqual(self.ip_scan.operating_system, 'Linux', 'Spatne detekovan OS!')
        self.assertEqual(self.ip_scan.device, 'PC', 'Spatne detekovano device!')
        self.assertEqual(self.ip_scan.os_info, '7.6p1 Ubuntu 4ubuntu0.1', 'Spatne detekovano OS info!')
        self.assertEqual(self.ip_scan.device_info, '', 'Spatne detekovano device info!')
