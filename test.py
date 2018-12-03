#!/usr/bin/env python

"""  Testy pro modul scanobjects  """

import unittest
from unittest.mock import patch
import scanobjects


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

