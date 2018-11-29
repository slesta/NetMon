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
        self.assertEqual(self.scan_net.accounts, expected, 'Nebylz nacteny uzivatelske ucty!')

    @patch('scanobjects.ScanNetwork.scan_ips.create_ipobject')
    def test_scan_ips(self, mocked_fnc):
        """ Oskenovani IP do IPobjektu - scan_ips() """

        self.scan_net.scan_ips()
        print("mocked function called: {c}".format(c=mocked_fnc.called))