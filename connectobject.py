#!/usr/bin/env python

""" Modul obstarava pripojeni k jednotlivym typum zarizeni Linux, Mikrotik a vytvari Generic device
z tech zarizeni ke kterym se neumi pripojit """

import logging
from multiprocessing.dummy import Pool
import tqdm
import scanobjects
import netobjects
import linux
import mikrotik
from tools import save_object


# Nastavi logovani
LOGGER = logging.getLogger(__name__)


class Connect:
    """ Trida rozdeli podle typu zarizeni a provede nacteni jejich konfigurace """

    def __init__(self, scan_net: scanobjects.ScanNetwork):
        self.scan_net = scan_net
        self.network = netobjects.Network(scan_net.net_name)
        self.linux_dev = list()
        self.mikrotik_dev = list()
        self.generic_dev = list()
        self.sort_devices()
        self.connect_mikrotik()
        self.connect_linux()
        self.get_generic_objects()

    def sort_devices(self):
        """ Rozdeli zarizeni podle typu """

        for dev in self.scan_net.ip_objects_active:
            if dev.operating_system == 'Linux':
                self.linux_dev.append(dev)
            elif dev.operating_system == 'RouterOS':
                self.mikrotik_dev.append(dev)
            else:
                self.generic_dev.append(dev)

    def save_network(self):
        """ Ulozi objekt sit do souboru """

        save_object(self.network, self.scan_net.net_name+'_network.pkl')

    def connect_linux(self):
        """ Nacte Linux zarizeni """

        def connect(ip_obj: scanobjects.IpObject) -> linux.Linux:
            return linux.Linux(ip_obj, self.scan_net.accounts, self.network)

        hlp_list = list()
        pool = Pool(52)  # Vytvori pool o danem poctu vlaken
        # Vytvori Linux objekty z daneho seznamu IpObjektu a zobrazi progress bar
        text = 'Analyzing Linux'
        for item in tqdm.tqdm(pool.imap_unordered(connect, self.linux_dev),
                              total=len(self.linux_dev), desc=text, unit='device'):
            hlp_list.append(item)
        pool.close()  # Udelame poradek
        pool.join()
        count = 0
        count_dupl = 0
        count_generic = 0
        for dev in hlp_list:
            if dev.device:
                # Pokud zarizeni uz nebylo nacteno, protoze ma vice IP tak ho oznaci jako duplikat
                if dev.device.uid not in self.network.get_uid_list():
                    # Pridame zarizeni k nactenym zarizenim
                    self.network.add_device(dev.device)
                    count += 1
                # Pridame zarizeni do seznamu duplikatu
                else:
                    self.network.add_duplicate_device(dev.device)
                    count_dupl += 1
            # Pokud se nepodarilo pripojit, tak dame zarizeni do generic
            else:
                self.generic_dev.append(dev.ip_obj)
                count_generic += 1
            self.save_network()
        print('')
        print('Saved {} linux devices.'.format(count))
        print('{} linux devices was duplicate.'.format(count_dupl))
        print('{} linux devices was unconectable and moved to generic devices.'.format(
            count_generic))
        print('')

    def connect_mikrotik(self):
        """ Nacte Mikrotik zarizeni """

        def connect(ip_obj: scanobjects.IpObject) -> mikrotik.Mikrotik:
            return mikrotik.Mikrotik(ip_obj, self.scan_net.accounts, self.network)

        hlp_list = list()
        pool = Pool(26)  # Vytvori pool o danem poctu vlaken
        # Vytvori Linux objekty z daneho seznamu IpObjektu a zobrazi progress bar
        text = 'Analyzing Mikrotik'
        for item in tqdm.tqdm(pool.imap_unordered(connect, self.mikrotik_dev),
                              total=len(self.mikrotik_dev), desc=text, unit='device'):
            hlp_list.append(item)
        pool.close()  # Udelame poradek
        pool.join()
        count = 0
        count_dupl = 0
        count_generic = 0
        for dev in hlp_list:
            if dev.device:
                # Pokud zarizeni uz nebylo nacteno, protoze ma vice IP tak ho oznaci jako duplikat
                if dev.device.uid not in self.network.get_uid_list():
                    # Pridame zarizeni k nactenym zarizenim
                    self.network.add_device(dev.device)
                    count += 1
                # Pridame zarizeni do seznamu duplikatu
                else:
                    self.network.add_duplicate_device(dev.device)
                    count_dupl += 1
            # Pokud se nepodarilo pripojit, tak dame zarizeni do generic
            else:
                self.generic_dev.append(dev.ip_obj)
                count_generic += 1
            self.save_network()
        print('')
        print('Saved {} mikrotik devices.'.format(count))
        print('{} mikrotik devices was duplicate.'.format(count_dupl))
        print('{} mikrotik devices was unconectable and moved to generic devices.'.format(
            count_generic))
        print('')

    def get_generic_objects(self):
        """ Z IpObjektu ze kterych neumime dostat data udelame GenericDevice objekty """

        for obj in tqdm.tqdm(self.generic_dev, total=len(self.generic_dev),
                             desc='Adding devices', unit='device'):
            # for obj in self.generic_dev:
            dev_obj = netobjects.GenericDevice()
            dev_obj.ipaddr = obj.ipaddr
            dev_obj.operating_system = obj.operating_system
            dev_obj.os_info = obj.os_info
            dev_obj.device = obj.device
            dev_obj.device_info = obj.device_info
            dev_obj.active = obj.active
            dev_obj.pingable = obj.pingable
            dev_obj.min = obj.min
            dev_obj.avg = obj.avg
            dev_obj.max = obj.max
            dev_obj.loss = obj.loss
            dev_obj.active_ports = obj.active_ports
            self.network.add_device(dev_obj)
        self.save_network()
        print('')
        print('Saved {} generic devices.'.format(len(self.generic_dev)))
        print('')
