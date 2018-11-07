#!/usr/bin/env python
# coding=utf8

import ipcalc
from multiprocessing.dummy import Pool as ThreadPool
from netobjects import IpObject, Network
from tools import load_object, save_object, load_json
from typing import TypeVar

# definice typu pro typing
ipobj_objekt = TypeVar('ipobj_objekt', bound=IpObject)

# Nalouduje konfiguraci ze souboru, jsou tam treba definice pro identifikaci ruznych sitovych zarizeni
config = load_json('config.json')


def create_netobject(ipaddr: str) -> ipobj_objekt:
    return IpObject(ip=ipaddr, config=config)


network = '10.60.0.0/16'
# network = '10.60.60.254/32'

adr_list = map(str, ipcalc.Network(network))

# Vytvori pool o danem poctu vlaken
pool = ThreadPool(125)

# Vytvori IP objekty z daneho seznamu adres a nacpe to do listu
n_obj_list = pool.map(create_netobject, adr_list)

# Udelame poradek
pool.close()
pool.join()

save_object(n_obj_list, 'n_obj_list.pkl')
n_obj_list = load_object('n_obj_list.pkl')

network_obj = Network()
network_obj.network = network
print('-------------------------------------------------------------------------------------------------')
for obj in n_obj_list:
    if obj.active:
        print('IP: {} \tOS: {} \tDev: {} \tOS-info: {} \tDev-info: {}'.format(obj.ip, obj.os, obj.device,
                                                                              obj.os_info, obj.device_info))
        for port_info in obj.active_ports:
            print('Port: {}\tName: {}\tProduct: {}\tVer: {}\tInfo: {} Cpe: {}'.format(
                port_info.port, port_info.name, port_info.product, port_info.version,
                port_info.extrainfo, port_info.cpe))
        network_obj.add_device(obj)
        print('-------------------------------------------------------------------------------------------------')
save_object(network_obj, 'network_scan_podlipan.pkl')
