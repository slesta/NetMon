#!/usr/bin/env python
# coding=utf8

import ipcalc
import pickle
from multiprocessing.dummy import Pool as ThreadPool
from netobjects import IpObject
import json

# Nalouduje konfiguraci ze souboru, jsou tam treba definice pro identifikaci ruznych sitovych zarizeni
with open('config.json') as json_data_file:
    config = json.load(json_data_file)


# Ulozi objekt do souboru
def save_object(object_to_save, filename):
    with open(filename, 'wb') as output:  # prepise soubor
        pickle.dump(object_to_save, output, pickle.HIGHEST_PROTOCOL)


# Nacte objekt ze souboru
def load_object(filename):
    with open(filename, 'rb') as input_file:
        return pickle.load(input_file)


def create_netobject(ipaddr):
    return IpObject(ip=ipaddr, config=config)


adr_list = map(str, ipcalc.Network('10.60.60.0/24'))
# adr_list = map(str, ipcalc.Network('192.168.88.0/24'))
# netw = ipcalc.Network('192.168.88.5/26')
# print(netw.subnet())
# print(netw.host_first())
# print(netw.host_last())
# print(netw.broadcast())
# print(netw.guess_network())
# print(netw.info())
# print(netw.netmask())
# print(netw.size())
# print(netw.to_ipv4())
# print(netw.network())
# exit()

# Vytvori pool o danem poctu vlaken
pool = ThreadPool(125)

# Vytvori IP objekty z daneho seznamu adres a nacpe to do listu
n_obj_list = pool.map(create_netobject, adr_list)

# Udelame poradek
pool.close()
pool.join()

save_object(n_obj_list, 'n_obj_list.pkl')
n_obj_list = load_object('n_obj_list.pkl')
print('-------------------------------------------------------------------------------------------------')
for obj in n_obj_list:
    if obj.active:
        print('IP: {} \tOS: {} \tDev: {} \tOS-info: {} \tDev-info: {}'.format(obj.ip, obj.os, obj.device,
                                                                              obj.os_info, obj.device_info))
        for port_info in obj.active_ports:
            print('Port: {}\tName: {}\tProduct: {}\tVer: {}\tInfo: {} Cpe: {}'.format(
                port_info.port, port_info.name, port_info.product, port_info.version,
                port_info.extrainfo, port_info.cpe))
        print('-------------------------------------------------------------------------------------------------')
