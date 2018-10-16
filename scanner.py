#!/usr/bin/env python
import ipcalc
import pickle
from multiprocessing.dummy import Pool as ThreadPool
from netobjects import IpObject
import json


with open('config.json') as json_data_file:
    config = json.load(json_data_file)


def save_object(object_to_save, filename):
    with open(filename, 'wb') as output:  # prepise soubor
        pickle.dump(object_to_save, output, pickle.HIGHEST_PROTOCOL)


def load_object(filename):
    with open(filename, 'rb') as input_file:
        return pickle.load(input_file)


def create_netobject(ipaddr):
    return IpObject(ip=ipaddr, config=config)


adr_list = map(str, ipcalc.Network('10.60.60.0/24'))

# make the Pool of workers
pool = ThreadPool(125)

# open the urls in their own threads
# and return the results
n_obj_list = pool.map(create_netobject, adr_list)

# close the pool and wait for the work to finish
pool.close()
pool.join()

save_object(n_obj_list, 'n_obj_list.pkl')
n_obj_list1 = load_object('n_obj_list.pkl')
print('-------------------------------------------------------------------------------------------------')
for obj in n_obj_list1:
    # obj.detect_device()
    if obj.active:
        print('IP: {} \tOS: {} \tDev: {} \tOS-info: {} \tDev-info: {}'.format(obj.ip, obj.os, obj.device,
                                                                              obj.os_info, obj.device_info))
        for port_info in obj.active_ports:
            print('Port: {}\tName: {}\tProduct: {}\tVer: {}\tInfo: {} Cpe: {}'.format(
                port_info.port, port_info.name, port_info.product, port_info.version,
                port_info.extrainfo, port_info.cpe))
        print('-------------------------------------------------------------------------------------------------')
