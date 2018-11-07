#!/usr/bin/env python

from netobjects import *
from tools import load_object
import ipcalc
import json
import networkx as nx
from networkx.readwrite import json_graph


network = load_object('network.pkl')
G = nx.MultiDiGraph()


for device in network.devices:
    # if type(device) == Device:
    G.add_node(device.uuid)

# Ze vsech rout krom defaultnich vytvori hrany grafu
edge_attr = dict()
for device in network.devices:
    if type(device) == Device:
        gateways = device.get_routes()
        if len(gateways):
            i = 2
            for route in gateways:
                iface = network.find_interface_by_ip(route.gw)
                if iface:
                    iface.parent.infrastructure_device = True
                    if route.net != '0.0.0.0/0':
                        G.add_edge(device.uuid, iface.parent.uuid, label=route.net, category='lan-route',
                                   count=i, type='curvedArrow', size=3)
                        i += 1
                else:
                    print('Unknown device')

        else:
            print('NO route')

# Z defaultnich rout vytvori hrany grafu
for device in network.devices:
    if type(device) == Device:
        route = device.get_default_route()
        if route:
            iface = network.find_interface_by_ip(route.gw)
            if iface:
                if device.infrastructure_device:
                    G.add_edge(device.uuid, iface.parent.uuid, label='default', category='default', count=0,
                               type='arrow', size=10)
                else:
                    G.add_edge(device.uuid, iface.parent.uuid, label='default', category='default', count=0,
                               type='arrow', size=1)

            else:
                print('Unknown device')

        else:
            print('NO default route')

# Dohleda branu pro GenericDevice podle site do ktere patri
for gendevice in network.devices:
    if type(gendevice) == GenericDevice:
        ip_list_hlp = list()
        dev_network = None
        for device in network.devices:
            if type(device) == Device and device.infrastructure_device:  # Pokud je to nactene a paterni zarizeni
                for ip in device.get_ips():  # Pro kazdou ip zarizeni
                    if gendevice.ip in ipcalc.Network('{}/{}'.format(ip.ip, ip.mask)):  # Pokud je ip ve stejne siti
                        # Zjisti subnet ve kterem je ip
                        dev_network = ipcalc.Network('{}/{}'.format(ip.ip, ip.mask)).guess_network()
                        ip_list_hlp.append(ip)
        if len(ip_list_hlp) == 1:  # Pokud je jen jeden iface kam se vejde, tak ho propoji
            G.add_edge(gendevice.uuid, ip_list_hlp[0].parent.parent.uuid, label='default', category='default',
                       count=0, type='arrow', size=1)  # Prida jako hranu do grafu
        else:  # Pokud je vice ifacu kam se vejde, tak kouknem kam patrej ostatni podobni
            gates = set()
            for iph in network.get_ips_same_net(gendevice.ip):  # Pro vsechny stejne ip v siti
                # Pokud je brana v subnet hledane ip
                if iph.parent.parent.get_default_route().gw in ipcalc.Network(dev_network):
                    gates.add(iph.parent.parent.get_default_route().gw)
            print('\n\n\n\n')
            print(gates)
            if len(gates) == 1:
                G.add_edge(gendevice.uuid, network.find_interface_by_ip(list(gates)[0]).parent.uuid, label='default',
                           category='default', count=0, type='arrow', size=1)

        ip_list_hlp = list()

nx.set_edge_attributes(G, edge_attr)


data1 = json_graph.node_link_data(G, {'link': 'edges', 'source': 'source', 'target': 'target'})

i = 0
for edge in data1['edges']:
    edge['id'] = 'e{}'.format(i)
    i += 1


G = nx.MultiGraph(G)
pos = nx.spring_layout(G, k=0.50, iterations=500, scale=5)

data2 = json_graph.node_link_data(G, {'link': 'edges', 'source': 'source', 'target': 'target'})
for node in data2['nodes']:
    dev = network.get_dev_by_uuid(node['id'])
    node['x'] = pos[node['id']][0]
    node['y'] = pos[node['id']][1]
    if type(dev) == Device:
        node['label'] = dev.hostname
    if type(dev) == GenericDevice:
        node['color'] = '#8B382F'
        if dev.os and dev.device:
            node['label'] = '{}-{} ({})'.format(dev.device, dev.os, dev.ip)
        else:
            node['label'] = '{}'.format(dev.ip)
    if dev.infrastructure_device:
        node['size'] = 7
    else:
        node['size'] = 2


json_export = {'nodes': data2['nodes'], 'edges': data1['edges']}

with open('html/data.json', 'w') as outfile:
    json.dump(json_export, outfile)


# Vytvori json s datama jednotlivych zarizeni pro webovku
device_info_dict = dict()
for device in network.devices:
    if type(device) == GenericDevice:
        device_info_dict[device.uuid] = {'ip': device.ip, 'info': device.get_html_info()}
    if type(device) == Device:
        device_info_dict[device.uuid] = {'ip': device.ip, 'info': '{}{}'.format(device.get_html_info(),
                                                                                device.get_html_dev_info())}


with open('html/device_data.json', 'w') as outfile:
    json.dump(device_info_dict, outfile)
