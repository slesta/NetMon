#!/usr/bin/env python

""" Vytvori z dat site orientovany graf a pripravi takto ziskana data pro preyentavi na webu"""


import json
import networkx as nx
from networkx.readwrite import json_graph
import netobjects


class Graf:
    """ Vytvari z dat site graf a z jeho dat json export """

    def __init__(self, network: netobjects.Network):
        self.network = network
        self.edge_data = None
        self.node_data = None
        self.pos = None
        self.graph = nx.MultiDiGraph()
        self.create_nodes()
        self.create_edges_routes()
        self.get_edge_data()
        self.change_to_multigraph()
        self.set_positions()
        self.get_node_data()
        self.save_graph_to_json()
        self.save_device_to_json()

    def create_nodes(self):
        """ Ze zarizeni vytvori nody grafu """

        for device in self.network.devices:
            self.graph.add_node(device.uuid)

    def create_edges_routes(self):
        """ Ze vsech spojeni vytvori hrany grafu """

        for conn in self.network.connections:
            if conn.category == 'default-route':
                if conn.get_dev_from().infrastructure_device:
                    self.graph.add_edge(conn.get_dev_from().uuid, conn.get_dev_to().uuid,
                                        label=conn.name, category=conn.category,
                                        count=conn.count, type='arrow', size=10)
                else:
                    self.graph.add_edge(conn.get_dev_from().uuid, conn.get_dev_to().uuid,
                                        label=conn.name, category=conn.category,
                                        count=conn.count, type='arrow', size=1)
            if conn.category == 'route':
                self.graph.add_edge(conn.get_dev_from().uuid, conn.get_dev_to().uuid,
                                    label=conn.name, category=conn.category,
                                    count=conn.count, type='curvedArrow', size=3)

    def change_to_multigraph(self):
        """ Zmeni graf z orientovaneho vicehranoveho na pouze vicehranovy """

        self.graph = nx.MultiGraph(self.graph)

    def set_positions(self):
        """ Rozmisti nody v grafu """

        self.pos = nx.spring_layout(self.graph, k=0.50, iterations=500, scale=5)

    def get_edge_data(self):
        """ Ziska data o hranach grafu pro export """

        data = json_graph.node_link_data(self.graph, {'link': 'edges', 'source': 'source',
                                                      'target': 'target'})
        i = 0
        for edge in data['edges']:
            edge['id'] = 'e{}'.format(i)
            i += 1
        self.edge_data = data['edges']

    def get_node_data(self):
        """ Ziska data o nodech grafu pro export """

        data = json_graph.node_link_data(self.graph, {'link': 'edges', 'source': 'source',
                                                      'target': 'target'})
        for node in data['nodes']:
            dev = self.network.get_dev_by_uuid(node['id'])
            node['x'] = self.pos[node['id']][0]
            node['y'] = self.pos[node['id']][1]
            if isinstance(dev, netobjects.Device):
                node['label'] = dev.hostname
            if isinstance(dev, netobjects.GenericDevice):
                node['color'] = '#8B382F'
                if dev.operating_system and dev.device:
                    node['label'] = '{}-{} ({})'.format(dev.device, dev.operating_system,
                                                        dev.ipaddr)
                else:
                    node['label'] = '{}'.format(dev.ipaddr)
            if dev:
                if dev.infrastructure_device:
                    node['size'] = 7
                else:
                    node['size'] = 2
        self.node_data = data['nodes']

    def save_graph_to_json(self):
        """ Ulozi data o nodech a hranach do json pro pouziti ve webovce """

        json_export = {'nodes': self.node_data, 'edges': self.edge_data}
        with open('html/data.json', 'w') as outfile:
            json.dump(json_export, outfile)

    def save_device_to_json(self):
        """ Vytvori json s datama jednotlivych zarizeni pro webovku """

        device_info_dict = dict()
        for device in self.network.devices:
            if isinstance(device, netobjects.GenericDevice):
                device_info_dict[device.uuid] = {'ip': device.ipaddr,
                                                 'info': device.get_html_info()}
            if isinstance(device, netobjects.Device):
                device_info_dict[device.uuid] = {'ip': device.ipaddr,
                                                 'info': '{}{}'.format(device.get_html_info(),
                                                                       device.get_html_dev_info())}

        with open('html/device_data.json', 'w') as outfile:
            json.dump(device_info_dict, outfile)
