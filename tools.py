#!/usr/bin/env python

""" Pomocne funkce pro NetMon """

import socket
import time
import json
import logging.config
import pickle
from typing import Any, Dict
import requests
from scp import SCPClient
import paramiko

# Nastavi logovani
logging.getLogger('paramiko.transport').setLevel(logging.WARNING)
LOGGER = logging.getLogger(__name__)


class SshClient:
    """ Trida zajistujici SSH spojeni. Provadi prikazy a stahuje/uploaduje soubory na vzdalene
    zarizeni. """

    def __init__(self, connect_host: str, port: int, user: str, password: str):
        self.host = connect_host
        self.port = port
        self.user = user
        self.password = password
        self.ssh_client = paramiko.SSHClient()
        self.error = None
        self.chan = None
        self.connect_ssh()

    def connect_ssh(self):
        """ Vytvori ssh spojeni a ulozi klienta pro dalsi pouziti """

        try:
            LOGGER.info('Try to connect host:%s user:%s passw:%s', self.host, self.user,
                        self.password)
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(hostname=self.host, port=self.port,
                                    username=self.user, password=self.password, banner_timeout=30,
                                    timeout=30)
        except paramiko.AuthenticationException:
            self.error = "Authentication failed"
            LOGGER.warning('Auth error host:%s user:%s passw:%s', self.host, self.user,
                           self.password)
            self.close_ssh()
        except (paramiko.BadHostKeyException, socket.error, paramiko.SSHException, socket.timeout,
                EOFError):
            self.close_ssh()
            self.error = "Connection Error"
            LOGGER.error('Connection error host:%s user:%s passw:%s', self.host, self.user,
                         self.password)
            LOGGER.exception('Connection error exception host:%s user:%s passw:%s', self.host,
                             self.user, self.password)
        else:
            # Nasledujici vycisti banner po prihlaseni
            try:
                self.chan = self.ssh_client.invoke_shell()
            except paramiko.SSHException as erro:
                self.close_ssh()
                self.error = erro
                LOGGER.error('Invoke shell error host:%s user:%s passw:%s', self.host, self.user,
                             self.password)
                LOGGER.exception('Invoke shell error exception host:%s user:%s passw:%s',
                                 self.host, self.user, self.password)
            else:
                self.chan.recv(9999)
                self.chan.send("\n")
                self.error = None
                LOGGER.info('Connected to host:%s user:%s passw:%s', self.host, self.user,
                            self.password)

    def cmd_exec(self, cmd: str) -> str:
        """ Pro prikazy v invoke_shell, kdyz je treba vicekrokove provedeni (sudo a pak heslo) """

        self.chan.send(cmd + '\r')
        while not self.chan.recv_ready():
            time.sleep(0.1)
        output = self.chan.recv(9999)
        output = output.decode('ascii')
        return output

    def command_exec(self, cmd: str) -> str:
        """ Provede prikaz a vrati vysledek """

        output = None
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
            LOGGER.debug('Command exec on host:%s - cmd:%s', self.host, cmd)
        except paramiko.SSHException:
            LOGGER.exception('Command exec exception on host:%s - cmd:%s', self.host, cmd)
        else:
            output = stdout.read().decode('ascii').strip('\n').replace('\r', '')
            self.error = stderr.read().decode('ascii').strip('\n')
            if self.error:
                LOGGER.debug('Command exec error on host:%s - err:%s', self.host, self.error)
        return output

    def get_file_from_remote(self, remote_file: str):
        """  Stahne soubor z hosta (zadat i s cestou) """

        with SCPClient(self.ssh_client.get_transport()) as scp:
            scp.get(remote_file)

    def copy_file_to_remote(self, local_file: str, remote_file: str):
        """  Posle soubor na hosta (zadat i s cestou) """

        with SCPClient(self.ssh_client.get_transport()) as scp:
            scp.put(local_file, remote_file)

    def close_ssh(self):
        """ Zavre spojeni  """

        self.ssh_client.close()

    def __del__(self):
        self.close_ssh()


def get_fresh_manufacturers():
    """ Stahne seznam vyrobcu podle mac a nacpe ho do slovniku """

    webfile = requests.get('http://standards-oui.ieee.org/oui/oui.txt')
    lines = webfile.text.split('\n')
    manufacturers_dict = dict()
    for line in lines:
        if '(base 16)' in line:
            manufacturers_dict[line.split('(base 16)')[0].strip(' ')] = line.split('(base 16)')[1] \
                .strip('\r\t ')
    with open('config/manufacturers.json', 'w') as soubor:
        json.dump(manufacturers_dict, soubor)


def save_object(object_to_save: Any, filename: str):
    """" Ulozi objek do souboru """

    with open('objects/' + filename, 'wb') as output:  # prepise soubor
        pickle.dump(object_to_save, output, pickle.HIGHEST_PROTOCOL)


def load_object(filename: str) -> Any:
    """ Nacte objekt ze souboru """

    with open('objects/' + filename, 'rb') as input_file:
        return pickle.load(input_file)


def load_json(filename: str) -> Dict:
    """ Nacte JSON ze souboru """

    with open('config/' + filename) as json_data_file:
        return json.load(json_data_file)
