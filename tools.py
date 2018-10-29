#!/usr/bin/env python

import paramiko
from scp import SCPClient
import time
import json
import requests
import pickle
from typing import Any


class SshClient:

    def __init__(self, connect_host: str, port: int, user: str, password: str):
        self.host = connect_host
        self.port = port
        self.user = user
        self.password = password
        self.ssh_client = paramiko.SSHClient()
        self.e = None
        self.chan = None
        self.connect_ssh()

    # Vytvori ssh spojeni a ulozi klienta pro dalsi pouziti
    def connect_ssh(self):
        # logging.basicConfig()
        # logging.getLogger('paramiko.transport').setLevel(logging.DEBUG)
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(hostname=self.host, port=self.port, username=self.user, password=self.password)
        except paramiko.AuthenticationException as erro:
            self.e = erro
            pass
        except paramiko.BadHostKeyException as erro:
            self.e = erro
            pass
        except paramiko.SSHException as erro:
            self.e = erro
            pass
        except Exception as erro:
            self.e = erro.args[1]
            pass
        if not self.e:
            self.chan = self.ssh_client.invoke_shell()  # Nasledujici vycisti banner po prihlaseni
            time.sleep(0.1)
            self.chan.recv(9999)
            self.chan.send("\n")
            time.sleep(0.1)
        else:
            raise Exception(self.e)

    # Pro prikazy v invoke_shell, kdyz je treba vicekrokove provedeni (sudo a pak heslo)
    def cmd_exec(self, cmd: str) -> str:
        self.chan.send(cmd + '\r')
        while not self.chan.recv_ready():
            time.sleep(0.1)
        time.sleep(0.5)
        output = self.chan.recv(9999)
        # output = output.decode('utf-8')
        output = output.decode('ascii')
        return output

    # Provede prikaz a vrati vysledek
    def command_exec(self, cmd: str) -> str:
        stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
        output = stdout.read().decode('ascii').strip('\n').replace('\r', '')
        # err = stderr.read().decode('ascii').strip('\n')
        # print(cmd)
        # print(output)
        return output

    # Stahne soubor z hosta (zadat i s cestou)
    def get_file_from_remote(self, remote_file: str):
        with SCPClient(self.ssh_client.get_transport()) as scp:
            scp.get(remote_file)

    # Posle soubor na hosta (zadat i s cestou)
    def copy_file_to_remote(self, local_file: str, remote_file: str):
        with SCPClient(self.ssh_client.get_transport()) as scp:
            scp.put(local_file, remote_file)

    # Zavre spojeni
    def close_ssh(self):
        self.ssh_client.close()

    def __del__(self):
        self.close_ssh()


def get_fresh_manufacturers():
    # Stahne seznam vyrobcu podle mac a nacpe ho do slovniku
    r = requests.get('http://standards-oui.ieee.org/oui/oui.txt')
    lines = r.text.split('\n')
    manufacturers_dict = dict()
    for line in lines:
        if '(base 16)' in line:
            manufacturers_dict[line.split('(base 16)')[0].strip(' ')] = line.split('(base 16)')[1].strip('\r\t ')
    with open('manufacturers.json', 'w') as fp:
        json.dump(manufacturers_dict, fp)


def save_object(object_to_save: Any, filename: str):
    with open(filename, 'wb') as output:  # prepise soubor
        pickle.dump(object_to_save, output, pickle.HIGHEST_PROTOCOL)


def load_object(filename: str) -> Any:
    with open(filename, 'rb') as input_file:
        return pickle.load(input_file)
