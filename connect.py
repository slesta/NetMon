# coding=utf8

import paramiko
import re
# import logging
import time



def connect_ssh(host, port, username, password):
    # logging.basicConfig()
    # logging.getLogger('paramiko.transport').setLevel(logging.DEBUG)
    e = False
    ssh_client = False
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=host, port=port, username=username, password=password,)
    except paramiko.AuthenticationException as er:
        e = er
    except paramiko.BadHostKeyException as er:
        e = er
    except paramiko.SSHException as er:
        e = er
    except Exception as er:
        e = er.args[1]
    return ssh_client, e


def clean_item(item):
    return str(item).replace('\t', ' ').replace('   ', ' ').replace('  ', ' ').replace('\n', '').replace('  ', ' ')\
        .replace('   ', ' ').replace('  ', ' ')


def clean_item_mikrotik(item):
    if item[0] == ' ':
        item = item[1:-3]
    return item

def mikrotik_line_to_keys(item):
    regex = r"[a-zA-Z0-9-_]+="
    subst = r"||\g<0>"
    result = re.sub(regex, subst, item,).replace(' \r\n', '').split(' ||')[1:]
    result_dict = {}
    for i in result:
        result_dict[str(i.split('=')[0])] = i.split('=')[1]
    return result_dict


def linux_data():
    cl, err = connect_ssh('10.60.60.241', 22, 'admin', 'marnost')
    # cl, err = connect_ssh('10.60.64.254', 22, 'root', 'marnost')
    print(cl)
    if not err:
        print('-------------------------------------------------------------------------------------------------')
        # ziska routovaci tabulku z Linux zarizeni
        cmd = 'ip route sh'
        stdin, stdout, stderr = cl.exec_command(cmd)
        if not stderr.readlines():
            out = stdout.readlines()
            out = map(clean_item, out)
            for line in out:
                # print(line)
                linesplit = line.split(' ')
                if linesplit[1] == 'via':
                    print('{} {} {}'.format(linesplit[0], linesplit[2], linesplit[4]))
        else:
            print('Command error')
        time.sleep(0.2)
        print('-------------------------------------------------------------------------------------------------')
        # ziska seznam IP adres z Linux zarizeni
        cmd = 'ip addr sh'
        stdin, stdout, stderr = cl.exec_command(cmd)
        if not stderr.readlines():
            out = stdout.readlines()
            out = map(clean_item, out)
            for line in out:
                # print(line)
                linesplit = line.split(' ')
                if linesplit[1] == 'inet' and linesplit[4] != 'host':
                    print('{} {} {}'.format(linesplit[2], linesplit[4], linesplit[7]))
        else:
            print('Command error')
        print('-------------------------------------------------------------------------------------------------')
        # ziska wireless int z ubnt
        cmd = 'mca-status'
        stdin, stdout, stderr = cl.exec_command(cmd)
        if not stderr.readlines():
            out = stdout.readlines()
            out = list(map(clean_item, out))
            print(out[0].split(',')[2].split('=')[1])  # FW
            print(out[3].split('=')[1])  # mode
            print(out[6].split('=')[1])  # SSID
        else:
            print('Command error')
        print('-------------------------------------------------------------------------------------------------')
        # ziska wireless int z ubnt
        cmd = 'iwconfig'
        stdin, stdout, stderr = cl.exec_command(cmd)
        out = list(stdout.readlines())
        if list(out):
            out = list(map(clean_item, out))
            print(out[0].split(' ')[0])
            print(out[0].split(' ')[2])
            print(out[0].split(' ')[3].replace('"', '').replace('ESSID:', ''))
            # print(out)
        else:
            print('Command error: {}'.format(''.join(list(stderr))))
        cl.close()

    else:
        print(err)

linux_data()

cl, err = connect_ssh('10.60.64.230', 22, 'admin', 'marnost')
# cl, err = connect_ssh('10.60.64.254', 22, 'root', 'marnost')
if not err:
    print('-------------------------------------------------------------------------------------------------')
    # ziska routy z mikrotik
    cmd = '/ip route print terse where !pref-src'
    stdin, stdout, stderr = cl.exec_command(cmd)
    out = list(stdout.readlines())
    if list(out):
        out = list(map(mikrotik_line_to_keys, out[:-1]))
        for line in out:
            if not 'unreachable' in line['gateway-status']:
                print('{} {} {}'.format(line['dst-address'], line['gateway'], line['gateway-status'].split(' reachable ')[1]))
    else:
        print('Command error: {}'.format(''.join(list(stderr))))
    print('-------------------------------------------------------------------------------------------------')
    # ziska ip z ubnt
    cmd = '/ip address print terse where !disabled'
    stdin, stdout, stderr = cl.exec_command(cmd)
    out = list(stdout.readlines())
    if list(out):
        out = list(map(mikrotik_line_to_keys, out[:-1]))
        for line in out:
            print('{} {} {}'.format(line['address'], line['broadcast'], line['interface']))
    else:
        print('Command error: {}'.format(''.join(list(stderr))))
    print('-------------------------------------------------------------------------------------------------')
    # ziska wireless int ubnt
    cmd = '/interface wireless print terse where !disabled'
    stdin, stdout, stderr = cl.exec_command(cmd)
    out = list(stdout.readlines())
    for line in out:
        print(line)
    if list(out):
        out = list(map(mikrotik_line_to_keys, out[:-1]))
        for line in out:
            print('{} {} {}'.format(line['address'], line['broadcast'], line['interface']))
    else:
        print('Command error: {}'.format(''.join(list(stderr))))


    cl.close()

else:
    print(err)