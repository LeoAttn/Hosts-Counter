#!/usr/bin/python3

# Copyright (C) 2018 LeoAttn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# ---------------------------------- Imports ----------------------------------

import json
import multiprocessing
import os
import re
import subprocess
import argparse
from datetime import datetime, timedelta

# -------------------------------- Constants ----------------------------------
DEFAULT_PORTS = [22, 80, 443, 3000, 8080]
# DEFAULT_PORTS = []

VERSION = '1.5'
# Declaration of all Regex
REGEX_IP = r'((?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}' \
           r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?)'
REGEX_MAC = r'((?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2}))'
REGEX_VENDOR = r'((?:(?!\(DUP: \d+\))[^\t\n])+)'
REGEX_NETBIOS_NAME = r'(\S+)'
REGEX_IP_ADDR = r"inet " + REGEX_IP + " brd"
REGEX_ARP_SCAN = r'^' + REGEX_IP + r'\s+' + REGEX_MAC + r'\s+' + REGEX_VENDOR + r'$'
REGEX_NBT_SCAN = r'^' + REGEX_IP + r'\s+' + REGEX_NETBIOS_NAME + r'\s'
REGEX_DNS_LOOKUP = r'domain name pointer (\S+)\.$'
REGEX_NMAP = r'^(\d+)/(?:udp|tcp)\s+open'
# Declaration for oui file
DEFAULT_OUI_URL = 'http://standards-oui.ieee.org/oui.txt'  # URL used by default to fetch OUI file
OUI_FILENAME = 'ieee-oui.txt'  # Name for the file generated by 'get-oui'
OUI_DAYS = 30  # Number of days before renew the OUI file

PREFIX_FILENAME = 'count_hosts_'  # Prefix used for the JSON file


# --------------------------------- Fonctions ---------------------------------

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Count the hosts in your local network and get informations from each host')
    parser.add_argument('interface', help='Select the network interface')
    parser.add_argument('-d', '--directory', help='Specify the directory where the JSON file will be save',
                        default='./')
    parser.add_argument('-p', '--ports', nargs='+', help='Port(s) to scan with Nmap', default=DEFAULT_PORTS)
    parser.add_argument('-o', '--oui-url', help='Specify the URL to fetch the OUI data from',
                        default=DEFAULT_OUI_URL)
    parser.add_argument('--update-hosts', action='store_true', help='Force Update of informations from each host')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + VERSION)
    return parser.parse_args()


def get_ip_range(interface: str) -> str:
    ip_addr = os.popen("ip addr show " + interface).read()
    re_ip_range = re.search(REGEX_IP_ADDR, ip_addr)
    if re_ip_range:
        return re_ip_range.group(1)
    else:
        exit(6)


def get_oui(url: str):
    print('Start fetch OUI file from ' + url)
    res = subprocess.Popen('get-oui -u ' + url, shell=True, stderr=subprocess.DEVNULL)
    res.wait()
    if not res.returncode:
        print("Writting OUI file successfully")
    else:
        exit(res.returncode)


def get_json_file(filename: str) -> dict:
    if os.path.exists(filename):
        with open(filename, 'r') as jsonFile:
            return json.load(jsonFile)
    else:
        return {
            'historic': []
        }


def get_info_host(ip: str, ports_list: list, output: multiprocessing.Queue):
    data = {
        'ip_addr': ip
    }
    # Find DNS Name
    print('Start Hostname on', ip)
    host_scan = os.popen('/usr/bin/host ' + ip).read()
    host_name = re.findall(REGEX_DNS_LOOKUP, host_scan)
    if host_name:
        data['dns_name'] = host_name[0]
    # Find NetBios Name
    print('Start NbtScan on', ip)
    nbt_scan = os.popen('/usr/bin/nbtscan ' + ip + ' -t 1000 -q | iconv -c -t UTF-8').read()
    nbt_name = re.findall(REGEX_NBT_SCAN, nbt_scan)
    if nbt_name:
        data['nbt_name'] = nbt_name[0][1]
    # Find open ports
    print('Start Nmap on', ip)
    ports_scan = list_to_comma_string(ports_list)
    # print("/usr/bin/nmap " + ip + " -Pn" + (" -p " + ports_scan if ports_scan else ''))
    nmap = os.popen("/usr/bin/nmap " + ip + " -Pn" + (" -p " + ports_scan if ports_scan else '')).read()
    if nmap:
        ports = [int(port) for port in re.findall(REGEX_NMAP, nmap, re.MULTILINE)]
        if ports:
            data['open_ports'] = ports

    output.put(data)


def list_to_comma_string(list: list) -> str:
    result = ''
    last = len(list) - 1
    for pos, elem in enumerate(list):
        result += str(elem)
        if pos != last:
            result += ','
    return result


def is_older_than_few_days(file: str, days: int) -> bool:
    return datetime.fromtimestamp(os.path.getmtime(file)) < datetime.now() - timedelta(days=days)


def set_attributes(new_attributes: dict, object_to_update: dict, filter_attr: staticmethod):
    for key, value in new_attributes.items():
        if filter_attr(key, value):
            object_to_update[key] = value


def create_host_object(data: dict, host: dict, ip_range: str, ports_to_scan: list, proccesses: list,
                       process_queue: multiprocessing.Queue):
    ip = host[0]
    if data[ip_range].get(ip) is None:
        data[ip_range][ip] = {
            'uptimes': []
        }
    data[ip_range][ip]['mac'] = host[1]
    data[ip_range][ip]['manufacturer'] = host[2]
    proccesses.append(multiprocessing.Process(target=get_info_host, args=(ip, ports_to_scan, process_queue)))


def update_host(data: dict, ip_range: str, proccess: list, process_queue: multiprocessing.Queue):
    proccess.join()
    data_host = process_queue.get()
    set_attributes(data_host, data[ip_range][data_host['ip_addr']], lambda key, _: key != 'ip_addr')


# ----------------------------------- Main ------------------------------------

def main():
    # Parse arguments
    args = parse_arguments()

    # Verify the directory
    if args.directory and not os.path.isdir(args.directory):
        print("Directory is not valid")
        exit(5)
    if not os.access(args.directory, os.W_OK):
        print("Directory is not writable")
        exit(7)

    # Find the IP range of the selected interface
    ip_range = get_ip_range(args.interface)
    date_start = datetime.now()

    # Goto the directory selected
    os.chdir(args.directory)

    # Get OUI file if not exist or it's older than 30 days
    if not os.path.exists(OUI_FILENAME):
        get_oui(args.oui_url)
    elif is_older_than_few_days(OUI_FILENAME, OUI_DAYS):
        get_oui(args.oui_url)
        os.remove(OUI_FILENAME + '.bak')

    # Execute ARP scan
    print("Start ARP scan on", ip_range)
    arp_scan = os.popen("sudo /usr/bin/arp-scan --interface " + args.interface + " " + ip_range).read()

    # List the IP hosts found in scan ARP
    hosts_list = re.findall(REGEX_ARP_SCAN, arp_scan, re.MULTILINE)

    # Define JSON path
    date_formated = date_start.strftime('%y-%m-%d')
    json_filename = PREFIX_FILENAME + date_formated + '.json'

    # Load the json data or create if not exist
    data = get_json_file(json_filename)

    # Create object of IP range if not exist
    if data.get(ip_range) is None:
        data[ip_range] = {}

    proccesses = []
    process_queue = multiprocessing.Queue()

    for host in hosts_list:
        ip = host[0]
        # Create object of host and launch scan if not exist
        if data[ip_range].get(ip) is None or args.update_hosts:
            create_host_object(data, host, ip_range, args.ports, proccesses, process_queue)
        # Add the date on the host
        data[ip_range][ip]['uptimes'].append(str(date_start))

    # Run processes
    for proccess in proccesses:
        proccess.start()

    # Exit the completed processes and get process results from the queue
    for proccess in proccesses:
        update_host(data, ip_range, proccess, process_queue)

    date_end = datetime.now()

    # Add a summary of scan
    data['historic'].append({
        'date': str(date_start),
        'duration': (date_end - date_start).total_seconds(),
        'ip_range': ip_range,
        'hosts_number': len(hosts_list)
    })

    # Write the json data in file
    with open(json_filename, 'w') as jsonFile:
        json.dump(data, jsonFile, indent=2)
    print("Found " + str(len(hosts_list)) + " hosts.")


if __name__ == '__main__':
    main()
    exit(0)
