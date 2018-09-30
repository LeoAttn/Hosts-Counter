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

import json
import os
import re
from argparse import ArgumentParser
from datetime import datetime

# ------------- Fonctions -------------


# --------------- Main ----------------
VERSION = '1.1.1'

# Declaration of all Regex
regexIP = r'((?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[' \
          r'0-5])(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?)'
regexMAC = r'((?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2}))'
regexManufacturer = r'([^\t\n]+)'
regexNBT = r'(\S+)'
regexARPScan = r'^' + regexIP + r'\s+' + regexMAC + r'\s+' + regexManufacturer + r'$'
regexNBTScan = r'^' + regexIP + r'\s+' + regexNBT + r'\s'
regexHostScan = r'domain name pointer (\S+)\.$'
regexNmapScan = r'^(\d+)/(?:udp|tcp)\s+open'

# Parse arguments
parser = ArgumentParser(description='Count the hosts in your local network and get informations from each host',
                        conflict_handler='resolve')
parser.add_argument('interface', help='Select the network interface')
parser.add_argument('-d', '--directory', help='Directory where the JSON file will be save', default='./')
parser.add_argument('--update-hosts', action='store_true', help='Force Update of informations from each host')
parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + VERSION)
args = parser.parse_args()

# Verify the directory
if args.directory and not os.path.isdir(args.directory):
    print("Directory is not valid")
    exit(5)

# Find the IP range of the selected interface
interface = os.popen("ip addr show " + args.interface).read()
regex = re.search(r"inet " + regexIP + " brd", interface)
if regex:
    range = regex.group(1)
else:
    exit(6)

# Goto the directory selected
os.chdir(args.directory)

# Execute ARP scan
dateStart = datetime.now()
print("Start ARP scan on", range)
arpScan = os.popen("sudo /usr/bin/arp-scan --interface " + args.interface + " " + range).read()

# List the IP hosts found in scan ARP
hostsList = re.findall(regexARPScan, arpScan, re.MULTILINE)

# Define JSON path
dateFormated = dateStart.strftime('%y-%m-%d')
jsonFilename = 'count_hosts_' + dateFormated + '.json'

# Load the json data or create if not exist
if os.path.exists(jsonFilename):
    with open(jsonFilename, 'r') as jsonFile:
        data = json.load(jsonFile)
else:
    data = {
        'historic': []
    }

# Create object of IP range if not exist
if data.get(range) == None:
    data[range] = {}

for host in hostsList:
    ip = host[0]
    # Create object of host and launch scan if not exist
    if data[range].get(ip) == None or args.update_hosts:
        if data[range].get(ip) == None:
            data[range][ip] = {
                'uptimes': []
            }

        data[range][ip]['mac'] = host[1]
        data[range][ip]['manufacturer'] = host[2]

        # Find DNS Name
        print('Start Hostname on', ip)
        hostScan = os.popen('/usr/bin/host ' + ip).read()
        hostName = re.findall(regexHostScan, hostScan)
        if hostName:
            data[range][ip]['dns_name'] = hostName[0]
        # Find NetBios Name
        print('Start NbtScan on', ip)
        nbtScan = os.popen('/usr/bin/nbtscan ' + ip + ' -t 1000 -q | iconv -c -t UTF-8').read()
        nbtName = re.findall(regexNBTScan, nbtScan)
        if nbtName:
            data[range][ip]['nbt_name'] = nbtName[0][1]
        # Find open ports
        print('Start Nmap on', ip)
        nmap = os.popen("/usr/bin/nmap " + ip + " -Pn -p 22,80,443,3000").read()
        if nmap:
            ports = [int(port) for port in re.findall(regexNmapScan, nmap, re.MULTILINE)]
            data[range][ip]['open_ports'] = ports

    # Add the date on the host
    data[range][ip]['uptimes'].append(str(dateStart))

dateEnd = datetime.now()

# Add a summary of scan
data['historic'].append({
    'date': str(dateStart),
    'duration': (dateEnd-dateStart).total_seconds(),
    'ip_range': range,
    'hosts_number': len(hostsList)
})

# Write the json data in file
with open(jsonFilename, 'w') as jsonFile:
    json.dump(data, jsonFile, indent=2)

print("Found " + str(len(hostsList)) + " hosts.")