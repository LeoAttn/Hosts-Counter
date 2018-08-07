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

import os
import argparse
import datetime
import re
import csv
from collections import OrderedDict


# ------------- Fonctions -------------
def listHosts(text):
    hostsList = []
    regex = re.findall(r"" + regexIP + "($|[^\d])", text, re.DOTALL)
    if regex:
        for addr in regex:
            hostsList.append(addr[0])
        return hostsList
    else:
        return []


# --------------- Main ----------------
VERSION = "0.2"
# Regex for IP address with or without CIDR
regexIP = "((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" \
          "(\/([0-9]|[1-2][0-9]|3[0-2]))?)"

# Parse arguments
parser = argparse.ArgumentParser(description='Count the hosts in your local network with nbtscan and nmap',
                                 conflict_handler='resolve')
parser.add_argument('interface', help='Select the network interface')
parser.add_argument('-d', '--directory', help='Directory where the CSV file will be save')
parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + VERSION)
args = parser.parse_args()

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

# Execute Nbt scan and Nmap scan
dateStart = datetime.datetime.now()
print("Start ARP scan on " + range)
arpScan = os.popen("sudo /usr/bin/arp-scan --interface " + args.interface + " " + range).read()
print("Start NbtScan on " + range)
nbtScan = os.popen("/usr/bin/nbtscan " + range + " -t 1000 -q | iconv -c -t UTF-8").read()
print("Start Nmap on " + range)
nmap = os.popen("/usr/bin/nmap " + range + " -sP").read()
print("End")
dateEnd = datetime.datetime.now()

# List the IP hosts found in scans
hostsArpList = listHosts(arpScan)
hostsNbtList = listHosts(nbtScan)
hostsNmapList = listHosts(nmap)

# Join the 3 lists and count the number of hosts in scans
hostsList = hostsArpList + hostsNbtList + hostsNmapList
nbHosts = len(list(set(hostsList)))
nbHostsArp = len(hostsArpList)
nbHostsNbt = len(hostsNbtList)
nbHostsNmap = len(hostsNmapList)

# Define CSV path
dateFormated = dateStart.strftime('%d-%m-%y')

csvFilename = 'count_hosts_' + dateFormated + '.csv'
if args.directory:
    csvPath = args.directory + '/' + csvFilename
else:
    csvPath = csvFilename

createHeader = not os.path.exists(csvPath)

# Write the result in CSV file
with open(csvPath, 'a') as csvFile:
    # Add a header if it's a new file
    if createHeader:
        header = OrderedDict([('Start_Date', None), ('End_Date', None),
                              ('IP_Range', None), ('Nbt_Hosts_Number', None), ('Arppro_Hosts_Number', None),
                              ('Nmap_Hosts_Number', None), ('Total_Hosts_Number', None)])
        dw = csv.DictWriter(csvFile, delimiter='\t', fieldnames=header)
        dw.writeheader()

    wr = csv.writer(csvFile, quoting=csv.QUOTE_ALL, delimiter=';')
    wr.writerow([dateStart, dateEnd, range, nbHostsArp, nbHostsNbt, nbHostsNmap, nbHosts])

print("Found " + str(nbHostsNbt) + " nbt hosts and " + str(nbHostsNmap) + " nmap hosts.")
print("Add row in " + csvPath)
