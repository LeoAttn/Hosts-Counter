#!/usr/bin/python3

import os
import sys
import argparse
import datetime
import re
import csv
from collections import OrderedDict


# ------------- Fonctions -------------
def listHosts(text):
    hostsList = []
    regex = re.findall(r"" + regexIP + "[^\d]", text, re.DOTALL)
    if regex:
        for addr in regex:
            hostsList.append(addr[0])
        return hostsList
    else:
        return []


# --------------- Main ----------------
# Regex for IP address with or without CIDR
regexIP = "((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" \
          "(\/([0-9]|[1-2][0-9]|3[0-2]))?)"

# Verify arguments
parser = argparse.ArgumentParser(prog='Hosts Counter',
                                 description='Count thes hosts in your local network with nbtscan and nmap',
                                 conflict_handler='resolve')
parser.add_argument('interface', help='Select the network interface')
parser.add_argument('-d', '--directory', help='Directory where the CSV file will be save')
args = parser.parse_args()

# if not sys.argv[1]:
#     print("No interface selected")
#     exit(1)
#
# if len(sys.argv) == 3 and not os.path.isdir(sys.argv[2]):
#     print("Directory not valid")
#     exit(2)

# Find the IP range of the selected interface
interface = os.popen("ip addr show " + args.interface).read()
regex = re.search(r"inet " + regexIP + " brd", interface)
if regex:
    range = regex.group(1)
else:
    exit(3)

# range = "10.92.0.0/28"

# Execute Nbt scan and Nmap scan
dateStart = datetime.datetime.now()
print("Start NbtScan on " + range)
nbtScan = os.popen("nbtscan " + range + " -t 1000 -q 2> /dev/null  | iconv -c -t UTF-8").read()
print("Start Nmap on " + range)
nmap = os.popen("nmap " + range + " -sP 2> /dev/null").read()
print("End")
dateEnd = datetime.datetime.now()

# List the IP hosts found in scans
hostsNbtList = listHosts(nbtScan)
hostsNmapList = listHosts(nmap)

# Join the 2 lists and count the number of hosts in scans
hostsList = hostsNbtList + hostsNmapList
nbHosts = len(list(set(hostsList)))
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
                              ('IP_Range', None), ('Nbt_Hosts_Number', None),
                              ('Nmap_Hosts_Number', None), ('Total_Hosts_Number', None)])
        dw = csv.DictWriter(csvFile, delimiter='\t', fieldnames=header)
        dw.writeheader()

    wr = csv.writer(csvFile, quoting=csv.QUOTE_ALL, delimiter=';')
    wr.writerow([dateStart, dateEnd, range, nbHostsNbt, nbHostsNmap, nbHosts])

print("Found " + str(nbHostsNbt) + " nbt hosts and " + str(nbHostsNmap) + " nmap hosts.")
print("Add row in " + csvPath)
