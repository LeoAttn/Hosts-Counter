#!/usr/bin/python3

import os
import sys
import datetime
import re
import csv


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

# Find the IP range of the selected interface
if not sys.argv[1]:
    print("No selected interface")
    exit()

interface = os.popen("ip addr show " + sys.argv[1]).read()
regex = re.search(r"inet " + regexIP + " brd", interface)
if regex:
    range = regex.group(1)
else:
    exit

# Execute Nbt scan and Nmap scan
dateStart = datetime.datetime.now()
print("Start NBTScan on " + range)
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

# Write the result in CSV file
dateFormated = dateStart.strftime('%d-%m-%y')

with open('count_hosts_' + dateFormated + '.csv', 'a') as csvFile:
    wr = csv.writer(csvFile, quoting=csv.QUOTE_ALL, delimiter=';')
    wr.writerow([dateStart, dateEnd, range, nbHostsNbt, nbHostsNmap, nbHosts])

print("Found " + str(nbHostsNbt) + " nbt hosts and " + str(nbHostsNmap) + " nmap hosts.")
