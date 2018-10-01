```
 _   _           _              ____                  _            
| | | | ___  ___| |_ ___       / ___|___  _   _ _ __ | |_ ___ _ __ 
| |_| |/ _ \/ __| __/ __|_____| |   / _ \| | | | '_ \| __/ _ \ '__|
|  _  | (_) \__ \ |_\__ \_____| |__| (_) | |_| | | | | ||  __/ |   
|_| |_|\___/|___/\__|___/      \____\___/ \__,_|_| |_|\__\___|_|   
```
# Requirements

- Python 3
- sudo
- arp-scan
- nbtscan
- nmap

# Help

```shell
usage: count_hosts.py [-h] [-d DIRECTORY] [--update-hosts] [-v] interface

Count the hosts in your local network and get informations from each host

positional arguments:
  interface             Select the network interface

optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        Directory where the JSON file will be save
  --update-hosts        Force Update of informations from each host
  -v, --version         show program's version number and exit
```

# Structure JSON Output

```json
{
  "historic": [
    {
      "date": datetime,
      "duration": float,
      "ip_range": string,
      "hosts_number": integer
    }
  ],
  "192.168.1.0/24": {
    "192.168.1.1": {
      "mac": string,
      "dns_name": string,
      "nbt_name": string,
      "manufacturer": string,
      "uptimes": [datetime],
      "open_ports": [integer]
    }
  }
}
```

# Licence

```text
Copyright (C) 2018 LeoAttn

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
```