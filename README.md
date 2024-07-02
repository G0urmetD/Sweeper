# Sweeper
![](radar.png)
## Description
<p>Sweeper is a ping sweep tool. It uses ICMP or ARP as packets to find active hosts in a network.
It is possible to set the workers for faster scans and create an output file with only the IP addresses to pass on to other tools.</p>

## :black_joker: Features
- Ping sweep with ICMP packets
- Output possibility with only the ip addresses to hand them over to other tools
- Adjusting the workers for a faster scan
- Showing scan time
- Colorized commandline output
- DNS Reverse Lookup for reachable ip addresses
- Customize DNS server for DNS lookup
- OS detection with nmap

## :coffee: Installation
```bash
sudo pip3 install -r requirements.txt
```

## :bookmark_tabs: Usage
```bash
# default ping sweep
python3 sweeper.py 192.168.1.0/24 -ping

# ping & arp sweep for better findings
python3 sweeper.py 192.168.1.0/24 -ping -arp

# default ping sweep with output file
python3 sweeper.py 192.168.1.0/24 -ping -o output.txt

# default ping sweep and adjusting the workers for a faster scan
python3 sweeper.py 192.168.1.0/24 -ping -w 50

# using arp instead of ping [requires sudo privileges]
sudo python3 sweeper.py 192.168.1.0/24 -arp
sudo python3 sweeper.py 192.168.1.0/24 -arp -o output.txt
sudo python3 sweeper.py 192.168.1.0/24 -arp -w 100 -o output.txt

# DNS feature
[sudo] python3 sweeper.py 192.168.1.0/24 -ping/-arp -dns
[sudo] python3 sweeper.py 192.168.1.0/24 -ping/-arp [-o output.txt | -w 50] -dns -dns-server 192.168.1.1

# OS Detection (with nmap)
[sudo] python3 sweeper.py 192.168.1.0/24 -ping/-arp -os
```

## :question: Help
```bash

     _____                                   
    /  ___|                                  
    \ `--.__      _____  ___ _ __   ___ _ __ 
     `--. \ \ /\ / / _ \/ _ \ '_ \ / _ \ '__|
    /\__/ /\ V  V /  __/  __/ |_) |  __/ |   
    \____/  \_/\_/ \___|\___| .__/ \___|_|   
                            | |              
                            |_|              

    Author: G0urmetD (403 - Forbidden)
    Version: 3.5.7
    
========== Starting Sweep ==========
usage: sweeper-os2.py [-h] [-ping] [-arp] [-dns] [-dns-server DNS_SERVER] [-os] [-o OUTPUT] [-w WORKERS] target

IP Sweep Tool

positional arguments:
  target                Target IP or CIDR range

options:
  -h, --help            show this help message and exit
  -ping                 Use ping for scanning
  -arp                  Use ARP for scanning
  -dns                  Resolve IP addresses to hostnames
  -dns-server DNS_SERVER
                        Custom DNS server for hostname resolution (only applicable with -dns)
  -os                   Activate OS detection with nmap.
  -o OUTPUT, --output OUTPUT
                        Output file for IP addresses
  -w WORKERS, --workers WORKERS
                        Number of parallel workers (default: 10)
```
