# Sweeper
![](radar.png)
## Description
<p>Sweeper is a small ping sweep tool. It uses ICMP or ARP as packets to find active hosts in a network.
It is possible to set the workers for faster scans and create an output file with only the IP addresses to pass on to other tools.</p>

## Features
- Ping sweep with ICMP packets
- Output possibility with only the ip addresses to hand them over to other tools
- Adjusting the workers for a faster scan
- Showing scan time
- Colorized commandline output

## Installation
```bash
pip3 install -r requirements.txt
```

## Usage
```bash
# default ping sweep
python3 sweeper.py 192.168.1.0/24 -ping

# default ping sweep with output file
python3 sweeper.py 192.168.1.0/24 -ping -o output.txt

# default ping sweep and adjusting the workers for a faster scan
python3 sweeper.py 192.168.1.0/24 -ping -w 30

# using arp instead of ping [requires sudo privileges]
sudo python3 sweeper.py 192.168.1.0/24 -arp
sudo python3 sweeper.py 192.168.1.0/24 -arp -o output.txt
sudo python3 sweeper.py 192.168.1.0/24 -arp -w 100 -o output.txt

# DNS feature
[sudo] python3 sweeper.py 192.168.1.0/24 -ping/-arp -dns
[sudo] python3 sweeper.py 192.168.1.0/24 -ping/-arp [-o output.txt | -w 50] -dns -dns-server 192.168.1.1
```

## Parameters
| **Parameter** | **Description**                                                                                                                              |
|---------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| -ping         | Runs a single ping packet. If response is there -> system is alive.                                                                    |
| -arp          | Runs arp scan. Can be used instead of ping scan. Requires SUDO privileges |
| -o            | Creates a output.txt file with just the ip addresses, to further usage for example with nmap. |
| -w            | [Optional] Adjusting the workers for a faster scan. Default = 10 |
| -dns          | [Optional] DNS reverse lookup |
| -dns-server   | [Optional] Custom dns-server. Only usable with -dns |
