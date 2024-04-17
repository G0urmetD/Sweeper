# Sweeper
![](radar.png)
## Description
<p>Sweeper is a small commandline tool, to ping sweep a network or single ip address.</p>

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

# ping sweep with dns resolve
python3 sweeper.py 192.168.1.0/24 -ping -dns

# ping sweep with dns resolve and custom dns server ip
python3 sweeper.py 192.168.1.0/24 -ping -dns -dns_server 192.168.1.1
```

## Parameters
| **Parameter** | **Description**                                                                                                                              |
|---------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| -ping         | Runs a single ping packet. If response is there -> system is alive.                                                                          |
| -o            | Creates a output.txt file with just the ip addresses, to further usage for example with nmap. |
| -dns            | Resolve ip-addresses into hostnames. |
| -dns_server            | Defines a custom DNS server. |
