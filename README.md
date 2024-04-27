# Sweeper
![](radar.png)
## Description
<p>Sweeper is a small commandline tool, to ping sweep a network or single ip address.</p>

## Features
- Ping sweep with ICMP packets
- Output possibility with only the ip addresses to hand them over to other tools
- Adjusting the workers for a faster scan
- Showing scan time

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
python3 sweeper.py 192.168.1.0/24 -ping -w 30 -o output.txt
```

## Parameters
| **** | **Parameter** | **Description**                                                                                                                              |
|------|---------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| [Required] | -ping         | Runs a single ping packet. If response is there -> system is alive.                                                                    |
| [Required] | -arp          | Runs arp scan. Can be used instead of ping scan. Requires SUDO privileges |
| [Optional ] | -o            | Creates a output.txt file with just the ip addresses, to further usage for example with nmap. |
| [Optional ] | -w            | [Optional] Adjusting the workers for a faster scan. Default = 10 |
