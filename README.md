# Sweeper
![](radar.png)
## Description
<p>Sweeper is a small commandline tool, to ping sweep a network or single ip address.</p>

## Installation
```bash
pip3 install requirements.txt
```

## Usage
```bash
# default ping sweep
python3 sweeper.py 192.168.1.0/24 -ping

# default ping sweep with output file
python3 sweeper.py 192.168.1.0/24 -ping -o output.txt
```

## Parameters
| **Parameter** | **Description**                                                                                                                              |
|---------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| -ping         | Runs a single ping packet. If response is there -> system is alive.                                                                          |
| -o            | Creates a output.txt file with just the ip addresses, to further usage for example with nmap. |
