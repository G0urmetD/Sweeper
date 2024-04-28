import argparse
import concurrent.futures
import subprocess
import socket
import nmap  # Installiere nmap mit pip install python-nmap
from ipaddress import ip_network
from colorama import Fore, Style
import time

def ping_ip(ip):
    try:
        subprocess.check_output(['ping', '-c', '1', '-W', '1', ip])
        return True
    except subprocess.CalledProcessError:
        return False

def arp_ping(ip):
    try:
        subprocess.run(['arping', '-c', '1', '-W', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def get_host_info(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror) as e:
        print(f"Error getting hostname for {ip}: {e}")
        print(f"Socket result: {socket.gethostbyaddr(ip)}")
        return ip

def get_open_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-p 1-65535 --open')  # Scan für offene Ports auf allen Ports
    open_ports = []
    for proto in nm[ip].all_protocols():
        ports = nm[ip][proto].keys()
        for port in ports:
            open_ports.append(port)
    return open_ports

def scan_ip(ip, use_ping, use_arp, use_info, output_file):
    ip_str = str(ip)
    try:
        if use_ping and ping_ip(ip_str):
            print(f'{Fore.GREEN}[+] {Fore.YELLOW}{ip_str}{Style.RESET_ALL} is {Fore.GREEN}alive{Style.RESET_ALL} (Ping)')
            if use_info:
                hostname = get_host_info(ip_str)
                open_ports = get_open_ports(ip_str)
                save_ip_to_file(ip_str, hostname, open_ports, output_file)
            else:
                save_ip_to_file(ip_str, "Unknown", [], output_file)
        elif use_arp and arp_ping(ip_str):
            print(f'{Fore.GREEN}[+] {Fore.YELLOW}{ip_str}{Style.RESET_ALL} is {Fore.GREEN}alive{Style.RESET_ALL} (ARP)')
            if use_info:
                hostname = get_host_info(ip_str)
                open_ports = get_open_ports(ip_str)
                save_ip_to_file(ip_str, hostname, open_ports, output_file)
            else:
                save_ip_to_file(ip_str, "Unknown", [], output_file)
    except Exception as exc:
        print(f'Error checking {ip_str}: {exc}')

def save_ip_to_file(ip, hostname, open_ports, output_file):
    if output_file:
        with open(output_file, 'a') as file:
            if hostname != "Unknown":
                file.write(f'IP: {ip}, Hostname: {hostname}, Open Ports: {open_ports}\n')
            else:
                file.write(f'IP: {ip}, Hostname: {hostname}\n')

def main():
    # ASCII banner
    print(r"""
     _____                                   
    /  ___|                                  
    \ `--.__      _____  ___ _ __   ___ _ __ 
     `--. \ \ /\ / / _ \/ _ \ '_ \ / _ \ '__|
    /\__/ /\ V  V /  __/  __/ |_) |  __/ |   
    \____/  \_/\_/ \___|\___| .__/ \___|_|   
                            | |              
                            |_|              

    Auhtor: G0urmetD (403 - Forbidden)
    Version: 2.1
    """)

    # Starting Portscan
    print("========== Starting Portscan ==========")
    
    start_time = time.time()

    parser = argparse.ArgumentParser(description='IP Sweep Tool')
    parser.add_argument('target', help='Target IP or CIDR range')
    parser.add_argument('-ping', action='store_true', help='Use ping for scanning')
    parser.add_argument('-arp', action='store_true', help='Use ARP for scanning')
    parser.add_argument('-info', action='store_true', help='Get additional host information')
    parser.add_argument('-o', '--output', help='Output file for IP addresses')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of parallel workers (default: 10)')

    args = parser.parse_args()

    target_ip = args.target
    use_ping = args.ping
    use_arp = args.arp
    use_info = args.info
    output_file = args.output
    num_workers = args.workers

    if not any([use_ping, use_arp]):
        print("Error: Please specify at least one scanning method (-ping, -arp).")
        return

    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print("Error: Invalid IP or CIDR range.")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_ip = {
            executor.submit(scan_ip, ip, use_ping, use_arp, use_info, output_file): ip for ip in network.hosts()
        }

    # Wait for all threads to complete
    for future in concurrent.futures.as_completed(future_to_ip):
        future.result()

    end_time = time.time()
    scan_time = end_time - start_time
    print(f'Scan completed in {scan_time:.2f} seconds.')

if __name__ == '__main__':
    main()
