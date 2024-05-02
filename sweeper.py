import argparse
import concurrent.futures
import subprocess
from ipaddress import ip_network
from colorama import Fore, Style
import socket
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

def resolve_hostname(ip, dns_server=None):
    try:
        if dns_server:
            resolver = socket.Resolver(configure=False)
            resolver.nameservers = [dns_server]
            hostname = resolver.gethostbyaddr(ip)[0]
        else:
            hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return None

def scan_ip(ip, use_ping, use_arp, reachable_ips, output_file):
    ip_str = str(ip)
    try:
        if use_ping and ping_ip(ip_str):
            print(f'{Fore.GREEN}[+] {Fore.YELLOW}{ip_str}{Style.RESET_ALL} is {Fore.GREEN}alive{Style.RESET_ALL} (Ping)')
            reachable_ips.add(ip_str)
            save_ip_to_file(ip_str, output_file)
        elif use_arp and arp_ping(ip_str):
            print(f'{Fore.GREEN}[+] {Fore.YELLOW}{ip_str}{Style.RESET_ALL} is {Fore.GREEN}alive{Style.RESET_ALL} (ARP)')
            reachable_ips.add(ip_str)
            save_ip_to_file(ip_str, output_file)
    except Exception as exc:
        print(f'Error checking {ip_str}: {exc}')
        
def save_ip_to_file(ip, output_file):
    if output_file:
        with open(output_file, 'a') as file:
            file.write(f'{ip}\n')

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

    Author: G0urmetD (403 - Forbidden)
    Version: 3.3.2
    """)

    print("========== Starting Sweep ==========")
    
    start_time = time.time()

    parser = argparse.ArgumentParser(description='IP Sweep Tool')
    parser.add_argument('target', help='Target IP or CIDR range')
    parser.add_argument('-ping', action='store_true', help='Use ping for scanning')
    parser.add_argument('-arp', action='store_true', help='Use ARP for scanning')
    parser.add_argument('-dns', action='store_true', help='Resolve IP addresses to hostnames')
    parser.add_argument('-dns-server', help='Custom DNS server for hostname resolution (only applicable with -dns)')
    parser.add_argument('-o', '--output', help='Output file for IP addresses')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of parallel workers (default: 10)')

    args = parser.parse_args()

    target_ip = args.target
    use_ping = args.ping
    use_arp = args.arp
    use_dns = args.dns
    dns_server = args.dns_server
    output_file = args.output
    num_workers = args.workers

    if use_dns and not dns_server:
        dns_server = None

    if not any([use_ping, use_arp]):
        print("Error: Please specify at least one scanning method (-ping, -arp).")
        return

    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print("Error: Invalid IP or CIDR range.")
        return

    reachable_ips = set()

    # Perform the sweep
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_ip = {
            executor.submit(scan_ip, ip, use_ping, use_arp, reachable_ips, output_file): ip for ip in network.hosts()
        }

    # Wait for all threads to complete
    for future in concurrent.futures.as_completed(future_to_ip):
        future.result()

    # Print DNS Reverse Lookup section
    if use_dns:
        print("\n========== DNS Reverse Lookup ==========")
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_hostname = {executor.submit(resolve_hostname, ip, dns_server): ip for ip in reachable_ips}
            for future in concurrent.futures.as_completed(future_to_hostname):
                ip = future_to_hostname[future]
                try:
                    hostname = future.result()
                    if hostname:
                        print(f'{Fore.GREEN}[+] {Fore.YELLOW}{ip} = {Fore.BLUE}{hostname}{Style.RESET_ALL}')
                except Exception as exc:
                    print(f'{Fore.RED}Error resolving hostname for {ip}: {exc}{Style.RESET_ALL}')

    end_time = time.time()
    scan_time = end_time - start_time
    print(f'Scan completed in {scan_time:.2f} seconds.')

if __name__ == '__main__':
    main()
