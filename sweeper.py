import argparse
import concurrent.futures
import subprocess
from ipaddress import ip_network
from colorama import Fore, Style
import time
import socket

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

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def scan_ip(ip, use_ping, use_arp, resolve_hostname, output_file):
    ip_str = str(ip)
    if use_ping and ping_ip(ip_str):
        print(f'[+] {Fore.YELLOW}{ip_str}{Style.RESET_ALL} is {Fore.GREEN}alive{Style.RESET_ALL} (Ping)')
        if resolve_hostname:
            hostname = get_hostname(ip_str)
            if hostname:
                print(f'    - {Fore.GREEN}[+]{Style.RESET_ALL} Hostname: {hostname}')
            else:
                print(f'    - {Fore.RED}[-]{Style.RESET_ALL} Hostname not found')
        save_ip_to_file(ip_str, output_file)
    elif use_arp and arp_ping(ip_str):
        print(f'[+] {Fore.YELLOW}{ip_str}{Style.RESET_ALL} is {Fore.GREEN}alive{Style.RESET_ALL} (ARP)')
        if resolve_hostname:
            hostname = get_hostname(ip_str)
            if hostname:
                print(f'    - {Fore.GREEN}[+]{Style.RESET_ALL} Hostname: {hostname}')
            else:
                print(f'    - {Fore.RED}[-]{Style.RESET_ALL} Hostname not found')
        save_ip_to_file(ip_str, output_file)

def save_ip_to_file(ip, output_file):
    if output_file:
        with open(output_file, 'a') as file:
            file.write(f'{ip}\n')

def main():
    start_time = time.time()

    parser = argparse.ArgumentParser(description='IP Sweep Tool')
    parser.add_argument('target', help='Target IP or CIDR range')
    parser.add_argument('-ping', action='store_true', help='Use ping for scanning')
    parser.add_argument('-arp', action='store_true', help='Use ARP for scanning')
    parser.add_argument('-dns', '--resolve-hostname', action='store_true', help='Resolve hostname for each alive IP address')
    parser.add_argument('-o', '--output', help='Output file for IP addresses')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of parallel workers (default: 10)')

    args = parser.parse_args()

    target_ip = args.target
    use_ping = args.ping
    use_arp = args.arp
    resolve_hostname = args.resolve_hostname
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
            executor.submit(scan_ip, ip, use_ping, use_arp, resolve_hostname, output_file): ip for ip in network.hosts()
        }

    # Wait for all threads to complete
    for future in concurrent.futures.as_completed(future_to_ip):
        future.result()

    end_time = time.time()
    scan_time = end_time - start_time
    print(f'Scan completed in {scan_time:.2f} seconds.')

if __name__ == '__main__':
    main()
