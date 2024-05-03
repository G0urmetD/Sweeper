import argparse
import concurrent.futures
import subprocess
import socket
import time
import nmap

from ipaddress import ip_network
from colorama import Fore, Style

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

#def resolve_hostname(ip, dns_server=None):
#    try:
#        if dns_server:
#            resolver = socket.getaddrinfo(ip, None)[0]
#            hostname = resolver[3]
#        else:
#            hostname = socket.gethostbyaddr(ip)[0]
#        return hostname
#    except (socket.herror, IndexError):
#        return None

def resolve_hostname(ip, dns_server=None):
    try:
        if dns_server:
            resolver = socket.gethostbyaddr(ip)
            hostname = resolver[0]
        else:
            resolver = socket.gethostbyaddr(ip)
            hostname = resolver[0]
        return hostname
    except (socket.herror, IndexError):
        return None


def detect_os(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-O')
    try:
        os_info = nm[ip]['osmatch'][0]['osclass'][0]
        os_family = os_info['osfamily']
        os_vendor = os_info.get('vendor', '')
        os_cpe = os_info.get('cpe', '')
        os_type = os_info.get('type', '')
        os_accuracy = os_info.get('accuracy', '')
        
        if os_family == 'Windows':
            os_version = os_info.get('osgen', '')
            service_pack = os_info.get('ossp', '')
            if os_version and service_pack:
                return f"OS: Windows {os_version} {service_pack}, Vendor: {os_vendor}, CPE: {os_cpe}, Type: {os_type}, Accuracy: {os_accuracy}"
            elif os_version:
                return f"OS: Windows {os_version}, Vendor: {os_vendor}, CPE: {os_cpe}, Type: {os_type}, Accuracy: {os_accuracy}"
            else:
                return f"OS: Windows, Vendor: {os_vendor}, CPE: {os_cpe}, Type: {os_type}, Accuracy: {os_accuracy}"
        elif os_family == 'Linux':
            os_version = os_info.get('osgen', '')
            if os_version:
                return f"OS: Linux {os_version}, Vendor: {os_vendor}, CPE: {os_cpe}, Type: {os_type}, Accuracy: {os_accuracy}"
            else:
                return f"OS: Linux, Vendor: {os_vendor}, CPE: {os_cpe}, Type: {os_type}, Accuracy: {os_accuracy}"
        elif os_family == 'embedded':
            return f"OS: Embedded, Vendor: {os_vendor}, CPE: {os_cpe}, Type: {os_type}, Accuracy: {os_accuracy}"
        else:
            return f"OS: Unknown, Vendor: {os_vendor}, CPE: {os_cpe}, Type: {os_type}, Accuracy: {os_accuracy}"
    except (KeyError, IndexError):
        return 'Unknown'


def scan_ip(ip, use_ping, use_dns, use_arp, reachable_ips, output_file, dns_server=None):
    ip_str = str(ip)
    try:
        if use_ping and ping_ip(ip_str):
            print(f'{Fore.GREEN}[RESULT] {Fore.YELLOW}{ip_str}{Style.RESET_ALL} is {Fore.GREEN}alive{Style.RESET_ALL} {Fore.MAGENTA}(Ping){Style.RESET_ALL}')
            if output_file:
                save_ip_to_file(ip_str, output_file)
            reachable_ips.add(ip_str)
            if use_dns:
                hostname = resolve_hostname(ip_str, dns_server)
        elif use_arp and arp_ping(ip_str):
            print(f'{Fore.GREEN}[RESULT] {Fore.YELLOW}{ip_str}{Style.RESET_ALL} is {Fore.GREEN}alive{Style.RESET_ALL} {Fore.MAGENTA}(ARP){Style.RESET_ALL}')
            if output_file:
                save_ip_to_file(ip_str, output_file)
            reachable_ips.add(ip_str)
            if use_dns:
                hostname = resolve_hostname(ip_str, dns_server)
    except Exception as exc:
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Checking {ip_str}: {exc}')

        
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
    Version: 3.5.7
    """)

    print("========== Starting Sweep ==========")
    
    start_time = time.time()

    parser = argparse.ArgumentParser(description='IP Sweep Tool')
    parser.add_argument('target', help='Target IP or CIDR range')
    parser.add_argument('-ping', action='store_true', help='Use ping for scanning')
    parser.add_argument('-arp', action='store_true', help='Use ARP for scanning')
    parser.add_argument('-dns', action='store_true', help='Resolve IP addresses to hostnames')
    parser.add_argument('-dns-server', help='Custom DNS server for hostname resolution (only applicable with -dns)')
    parser.add_argument('-os', action='store_true', help='Activate OS detection with nmap.')
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
    perform_os_detection = args.os

    if use_dns and not dns_server:
        dns_server = None

    if not any([use_ping, use_arp]):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Please specify at least one scanning method (-ping, -arp).")
        return

    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid IP or CIDR range.")
        return

    reachable_ips = set()

    # Perform the sweep
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_ip = {
            executor.submit(scan_ip, ip, use_ping, use_dns, use_arp, reachable_ips, output_file, dns_server=dns_server): ip 
            for ip in network.hosts()
        }

    # Wait for all threads to complete
    for future in concurrent.futures.as_completed(future_to_ip):
        future.result()

    # Print OS Detection section
    if perform_os_detection:
        print("\n========== OS Detection ==========")
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_os = {executor.submit(detect_os, ip): ip for ip in reachable_ips}
            for future in concurrent.futures.as_completed(future_to_os):
                ip = future_to_os[future]
                os_info = future.result()
                print(f'{Fore.GREEN}[OS]{Style.RESET_ALL} {Fore.YELLOW}{ip}{Style.RESET_ALL} = {Fore.MAGENTA}{os_info}{Style.RESET_ALL}')

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
                    else:
                        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Could not resolve hostname for {ip}: No hostname found')
                except Exception as exc:
                    print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Could not resolve hostname for {ip}: {exc}')


    end_time = time.time()
    scan_time = end_time - start_time
    print()
    print(f'Scan completed in {scan_time:.2f} seconds.')

if __name__ == '__main__':
    main()
