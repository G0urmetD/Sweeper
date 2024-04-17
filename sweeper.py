import argparse
import subprocess
import concurrent.futures
import socket
from ipaddress import ip_network
from colorama import Fore, Style

# sets the socket timeout for dns resolv higher (in seconds)
socket.setdefaulttimeout(10)

def ping_ip(ip):
    try:
        subprocess.check_output(['ping', '-c', '1', '-W', '1', ip])
        return True
    except subprocess.CalledProcessError:
        return False

def resolve_hostname(ip, dns_server=None):
    try:
        if dns_server:
            resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            resolver.settimeout(2)  # Timeout setzen (optional)
            resolver.connect((dns_server, 53))
            hostname = socket.gethostbyaddr(ip)[0]
            resolver.close()
        else:
            hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.timeout):
        return None

def scan_ip(ip, use_ping, use_dns, dns_server, output_file):
    ip_str = str(ip)
    try:
        if use_ping and ping_ip(ip_str):
            if use_dns:
                hostname = resolve_hostname(ip_str, dns_server)
                print(f'[+] {ip_str} - {hostname if hostname else "Unknown"} is {Fore.GREEN}alive{Style.RESET_ALL}')
                save_ip_to_file(ip_str, hostname, output_file)
            else:
                print(f'[+] {ip_str} is {Fore.GREEN}alive{Style.RESET_ALL}')
                save_ip_to_file(ip_str, None, output_file)
    except Exception as exc:
        print(f'Error checking {ip_str}: {exc}')

def save_ip_to_file(ip, hostname, output_file):
    if output_file:
        with open(output_file, 'a') as file:
            if hostname:
                file.write(f'{ip} - {hostname}\n')
            else:
                file.write(f'{ip}\n')

def main():
    parser = argparse.ArgumentParser(description='IP Sweep Tool')
    parser.add_argument('target', help='Target IP or CIDR range')
    parser.add_argument('-ping', action='store_true', help='Use ping for scanning')
    parser.add_argument('-dns', action='store_true', help='Resolve IP addresses to hostnames')
    parser.add_argument('-dns_server', help='DNS server IP address')
    parser.add_argument('-o', '--output', help='Output file for IP addresses')

    args = parser.parse_args()

    target_ip = args.target
    use_ping = args.ping
    use_dns = args.dns
    dns_server = args.dns_server
    output_file = args.output

    if not use_ping and use_dns:
        print("Error: Please use -ping when using -dns.")
        return

    if use_dns and not dns_server:
        dns_server = None  # Wenn -dns ohne -dns_server verwendet wird, verwende Standard-DNS-Konfiguration

    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print("Error: Invalid IP or CIDR range.")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {
            executor.submit(scan_ip, ip, use_ping, use_dns, dns_server, output_file): ip for ip in network.hosts()
        }

    # Wait for all threads to complete
    for future in concurrent.futures.as_completed(future_to_ip):
        future.result()

if __name__ == '__main__':
    main()
