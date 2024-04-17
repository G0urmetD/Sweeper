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

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None
    except socket.timeout:
        return None

def scan_ip(ip, use_ping, use_dns, output_file):
    ip_str = str(ip)
    try:
        if use_ping and ping_ip(ip_str):
            print(f'[+] {ip_str} - {resolve_hostname(ip_str) if use_dns else ip_str} is {Fore.GREEN}alive{Style.RESET_ALL}')
            save_ip_to_file(ip_str, resolve_hostname(ip_str) if use_dns else None, output_file)
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
    parser.add_argument('-o', '--output', help='Output file for IP addresses')

    args = parser.parse_args()

    target_ip = args.target
    use_ping = args.ping
    use_dns = args.dns
    output_file = args.output

    if not use_ping and use_dns:
        print("Error: Please use -ping when using -dns.")
        return

    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print("Error: Invalid IP or CIDR range.")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {
            executor.submit(scan_ip, ip, use_ping, use_dns, output_file): ip for ip in network.hosts()
        }

    # Wait for all threads to complete
    for future in concurrent.futures.as_completed(future_to_ip):
        future.result()

if __name__ == '__main__':
    main()
