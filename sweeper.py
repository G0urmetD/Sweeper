import argparse
import subprocess
import concurrent.futures
from ipaddress import ip_network
from colorama import Fore, Style

def ping_ip(ip):
    try:
        subprocess.check_output(['ping', '-c', '1', '-W', '1', ip])
        return True
    except subprocess.CalledProcessError:
        return False

def scan_ip(ip, use_ping, output_file):
    ip_str = str(ip)
    try:
        if use_ping and ping_ip(ip_str):
            print(f'[+] {ip_str} is {Fore.GREEN}alive{Style.RESET_ALL}')
            save_ip_to_file(ip_str, output_file)
    except Exception as exc:
        print(f'Error checking {ip_str}: {exc}')

def save_ip_to_file(ip, output_file):
    if output_file:
        with open(output_file, 'a') as file:
            file.write(f'{ip}\n')

def main():
    parser = argparse.ArgumentParser(description='IP Sweep Tool')
    parser.add_argument('target', help='Target IP or CIDR range')
    parser.add_argument('-ping', action='store_true', help='Use ping for scanning')
    parser.add_argument('-o', '--output', help='Output file for IP addresses')

    args = parser.parse_args()

    target_ip = args.target
    use_ping = args.ping
    output_file = args.output

    if not use_ping:
        print("Error: Please use -ping.")
        return

    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print("Error: Invalid IP or CIDR range.")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {
            executor.submit(scan_ip, ip, use_ping, output_file): ip for ip in network.hosts()
        }

    # Wait for all threads to complete
    for future in concurrent.futures.as_completed(future_to_ip):
        future.result()

if __name__ == '__main__':
    main()
