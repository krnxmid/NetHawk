import subprocess
import re
import nmap
import socket
from scapy.all import ARP, Ether, srp
import requests
from tabulate import tabulate

class WifiRecon:
    """
    A class to perform Wi-Fi and network reconnaissance.
    Capabilities include:
      - Scanning available Wi-Fi networks (Windows)
      - Scanning local network for active hosts (via Nmap and ARP requests)
      - Retrieving MAC addresses, hostnames, and vendors
    """
    
    def __init__(self, network_range="192.168.1.0/24"):
        """Initialize with a default network range."""
        self.network_range = network_range

    def get_vendor(self, mac):
        """Fetch the vendor name using the MAC address lookup API."""
        print("[+] Getting vendor through reverse-searching Mac...")
        url = f"https://api.macvendors.com/{mac}"

        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.text.strip()
            else:
                return "Unknown"
        except Exception as e:
            print("[!] Couldn't retrieve vendor information:", e)
            return "Unknown"

    def get_mac_address(self, ip):
        """Retrieve the MAC address of a device on the local network using ARP requests."""
        print("[+] Trying another method for Mac...")
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=False)[0]
        
        for _, received in result:
            if received.psrc == ip:
                return received.hwsrc
        return "Unknown"

    def get_hostname(self, ip):
        """Attempt to resolve an IP address to a hostname using multiple methods."""
        
        # 1️⃣ Reverse DNS Lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname != ip:
                return hostname
            print("[+] Socket method didn't work trying next...")
        except socket.herror:
            pass  # Continue if reverse lookup fails

        # 2️⃣ NetBIOS Name Lookup (Windows-only)
        if subprocess.run("ver", shell=True, capture_output=True).returncode == 0:  # Check if running on Windows
            try:
                result = subprocess.run(["nbtstat", "-a", ip], capture_output=True, text=True).stdout
                match = re.search(r"(\S+)\s+<00>\s+UNIQUE\s+Registered", result)
                if match and match.group(1) != ip:
                    return match.group(1)
            except:
                pass
        
        return "Unknown"  # If all methods fail

    def scan_network(self):
        """Scan the local network for active devices using Nmap and display results in a table."""
        nm = nmap.PortScanner()
        print("\n[*] Scanning network, please wait...")
        nm.scan(hosts=self.network_range, arguments="-sn")  # Perform a ping scan

        hosts = []
        
        for host in nm.all_hosts():
            ip = host
            print(f"[+] IP address: {ip}")
            print("[+] Getting MAC address..")
            mac = nm[host]["addresses"].get("mac", self.get_mac_address(ip))
            print(f"[+] MAC address: {mac}")
            print("[+] Getting Vendor..")
            vendor = nm[host]["vendor"].get(mac, self.get_vendor(mac))
            print(f"[+] Vendor Found: {vendor}")
            print("[+] Getting hostname...")
            hostname = self.get_hostname(ip)
            print(f"[+] Found hostname: {hostname}")

            # Append to the hosts list for tabular display
            hosts.append([ip, hostname, mac, vendor])

        # Display results in table format
        if hosts:
            # print("\n" + "=" * 80)
            print("\n[+] Connected Clients:")
            # print("=" * 80)
            print(f"\n{tabulate(hosts, headers=["IP Address", "Hostname", "MAC Address", "Vendor"], tablefmt="double_grid")}")
            # print("=" * 80)
        else:
            print("[!] No active devices found on the network.")
    
    def scan_wifi(self, show_info=False):
        """Scan for available Wi-Fi networks (Windows-only) and display more details."""
        print("\n[+] Scanning available Wi-Fi networks...")

        # Run netsh command
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"], 
            capture_output=True, text=True, universal_newlines=True
        )

        output = result.stdout

        # Check if any networks are found
        if "SSID" not in output:
            print("[!] No Wi-Fi networks found.")
            return

        # Regex patterns to extract information
        ssid_pattern = r"SSID\s\d+\s:\s(.+)"
        bssid_pattern = r"BSSID\s\d+\s:\s([0-9a-fA-F:]+)"
        signal_pattern = r"Signal\s+:\s(\d+)%"
        security_pattern = r"Authentication\s+:\s(.+)"
        frequency_pattern = r"Band\s+:\s([\d\.]+ GHz)"
        channel_pattern = r"Channel\s+:\s(\d+)"

        # Extract data
        ssids = re.findall(ssid_pattern, output)
        bssids = re.findall(bssid_pattern, output)
        signals = re.findall(signal_pattern, output)
        security_types = re.findall(security_pattern, output)
        frequencies = re.findall(frequency_pattern, output)
        channels = re.findall(channel_pattern, output)

        # Combine into a structured table
        wifi_data = []
        for i in range(len(ssids)):
            wifi_data.append([
                ssids[i] if i < len(ssids) else "N/A",
                bssids[i] if i < len(bssids) else "N/A",
                signals[i] if i < len(signals) else "N/A",
                security_types[i] if i < len(security_types) else "N/A",
                frequencies[i] if i < len(frequencies) else "N/A",
                channels[i] if i < len(channels) else "N/A"
            ])

        # Print table using tabulate
        # print("\n" + "=" * 80)
        print("[*] Available Wi-Fi Networks:")
        # print("=" * 80)
        print(f"\n{tabulate(wifi_data, headers=["SSID", "BSSID", "Signal %", "Security", "Frequency", "Channel"], tablefmt="double_grid")}")
        # print("=" * 80)

if __name__ == "__main__":
    wifi_recon = WifiRecon()
    wifi_recon.scan_wifi()
    wifi_recon.scan_network()
