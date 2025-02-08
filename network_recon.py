import subprocess
import re
import nmap
import socket
from scapy.all import ARP, Ether, srp
import requests

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
        url = f"https://api.macvendors.com/{mac}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.text.strip()
            else:
                return "Unknown"
        except Exception as e:
            print(f"[!] Couldn't retrieve vendor information: {e}")
            return "Unknown"

    def get_mac_address(self, ip):
        """Retrieve the MAC address of a device on the local network using ARP requests."""
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
        """Scan the local network for active devices using Nmap."""
        nm = nmap.PortScanner()
        print("\nScanning network, please wait...")
        nm.scan(hosts=self.network_range, arguments="-sn")  # Perform a ping scan

        print("\nConnected Clients:")
        for host in nm.all_hosts():
            ip = host
            mac = nm[host]["addresses"].get("mac", self.get_mac_address(ip))
            vendor = nm[host]["vendor"].get(mac, self.get_vendor(mac))
            hostname = self.get_hostname(ip)

            print(f"IP: {ip}, Hostname: {hostname}, MAC: {mac}, Vendor: {vendor}")
    
    def scan_wifi(self, show_info=False):
        """Scan for available Wi-Fi networks (Windows-only)."""
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True)
        
        # Regular expression to extract SSIDs (network names)
        ssid_pattern = r"SSID\s\d+\s:\s(.+)"
        ssids = re.findall(ssid_pattern, result.stdout)
        
        if show_info:
            print("=" * 40)
            print("Detailed Info of Wi-Fi Nearby Networks:")
            print("=" * 40)
            print(result.stdout)
            print("=" * 40)
        else:
            print("=" * 30)
            print("Available Wi-Fi Nearby Networks:")
            print("=" * 30)
            for ssid in ssids:
                print(ssid)
            print("=" * 30)

if __name__ == "__main__":
    wifi_recon = WifiRecon()
    wifi_recon.scan_wifi()
    wifi_recon.scan_network()
