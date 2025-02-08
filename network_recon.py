import subprocess
import re
import nmap
import socket
from scapy.all import ARP, Ether, srp
import requests

class WifiRecon:
    def __init__(self, network_range="192.168.1.0/24"):
        self.network_range = network_range

    def get_vendor(self, mac):
        url = f"https://api.macvendors.com/{mac}"

        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.text
            else:
                return "Unkown"
        except Exception as e:
            print(f"[!] Couldn't get vendor address: {e}")
            return "Unkown"

    def get_mac_address(self, ip):
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=False)[0]

        for sent, recieved in result:
            if recieved.psrc == ip:
                return recieved.hwsrc
        return "Unkown"

    def get_hostname(self, ip):
        """Tries multiple methods to resolve a hostname from an IP."""
        
        # 1️⃣ Try Reverse DNS Lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]  # Returns hostname
            if hostname != ip:  # Ensure it actually found a name
                return hostname
        except socket.herror:
            pass  # Move to next method if it fails

        # 2️⃣ Try NetBIOS Name (Windows)
        if subprocess.run("ver", shell=True, capture_output=True).returncode == 0:  # Checks if Windows
            try:
                result = subprocess.run(["nbtstat", "-a", ip], capture_output=True, text=True).stdout
                match = re.search(r"(\S+)\s+<00>\s+UNIQUE\s+Registered", result)
                if match and match.group(1) != ip:
                    return match.group(1)  # Extract NetBIOS name
            except:
                pass
            
        return "Unknown"  # If all methods fail

    def scan_network(self):
        nm = nmap.PortScanner()
        print("\nScanning network, please wait...")
        nm.scan(hosts=self.network_range, arguments="-sn")  # Ping scan

        print("\nConnected Clients:")
        for host in nm.all_hosts():
            ip = host
            mac = nm[host]["addresses"].get("mac", self.get_mac_address(ip))
            vendor = nm[host]["vendor"].get(mac, self.get_vendor(mac=mac))
            hostname = self.get_hostname(ip)  # Get hostname using reverse DNS

            print(f"IP: {ip}, Hostname: {hostname}, MAC: {mac}, Vendor: {vendor}")
    
    def scan_wifi(self, show_info=False):
        # Run netsh command to scan Wi-Fi networks (Works on Windows)
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True)

        # Regular expression to extract SSIDs (Network names)
        ssid_pattern = r"SSID\s\d+\s:\s(.+)"
        ssids = re.findall(ssid_pattern, result.stdout)

        # Display SSID names only

        if show_info:
            print("="*40)
            print("Detailed Info of Wi-Fi Nearby-Networks:")
            print("="*40)
            print(result.stdout)
            print("="*40)
        else:
            print("="*30)
            print("Available Wi-Fi Nearby-Networks:")
            print("="*30)
            for ssid in ssids:
                print(ssid)
            print("="*30)

if __name__ == "__main__":
    wifi_recon = WifiRecon()
    wifi_recon.scan_wifi()
    wifi_recon.scan_network()
