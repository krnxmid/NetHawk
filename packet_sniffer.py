import pyshark
import signal
from contextlib import suppress
import datetime
import re

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

class PktSniffer:
    def __init__(self, interface="Wi-fi"):
        self.interface = interface # Interface for sniffing
        self.capturing = None # Capture object
        self.is_running = True # Flag to control capturing state
        self.raw = False
    
    def log_packet(self, packet):
        """Logs packet details to a file (removes ANSI escape sequences)."""
        cleaned_packet = ANSI_ESCAPE.sub('', str(packet))  # Remove ANSI codes
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open("NetHawk/packet_log.txt", "a", encoding="utf-8") as log:
            log.write(f"{packet.sniff_time} | {packet.ip.src} -> {packet.ip.dst} | {packet.highest_layer} | Length: {packet.length}\n")

    
    def setup_capture(self, filter):
        """Setup a Capture Object"""
        print("[+] Created Capture Object")
        self.capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=filter)
    
    def handle_interrupt(self, signum, frame):
        """To Handle Interrupts Gracefully"""
        self.is_running = False
        print("\n[+] Stopping Live Capture")
        if self.capture:
            with suppress(Exception):
                self.capture.close() # Finally close the capture object safely
    
    def process_packet(self, packet):
        """Process Packets Info according to their info"""
        try:
            print("-"*40)
            if self.raw:
                print(packet)
            else:
                if hasattr(packet, "ip"): # Check if it has a IP layer
                    print(f"Source IP: {packet.ip.src} -> Dest. Ip {packet.ip.dst}")
                    if hasattr(packet, "tcp"): # If TCP
                        print(f"Protocol: TCP | Port: {packet.tcp.dstport}")
                    elif hasattr(packet, "udp"): # If UDP
                        print(f"Protocol: UDP | Port: {packet.udp.dstport}")
            self.log_packet(packet=packet)
        except AttributeError:
            pass # Skip packets without IP Layer
    
    def start_pkt_capture(self, raw=False, filter=None):
        """Start capturing packets"""
        # Setup signal handler
        signal.signal(signal.SIGINT, self.handle_interrupt)
        
        print(f"[+] Started Sniffer at {self.interface}")
        print("[+] Press Ctrl+C to Stop")

        if raw:
            self.raw = True

        try:
            self.setup_capture(filter=filter)

            self.capture.apply_on_packets(
                self.process_packet,
                timeout=None
            )
        except Exception as e:
            if self.is_running:
                print(f"[!] Error: {e}")
        finally:
            if self.capture:
                with suppress(Exception):
                    self.capture.close()
                print("[+] Capture Object Closed")
            if self.is_running:
                print("\n[+] Sniffer Stopped")

if __name__ == "__main__":
    raw = input("Raw Packets? (y/n): ")
    if raw == "y":
        raw = True
    else:
        raw = False
    
    filter = input("Do you want to apply any filter (eg. src 192.168.1.5): ")
    sniffer = PktSniffer()
    sniffer.start_pkt_capture(raw=raw, filter=filter)