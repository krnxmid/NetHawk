import pyshark
import signal
from contextlib import suppress
import datetime
import re

# Regular expression to remove ANSI escape sequences (used for colored outputs)
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

class PacketSniffer:
    def __init__(self, interface="Wi-Fi"):
        """
        Initializes the packet sniffer.
        :param interface: The network interface to capture packets from.
        """
        self.interface = interface  # Interface for sniffing
        self.capture = None  # Pyshark capture object
        self.is_running = True  # Flag to control capturing state
        self.raw = False  # Whether to show raw packet data
        self.log_pkt = False
    
    def log_packet(self, packet):
        """
        Logs packet details to a file while removing ANSI escape sequences.
        :param packet: Captured packet object.
        """
        try:
            cleaned_packet = ANSI_ESCAPE.sub('', str(packet))  # Remove ANSI codes
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Log packet details into a file
            with open("NetHawk/packet_log.txt", "a", encoding="utf-8") as log:
                log.write(f"{timestamp} | {packet.ip.src} -> {packet.ip.dst} | "
                          f"{packet.highest_layer} | Length: {packet.length}\n")
        except AttributeError:
            pass  # Skip packets without IP layer

    def setup_capture(self, filter=None):
        """
        Sets up the packet capture object.
        :param filter: A BPF (Berkeley Packet Filter) string to filter packets.
        """
        print("[+] Creating Capture Object...")
        self.capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=filter)

    def handle_interrupt(self, signum, frame):
        """
        Gracefully handles interrupt signals (Ctrl+C).
        """
        self.is_running = False
        print("\n[+] Stopping Live Capture...")
        
        if self.capture:
            with suppress(Exception):
                self.capture.close()  # Safely close capture object
    
    def process_packet(self, packet):
        """
        Processes captured packets and prints relevant information.
        :param packet: The captured network packet.
        """
        try:
            if self.raw:
                print("\n" + "═" * 60)
                print(packet)  # Print raw packet details
                print("═" * 60)
            else:
                if hasattr(packet, "ip"):  # Check if packet has an IP layer
                    print("\n" + "═" * 60)
                    print(f"{'Source IP':<20}: {packet.ip.src}")
                    print(f"{'Destination IP':<20}: {packet.ip.dst}")
                    
                    if hasattr(packet, "tcp"):  # TCP packets
                        print(f"{'Protocol':<20}: TCP")
                        print(f"{'Destination Port':<20}: {packet.tcp.dstport}")
                    elif hasattr(packet, "udp"):  # UDP packets
                        print(f"{'Protocol':<20}: UDP")
                        print(f"{'Destination Port':<20}: {packet.udp.dstport}")
                    
                    print("═" * 60)
            if self.log_pkt:
                self.log_packet(packet)  # Log packet details to file
        
        except AttributeError:
            pass  # Skip packets without necessary attributes

    def start_pkt_capture(self, raw=False, filter=None, log_pkt=False):
        """
        Starts live packet capture on the specified interface.
        :param raw: Whether to display raw packet details.
        :param filter: A BPF filter string.
        """
        # Handle Ctrl+C interrupt to stop capture
        signal.signal(signal.SIGINT, self.handle_interrupt)
        
        print(f"[+] Started Sniffer on interface: {self.interface}")
        print("[+] Press Ctrl+C to Stop")

        self.log_pkt= log_pkt
        self.raw = raw  # Set raw mode

        try:
            self.setup_capture(filter=filter)  # Initialize capture

            # Process packets in real-time
            self.capture.apply_on_packets(self.process_packet, timeout=None)

        except Exception as e:
            if self.is_running:
                print(f"[!] Error: {e}")

        finally:
            # Ensure capture object is closed properly
            if self.capture:
                with suppress(Exception):
                    self.capture.close()
                print("[+] Capture Object Closed")
            
            if self.is_running:
                print("\n[+] Sniffer Stopped")

# Main Execution Block
if __name__ == "__main__":
    # Ask user whether to show raw packets
    raw_input = input("Show raw packets? (y/n): ").strip().lower()
    raw = True if raw_input == "y" else False

    # Ask user for a packet filter (optional)
    filter_input = input("Apply a packet filter? (e.g., 'src 192.168.1.5'): ").strip()
    filter_str = filter_input if filter_input else None

    # Initialize and start the sniffer
    sniffer = PacketSniffer()
    sniffer.start_pkt_capture(raw=raw, filter=filter_str)
