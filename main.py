import time
from colorama import Fore, Style
from network_recon import WifiRecon  # Importing your class
from packet_sniffer import PacketSniffer
import os

# Function to display a header
def print_header(title):
    print(Fore.WHITE + "═" * 50)
    print(Fore.GREEN + title.center(50))
    print(Fore.WHITE + "═" * 50 + Style.RESET_ALL)

# Function to show a loading effect
def loading_animation(message="Processing"):
    print(Fore.GREEN + message, end="", flush=True)
    for _ in range(3):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print("\n" + Style.RESET_ALL)

# Function to display the banner from 'banner.txt'
def print_banner():
    # Get the absolute path of the banner.txt file
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    banner_path = os.path.join(script_dir, 'banner.txt')
    
    try:
        with open(banner_path, 'r', encoding='utf-8') as file:
            banner = file.read()
            print(banner)
    except UnicodeDecodeError:
        print("Error: Could not decode the file. It might contain non-UTF-8 characters.")
    except FileNotFoundError:
        print(f"Error: The file {banner_path} does not exist.")


def run_sniff_function(method_name):
    # Create an instance of WifiRecon
    raw_input = input("[?] Show raw packets? (y/n): ").strip().lower()
    raw = True if raw_input == "y" else False

    # Ask user for a packet filter (optional)
    filter_input = input("[?] Apply a packet filter? (e.g., 'src 192.168.1.5'): ").strip()
    filter_str = filter_input if filter_input else None

    interface = input("[?] Interface (default: Wi-Fi): ").strip()
    interface_str = interface if interface else "Wi-Fi"

    log_pkt = input("[?] Do you want to save the output? (y/n): ")
    log_pkt_str = True if log_pkt == "y" else False

    # Get the method dynamically by name
    tshark = PacketSniffer(interface=interface_str)
    print(Fore.BLUE + f"\n[INFO] Running {method_name}...\n" + Style.RESET_ALL)
    loading_animation("Executing")
    tshark.start_pkt_capture(raw=raw, filter=filter_str, log_pkt=log_pkt_str)
    
    input("\nPress Enter to continue...")

# Function to run any WifiRecon method
def run_wifi_function(method_name):
    # Create an instance of WifiRecon
    wifirecon = WifiRecon()

    # Get the method dynamically by name
    method = getattr(wifirecon, method_name, None)

    if method and callable(method):
        print(Fore.BLUE + f"\n[INFO] Running {method_name}...\n" + Style.RESET_ALL)
        loading_animation("[INFO] Executing")

        # Interactive input based on method name
        if method_name == "get_vendor":
            mac = input("[?] Enter MAC Address: ").lower()
            vendor_name = method(mac)
            if vendor_name == "Unknown":
                print(f"\n[+] Vendor name not found: {Fore.RED}{vendor_name}{Style.RESET_ALL}")
            else:
                print(f"\n[+] Vendor name found: {Fore.GREEN}{vendor_name}{Style.RESET_ALL}")

        elif method_name == "get_hostname":
            ip = input("[?] Enter IP Address: ").strip()
            hostname = method(ip)
            if hostname == "Unknown":
                print(f"\n[+] Hostname not found: {Fore.RED}{hostname}{Style.RESET_ALL}")
            else:
                print(f"\n[+] Hostname found: {Fore.GREEN}{hostname}{Style.RESET_ALL}")

        elif method_name == "get_mac_address":
            ip = input("[?] Enter IP Address: ").strip()
            mac_address = method(ip)
            if mac_address == "Unknown":
                print(f"\n[+] MAC address not found: {Fore.RED}{mac_address}{Style.RESET_ALL}")
            else:
                print(f"\n[+] MAC address found: {Fore.GREEN}{mac_address}{Style.RESET_ALL}")

        else:
            # For other methods, no user input is needed
            method()

    else:
        print(Fore.RED + f"\n[ERROR] {method_name} is not a valid function in WifiRecon.\n" + Style.RESET_ALL)
    
    input("\n[?] Press Enter to continue...")

# Main menu loop
def main():
    # Print the banner from 'banner.txt'
    print_banner()

    while True:
        print_header("NetHawk - Network Tools")

        print(Fore.GREEN + "\n[1] Scan Nearby Wi-Fi")
        print(Fore.GREEN + "[2] ARP Scan connected clients" + Style.RESET_ALL)
        print(Fore.GREEN + "[3] Sniff Network Packets" + Style.RESET_ALL)
        print(Fore.GREEN + "[4] Get Vendor Name" + Style.RESET_ALL)
        print(Fore.GREEN + "[5] Get Hostname" + Style.RESET_ALL)
        print(Fore.GREEN + "[6] Get MAC Address" + Style.RESET_ALL)
        print(Fore.GREEN + "\n[x] Exit" + Style.RESET_ALL)

        choice = input(f"\n{Fore.GREEN}>>>{Style.RESET_ALL} Enter choice: ")

        if choice == "1":
            run_wifi_function("scan_wifi")  # Run the Wi-Fi scan method
        elif choice == "2":
            run_wifi_function("scan_network")  # Run the ARP scan method
        elif choice == "3":
            run_sniff_function("start_pkt_capture")
        elif choice == "4":
            run_wifi_function("get_vendor")  # Run the Get Vendor method
        elif choice == "5":
            run_wifi_function("get_hostname")  # Run the Get Hostname method
        elif choice == "6":
            run_wifi_function("get_mac_address")  # Run the Get MAC Address method
        elif choice == "clear":
            os.system("cls")
            print_banner()
        elif choice == "x":
            print(Fore.RED + "\n[INFO] Exiting...\n" + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "\n[ERROR] Invalid choice! Try again.\n" + Style.RESET_ALL)
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit()
