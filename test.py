import netifaces
from scapy.all import *
import socket
import datetime
import os
import time

from scapy.layers.inet import TCP, UDP, ICMP, IP


def network_monitoring_for_visualization_version(pkt):
    print(str(pkt))

def get_interface():
    interface_names = netifaces.interfaces()  # get interfaces
    interfaces_length = str(len(interface_names) - 1) + ""
    for i in range(0, len(interface_names)):
        print(i, ":", interface_names[i])
    interface_index = input("\nchoose the WIFI interface you want to sniff packets from"
                            "(press 0 - " + interfaces_length + "): ")
    while '0' > str(interface_index) or str(interface_index) > interfaces_length:  # if the user chose wrong number
        interface_index = input("\n\nERROR: please choose the interface" + interfaces_length + ": ")
    iface = interface_names[int(interface_index)]
    return iface

def monitor(interface):
    os.system('sudo ifconfig ' +str(interface) + ' down')
    os.system('sudo iwconfig ' +str(interface) + ' mode monitor')
    os.system('sudo ifconfig ' +str(interface) + ' up')


interface = get_interface()
monitor(interface)
print("sniffing...")
sniff(iface=interface, prn=network_monitoring_for_visualization_version)

