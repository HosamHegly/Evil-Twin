import os
import sys

from alive_progress import alive_bar
from progress.bar import IncrementalBar, ShadyBar, PixelBar
from scapy.all import *
from threading import Thread
import pandas
import time
import netifaces
import alive_progress

# global variables
from scapy.layers.dot11 import Dot11

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
networks.set_index("BSSID", inplace=True)
macs = dict()
interface = ""
network_mac = ""
devices_macs = dict()
victim_mac = ""
i2 = 0
tic = time.perf_counter()
ch = 1
devices = dict()
Networks = dict()
presentation = '''

  ______           _   _     _______              _         
 |  ____|         (_) | |   |__   __|            (_)        
 | |__    __   __  _  | |      | |    __      __  _   _ __  
 |  __|   \ \ / / | | | |      | |    \ \ /\ / / | | | '_ \ 
 | |____   \ V /  | | | |      | |     \ V  V /  | | | | | |
 |______|   \_/   |_| |_|      |_|      \_/\_/   |_| |_| |_|


made by: Hosam Hegly, Ayman Younis, Ahmad Abed
'''


def main():
    global victim_mac
    global network_mac
    global interface
    global presentation
    print(presentation)
    interface = get_interface()
    monitor_mode(interface)
    print("[+]Interface switched to monitor mode successfully")
    print("[+]Scanning for wireless networks over all channels this will take 1 minute")
    # change interface wifi channel
    os.system("clear")
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    progbar = Thread(target=progressbar(), daemon=True)
    progbar.start()
    sniff(prn=callback, iface=interface, timeout=60)


# display a progress bar for aesthetics
def progressbar():
    bar_cls = IncrementalBar
    suffix = '%(percent)d%% [%(elapsed_td)s / %(eta)d / %(eta_td)s]'
    with bar_cls('Scanning', suffix=suffix, max=100) as bar:
        for i in range(100):
            bar.next()
            time.sleep(0.6)


# get a list of all the interfaces and return the interface chosen by the user
def get_interface():
    interface_names = netifaces.interfaces()  # get interfaces
    interfaces_length = str(len(interface_names) - 1) + ""
    for i in range(0, len(interface_names)):
        print(i, ":", interface_names[i])
    interface_index = input("\nchoose the WIFI interface you want to sniff packets from"
                            "(press 0 - " + interfaces_length + "): ")
    while '0' > str(interface_index) or str(interface_index) > interfaces_length:  # if the user chose wrong number
        interface_index = input("\n\nERROR: please choose between numbers 0 - " + interfaces_length + ": ")
    iface = interface_names[int(interface_index)]
    return iface


# switch interface to monitor mode
def monitor_mode(iface):
    try:
        os.system("bash mon.sh " + iface)
    except:
        print("ERROR: make sure that", iface, "Supports monitor mode.")
        sys.exit(0)


# change channels
def change_channel():
    global ch
    os.system("iwconfig " + interface + " channel " + str(ch))
    # switch channel from 1 to 14 each 0.5s
    ch = ch % 14 + 1
    time.sleep(0.5)


# captures wireless networks and devices with packets sniffed by scapy
def callback(pkt):
    if pkt.haslayer(Dot11):
        ds = pkt.FCfield & 0x3  # Distribution server
        to_ds = ds & 0x1 != 0  # to access point
        from_ds = ds & 0x2 != 0  # from access point


main()
# progressbar()
