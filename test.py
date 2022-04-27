import argparse
import fcntl
import os
import getmac
from getmac import get_mac_address
from progress.bar import IncrementalBar, ShadyBar, PixelBar, Bar, FillingSquaresBar, ChargingBar, FillingCirclesBar
from progress.spinner import Spinner, MoonSpinner, PixelSpinner, PieSpinner, LineSpinner
from scapy.all import *
import time
import netifaces
import http.server

from scapy.layers.dhcp import DHCP
from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap, Dot11Deauth, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, \
    Dot11AssoResp
from scapy.layers.l2 import Ether


def send_beacon(iface):
    # SSID (name of access point)
    # 802.11 frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2='00:0f:00:5d:2f:8e', addr3='00:0f:00:5d:2f:8e')
    # beacon layer
    beacon = Dot11Beacon()
    # putting ssid in the frame
    essid = Dot11Elt(ID="SSID", info='ass', len=len('ass'))
    # stack all the layers and add a RadioTap
    frame = RadioTap() / dot11 / beacon / essid
    # send the frame in layer 2 every 200 milliseconds forever
    sendp(frame, inter=0.2, iface=iface, loop=1, verbose=0)


def handler(pkt):
    if pkt.haslayer(Ether):
        print(pkt.getlayer(Ether).src)
        return True


iface = 'wlan0mon'
sniff(iface=iface, filter='udp and (src port 68 and dst port 67)', stop_filter=handler)
