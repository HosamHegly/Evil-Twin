import netifaces
from scapy.all import *
import socket
import datetime
import os
import time

from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.inet import TCP, UDP, ICMP, IP


print(os.system("interfaces.sh"))