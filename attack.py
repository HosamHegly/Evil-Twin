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
from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap, Dot11Deauth, Dot11Beacon, Dot11ProbeResp

mac = ''
client_AP = dict()
AP = {}
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

    args = vars(parser.parse_args())
    if args['interface'] not in netifaces.interfaces():
        print('Interface not found.')
        sys.exit()

    return args['interface'], args['channels']


# switch interface to monitor mode
def monitor_mode(iface):
    try:
        os.system('sudo ifconfig ' + str(iface) + ' down')
        os.system('sudo iwconfig ' + str(iface) + ' mode monitor')
        os.system('sudo ifconfig ' + str(iface) + ' up')
    except:
        print("Make sure that this interface " + iface + " supports monitor mode")


def add_ap(pkt):
    global AP
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Beacon].network_stats()['ssid']
    else:
        ssid = pkt[Dot11ProbeResp].network_stats()['ssid']

    bssid = pkt[Dot11].addr3.lower()  # ap mac address
    ap_channel = str(ord(pkt[Dot11Elt:3].info))
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

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):  # AP
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
        from_ch = from_ch % to_ch + 1
        sniff(prn=handler, iface=iface, timeout=1, monitor=True)
        if time.time() > timeout:
            break


def output():
    dash = '-' * 60
    global AP
    global client_AP
    print(dash)
    print('{:<20s}{:>10s}{:>25s}'.format('ESSID', 'CH', 'Access Points'))
    print(dash)
    for i in AP:
        ssid = AP[i]['ESSID']
        print('{:<20s}{:>10s}{:^40s}'.format(ssid, AP[i]['channel'], i))
    print('\n\n')
    dash = '-' * 80
    print(dash)
    print('{:<20s}{:>10s}{:>25s}{:>25s}'.format('Stations', 'CH', 'ESSID', 'BSSID'))
    print(dash)
    for i in client_AP:
        print('{:<20s}{:>10s}{:^40s}{:>25}'.format(i, client_AP[i]['channel'], client_AP[i]['ESSID'],
                                                   client_AP[i]['BSSID']))


# display a progress bar for aesthetics
def progressbar():
    bar_cls = IncrementalBar
    suffix = '%(percent)d%% [%(elapsed_td)s / %(eta)d / %(eta_td)s]'
    with bar_cls('Scanning', suffix=suffix, max=100) as bar:
        for i in range(100):
            bar.next()
            time.sleep(0.6)


if __name__ == "__main__":
    interface, channel = arg_parse()
    print(presentation)
    progress()
    os.system('clear')
    time.sleep(1)
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
