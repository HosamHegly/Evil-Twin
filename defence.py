import signal

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon, RadioTap

AP = dict()
mac = ''
essid = ''
ch = 1
stop_thread = False
evil = ''


def handler(pkt):
    global AP
    global mac
    if pkt.haslayer(Dot11Deauth) and pkt.addr2 is not None and pkt.addr3 is not None:
        if pkt.addr3 not in AP:
            AP[pkt.addr3] = 0

        else:
            AP[pkt.addr3] += 1
            if AP[pkt.addr3] > 30:
                print("[+] detected possible deauth attack on " + pkt.addr3)
                mac = pkt.addr3
                return True


# switch interface to monitor mode
def monitor_mode(iface):
    try:
        os.system('sudo ifconfig ' + str(iface) + ' down')
        os.system('sudo iwconfig ' + str(iface) + ' mode monitor')
        os.system('sudo ifconfig ' + str(iface) + ' up')
    except:
        print("Make sure that this interface " + iface + " supports monitor mode")
    print("[+] switched to monitor mode")


def ap_handler(pkt):
    global ssid
    if pkt.haslayer(Dot11):

        if pkt.haslayer(Dot11Beacon):  # AP
            if pkt.addr2 is not None:
                if pkt.addr2 == mac and ssid == '':
                    ssid = pkt[Dot11Beacon].network_stats()['ssid']
                elif ssid != '' and pkt.addr2 != mac:
                    if pkt[Dot11Beacon].network_stats()['ssid'] == ssid:
                        print("[+] Possible Evil twin detected")
                        sys.exit()


def change_channel(iface):
    global stop_thread
    while True:
        ch = 1
        os.system("iwconfig " + iface + " channel " + str(ch))
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)
        if stop_thread:
            break


def sig_handler(signum, frame):
    print("bye")
    sys.exit()


def add_ap(pkt):
    global from_ch
    global AP
    global essid
    global evil
    ssid = pkt[Dot11Beacon].network_stats()['ssid']

    bssid = pkt[Dot11].addr3.lower()  # ap mac address
    if str(bssid).lower() == mac.lower():
        essid = ssid
    if essid != '' and ssid == essid and bssid != mac.lower():
        evil = bssid

    ap_channel = str(from_ch)
    if bssid in AP:
        return
    else:
        AP[bssid] = {}
        AP[bssid]['channel'] = ap_channel
        AP[bssid]['ESSID'] = ssid


def sniffer(iface):
    global ch
    timeout = time.time() + 60  # a minute  from now
    while True:
        os.system("iwconfig " + iface + " channel " + str(ch))  # switch channel
        ch = ch % 14 + 1
        sniff(prn=handler, iface=iface, timeout=1)
        if time.time() > timeout:
            break


def deauth(iface):
    global evil
    dot11 = Dot11(type=0, subtype=12, addr1='ff:ff:ff:ff:ff:ff', addr2=evil, addr3=evil)
    frame = RadioTap() / dot11 / Dot11Deauth(reason=7)
    os.system("iwconfig " + iface + " channel " + str(AP[evil]['channel']))
    print("[+] started deauth attack...")
    sendp(frame, iface=iface, loop=1, inter=.1, verbose=1)


if __name__ == "__main__":
    interface = input("please enter the name of the interface you want to work with: ")
    monitor_mode(interface)
    time.sleep(1)
    Th = Thread(target=change_channel, args=(interface,)).start()
    time.sleep(2)
    while True:
        print("[+]starting scan if you want to stop press ctrl-c")

        signal.signal(signal.SIGINT, sig_handler)

        print("[+] scanning for deauth attacks")
        sniff(iface=interface, stop_filter=handler)
        stop_thread = True
        Th.join()
        print("[+] scanning APs and checking for evil twin this will take a minute...")
        sniffer(interface)
        if evil != '':
            print("[+]evil twin detected", evil, " launching deauth attack on evil AP press ctrl-c to stop")
            deauth(interface)

        else:
            print("[+] didnt detect evil twin")

        for i in AP:
            AP[i] = 0
