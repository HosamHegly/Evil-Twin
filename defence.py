import signal

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon

stations = dict()
mac = ''
ssid = ''


def handler(pkt):
    global stations
    global mac
    if pkt.haslayer(Dot11Deauth) and pkt.addr2 is not None and pkt.addr3 is not None:
        if pkt.addr1 not in stations:
            stations[pkt.addr1] = 0

        else:
            stations[pkt.addr1] += 1
            if stations[pkt.addr1] > 30:
                print("[+] detected possible deauth attack on " + pkt.addr1)
                mac = pkt.addr2
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
    ch = 1
    os.system("iwconfig " + iface + " channel " + str(ch))
    # switch channel from 1 to 14 each 0.5s
    ch = ch % 14 + 1
    time.sleep(0.5)


def sig_handler(signum, frame):
    print("bye")
    sys.exit()


if __name__ == "__main__":
    interface = input("please enter the name of the interface you want to work with: ")
    monitor_mode(interface)
    time.sleep(1)
    Thread(target=change_channel, args=(interface,)).start()
    print("Beggining scan if you want to stop press ctrl-c")
    time.sleep(2)
    while True:
        signal.signal(signal.SIGINT, sig_handler)

        print("[+] scanning for deauth attacks")
        sniff(iface=interface, stop_filter=handler)
        print("[+] checking for an evil twin access point this will take a minute...")
        sniff(iface=interface, prn=ap_handler, timeout=30)

        for i in stations:
            stations[i] = 0
