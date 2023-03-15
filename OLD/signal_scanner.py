#!/usr/bin/python

import re
import sys
import json
import subprocess as sp
from scapy.all import *
import numpy as np
import matplotlib.pyplot as plt
from scipy.interpolate import griddata
import matplotlib.colors as color


CHANNEL_SCAN_TIMEOUT = 3
CHANNEL_SCAN_COUNT = 5
data = {}
runcount = 1 

def main():
    global runcount

    while True:
       match meny():
           
            case 1:

                if start_monitor() == 0:
                    runcount += 1
                    json_string = json.dumps(data) 

            case 2:
               print(f"\n{json_string}\n")

            case 3:
               pass

            case 4:
                print(" ", end = "")
                break


def meny():
    val = 0

    while True:
        print("\n\n-=-=-=-=-=  AP-SCANNER =-=-=-=-=-=-\n\n1. Start\n2. Print readings \n3. Generate heatmap (hardcoded) \n4. Exit")

        try:
            val = int(input("\nChoice: "))

            if val not in range(1, 5):
                raise ValueError
            
            else:
                break

        except ValueError:
            print("\nEnter a number between 1-4")
            continue

    return val


def start_monitor():
    try:
        mon_name = sys.argv[1] + "mon"

        proc_check = sp.check_output(["airmon-ng", "check"])  # mon check
        proc_killed = re.findall(r"\d+\s+(\S+)", proc_check.decode())[1:]  # proclist, avkoda UTF-8

        if (len(proc_killed) > 0):  # om det finns proccesser från check kill slice "procceses"
            sp.check_output(["airmon-ng", "check", "kill"])
            print(f"\n\nKilled {len(proc_killed)} processes:\n")

            for proc in proc_killed: 
                print(f"\t{proc}")

        start_airmon_attempt = sp.check_output(["airmon-ng", "start", sys.argv[1]]).decode()  # try start mon mode, int exist?
        mon_started = mon_name in start_airmon_attempt
        
        if mon_started:
            print(f"\n\nSuccessfully started Monitor interface {mon_name} \n\n")
            run_scan(mon_name)  # anropa function som förbereder scan
            
        else:
            raise Exception(start_airmon_attempt) 

    except Exception as fail:
        print(f"\nFailed to start Monitor interface: {fail}\n")
        return 1
    
    exit_monitor(proc_killed, mon_name, mon_started)
    return 0


def exit_monitor(proc_killed, mon_name, mon_started):
    if mon_started:
        sp.check_output(["airmon-ng", "stop", mon_name])  # Avslutar monitor mode

    if len(proc_killed) > 0:
        print("\nRestaring processes:\n")  # Startar de tidigare avslutade processerna

        for proc in proc_killed:
            sp.run(["systemctl", "start", proc])
            print(f"\t{proc}") #fail or not?

    print("\n\nRestarting WLAN driver: ", end="")  # Pga driver/kernel bug så startas wlan-drivern om

    try:
        sp.check_output(["modprobe", "-r", "brcmfmac"])
        sp.check_output(["modprobe", "brcmfmac"])
        print("SUCCESS")

    except:
        print("FAILED")
        sys.exit(1)


def run_scan(mon_name):  # Ändrar kanal och anropar sniff funktionen
    print("Fetching Supported channels...\n")

    channel_check = sp.check_output(["iwlist", mon_name, "channel"])  # subproccess.run istället
    supported_channels = re.findall(r"Channel.(\S*) :", channel_check.decode())
    data.update({runcount: {}})

    for channel in supported_channels:
        try:
            sp.check_output(["iwconfig", mon_name, "channel", channel])
            print(f"\nCHANGING CHANNEL TO: {channel}\n")
            sniff(
                iface = mon_name,
                prn = packet_handler,
                filter = "type mgt subtype beacon",
                count = CHANNEL_SCAN_COUNT,
                timeout = CHANNEL_SCAN_TIMEOUT
            )  

        except KeyboardInterrupt:  # hoppar över kanal
            continue


def packet_handler(pkt):  # Anropas för varje paket som skannas
    bssid = pkt.addr2
    ssid = pkt.info.decode()
    signal_strength = pkt.dBm_AntSignal
    channel_info = pkt[Dot11Elt:3].info

    if (len(channel_info) != 1):  # om channelinfo endast består av 1 byte tilldela denna till var
        channel = channel_info[0]
        
    else:
        channel = (int.from_bytes(channel_info[0:2], byteorder="little") & 0x0FFF)  # om fler bytes, FUNKAR INTE

    if ssid not in data[runcount]:
        data[runcount].update(
            {
                ssid: {
                    "bssid": {
                        bssid: {
                            "channel": channel, 
                            "signal_strength": signal_strength
                        }
                    }
                }
            }
        )
        print(f"\tSSID: {ssid}\n\t\tChannel: {channel}\n\t\tSignal Strength: {signal_strength}\n\t\tBSSID: {bssid}\n")

    elif bssid not in data[runcount][ssid]["bssid"]:
        data[runcount][ssid]["bssid"].update(
            {
                bssid: {
                    "channel": channel,
                    "signal_strength": signal_strength
                }
            }
        )


def heatmap(): #tar ej emot data just nu utan använder hardcodad data från tidigare mätning
    
    x = [154,63,161,131,247,196,250,200,261,207,271,211,271,216,272,217,276,223,276,227,245,246,242,240,231,199,278]
    y = [732 - num for num in [573,511,461,510,551,518,495,455,440,411,392,355,336,291,269,236,204,179,147,106,205,265,316,394,460,576,106]]
    signal_strength = [-62, -60, -57, -55, -42, -44, -52, -54, -53, -57, -58, -67, -65, -59, -58, -67, -58, -59, -59, -65, -55, -62, -63, -61, -55, -48, -64]

    # skapa och ändra storlek på grid
    xi = np.linspace(min(x), max(x), 1000)
    yi = np.linspace(min(y), max(y), 1000)

    #sparar minne, pga de nu oanvända variablerna kommer peka på samma minnesarea.
    xi, yi = np.meshgrid(xi, yi)

    #interpolering
    zi = griddata((x, y), signal_strength, (xi,yi), method='cubic')

    #färggränser
    bounds = [-75, -70, -60, -55, -50, -45, -40]
    cmap = color.ListedColormap([
        (255/255, 0/255, 0/255), # röd
        (255/255, 127/255, 0/255), # orange
        (255/255, 255/255, 0/255), # gul
        (128/255, 255/255, 0/255), #ljusgrön
        (0/255, 255/255, 0/255), #grön
        (0/255, 127/255, 0/255),
        (0/255, 63/255, 0/255) # mörk grön
    ])

    norm = plt.Normalize(min(bounds), max(bounds))
    colors = cmap(norm(zi))
    levels = [norm(b) for b in bounds]

    plt.imshow(colors, origin='lower', extent=[min(x), max(x), min(y), max(y)], aspect='auto')
    plt.colorbar()
    plt.xlabel('X')
    plt.ylabel('Y')
    plt.title('Signal Strength Heatmap')

    plt.scatter(x, y, s=20, c='white', edgecolors='black')

    x_range = max(x) - min(x)
    y_range = max(y) - min(y)
    x_pad = 0.1 * x_range
    y_pad = 0.1 * y_range
    plt.xlim([min(x) - x_pad, max(x) + x_pad])
    plt.ylim([min(y) - y_pad, max(y) + y_pad])

    plt.contour(xi, yi, zi, levels=levels, colors='white', linewidths=0.5) 

    plt.show()#funkar bara på windows, och kanske på linux med GUI


if len(sys.argv) == 2:
    if __name__ == "__main__":
        main()
    else:
        start_monitor()
else:
    print(f"\nUsage: python {os.path.basename(__file__)} <interface>.")
    sys.exit(1)

