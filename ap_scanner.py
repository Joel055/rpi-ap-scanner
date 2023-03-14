#!/usr/bin/python

import sys
import json
import heatmap
import monitormode as mon
import datetime as dt
import subprocess as sp
from scapy.all import *


CHANNEL_SCAN_TIMEOUT = 3 # antal sekunder som väntas på paket i scan
CHANNEL_SCAN_COUNT = 20 # max antal paket för varje scan
data = {}
runcount = 0

def main():
    
    while True:
       match meny():
           
            case 1:
                monitor = mon.start(sys.argv[1]) # Startar monitor mode och tilldelar körinfo till variabel

                if monitor["status"] == 0:
                    try:
                        timestamp = dt.datetime.now()

                        run_scan(monitor["name"])  # Anropa function som förbereder/startar scan
                        create_json(timestamp)
                        
                    except Exception as fail:
                        print(f"Error:\n{str(fail)}")
                        create_json(timestamp)

                mon.exit(monitor) # Avsutar monitormode efter körningarna är klara

            case 2:
                if runcount != 0:
                    print(f"\n{json.dumps(data)}")
                else:
                    print("No data.\n")

            case 3:
               if runcount != 0:
                    extract_best_sig()

            case 4:
               heatmap.generate() # Hårdkodad mätdata

            case 5:
                print(" ", end = "")
                break


def meny():
    val = 0

    while True:
        print(f"\n\n-=-=-=-=-=  AP-SCANNER =-=-=-=-=-=-\n\n1. Start\n2. Print readings ({runcount}) \n3.Get highest signalstrenghts \n4. Generate heatmap (hardcoded) \n5. Exit")

        try:
            val = int(input("\nChoice: "))

            if val not in range(1, 5):
                raise ValueError
            
            else:
                break

        except ValueError:
            print("\nEnter a number between 1-4")

    return val


def run_scan(mon_name):  # Ändrar kanal och anropar sniff funktionen
    global runcount

    print("Fetching Supported channels...")

    channel_check = sp.check_output(["iwlist", mon_name, "channel"])
    supported_channels = re.findall(r"Channel.(\S*) :", channel_check.decode())
    
    while True:
        runcount += 1
        data.update({runcount: {}})
        print(f"\n\nSCAN {runcount}:")
        
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

        while True:
            scan_again = input("\nRun another scan (Y/N): ").lower()

            try:
                if scan_again == "y":
                    break

                elif scan_again == "n":
                    return

                else:
                    raise ValueError

            except ValueError:
                print("Invalid input\n")
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


def extract_best_sig(): # Extraherar bästa dBm värdet från 2.4 och 5GHz kanalerna för varje mätning
    ssid = input("\nEnter SSID: ")

    lowest2 = [] #2.4 GHz
    lowest5 = [] #5 GHz

    for i in data:
        all5 = []
        all2 = []

        if ssid in data[i]:
            for j in data[i][ssid]["bssid"]:
                if int(data[i][ssid]["bssid"][j]["channel"]) > 14:
                    all5.append(data[i][ssid]["bssid"][j]["signal_strength"])

                else:
                    all2.append(data[i][ssid]["bssid"][j]["signal_strength"])
        else:
            all5.append(None)
            all2.append(None)

        lowest2.append(max(all2))
        lowest5.append(max(all5))
        
    print(f"2.4 GHz: {lowest2}\n5 GHz: {lowest5}")


def create_json(timestamp): # Skapar jsonfil med mätdata och appendar det till en lokal fil
    json_string = json.dumps(data)
    timestamp_formated = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    header = f"\n\n=======================================\n{timestamp_formated}\n\n"

    with open("scanresult.json", "a") as file:
        file.write(header + json_string)
        

if len(sys.argv) == 2:
    if __name__ == "__main__":
        main()
    else:
        mon.start() # borde gå via runscan?
else:
    print(f"\nUsage: python {os.path.basename(__file__)} <interface>.")
    sys.exit(1)
