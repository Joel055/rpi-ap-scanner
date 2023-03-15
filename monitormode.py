# Specifically made for Kali Linux on Raspberry Pi 4b
import re
import sys
import subprocess as sp

def start(interface):
    try:
        mon_name = interface + "mon"

        proc_check = sp.check_output(["airmon-ng", "check"])  # mon check
        proc_killed = re.findall(r"\d+\s+(\S+)", proc_check.decode())[1:]  # proclist, avkoda UTF-8

        if (len(proc_killed) > 0):  # Om det finns proccesser från check kill slice "procceses"
            sp.check_output(["airmon-ng", "check", "kill"])
            print(f"\n\nKilled {len(proc_killed)} processes:\n")

            for proc in proc_killed: 
                print(f"\t{proc}")

        start_airmon_attempt = sp.check_output(["airmon-ng", "start", interface]).decode()  # Försöker start mon mode, int exist?
        mon_started = mon_name or "already" in start_airmon_attempt
        
        if mon_started:
            print(f"\n\nSuccessfully started Monitor interface {mon_name} \n\n")
            return {"status": 0, "proc_killed": proc_killed, "name": mon_name, "started": mon_started}

        else:
            raise Exception(start_airmon_attempt) 

    except Exception as fail:
        print(f"\nFailed to start Monitor interface: {str(fail)}\n")
        return {"status": 1, "proc_killed": proc_killed, "name": mon_name, "started": mon_started}
    

def exit(monitor):
    if monitor["started"]:
        sp.check_output(["airmon-ng", "stop", monitor["name"]])  # Avslutar monitor mode

    if len(monitor["proc_killed"]) > 0:
        print("\nRestaring processes:\n")  # Startar de tidigare avslutade processerna

        for proc in monitor["proc_killed"]:
            sp.run(["systemctl", "start", proc])
            print(f"\t{proc}")

    print("\n\nRestarting WLAN driver: ", end="")  # Pga driver/kernel bug så startas wlan-drivern om

    try:
        sp.check_output(["modprobe", "-r", "brcmfmac"])
        sp.check_output(["modprobe", "brcmfmac"])
        print("SUCCESS")

    except:
        print("FAILED")
        sys.exit(1)
