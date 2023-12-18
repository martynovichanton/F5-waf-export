import os
import sys
import paramiko
import time
from getpass import getpass
from datetime import datetime
import requests
import json
from Crypto import Crypto
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from F5 import F5


def iterate():
    mainDir = sys.argv[1]
    print(f"[*] {mainDir}")
    mainCrypto = Crypto()
    port = 443
    
    user = mainCrypto.encrypt_random_key(getpass("Enter user"))
    passw = mainCrypto.encrypt_random_key(getpass("Enter password"))

    now = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    outputDir = "output" + "-" + now
    if not os.path.exists(f"{mainDir}/{outputDir}"):
        os.mkdir(f"{mainDir}/{outputDir}")
    
    logFile = open(f"{mainDir}/{outputDir}/log.txt", "w")
    logFile.write(f"[*] {mainDir}" + "\n")

    for dir in os.listdir(f"{mainDir}/api"):
        print(f"[*] {dir}")
        logFile.write(f"[*] {dir}" + "\n")
        
        devicesFile = open(f"{mainDir}/api/{dir}/devices.txt", 'r')
        devices = devicesFile.read().splitlines()
        devicesFile.close()

        print(f"[*] Devices: {devices}")
        logFile.write(f"[*] Devices: {devices}" + "\n")


        if dir == 'f5' or dir == 'f501' or dir == 'f502':  
            username = user
            password = passw
            

        for device in devices:
            outFilePerDevice = open(f"{mainDir}/{outputDir}/{device}.txt", "w")
            print (f"[*] {device}")
            logFile.write(f"[*] {device}" + "\n")
            
            if dir == "f5":
                # export policies -> /var/ts/var/rest
                # move policies to /shared/images
                # download policies by chunks and content-range from this location
                # move policies to /var/ts/var/rest

                api = F5(device, port, mainCrypto.decrypt_random_key(username), mainCrypto.decrypt_random_key(password))
                policies = api.getPolicies()
                print(f"[*] {policies}")
                logFile.write(f"[*] {policies}" + "\n")

                saved_policies = api.savePolicies(policies)
                print(f"[*] {json.dumps(saved_policies, indent=4, sort_keys=False)}")
                outFilePerDevice.write(f"[*] {json.dumps(saved_policies, indent=4, sort_keys=False)}" + "\n")

                moved_policies = api.movePoliciesToImages(policies)
                print(f"[*] {json.dumps(moved_policies, indent=4, sort_keys=False)}")
                outFilePerDevice.write(f"[*] {json.dumps(moved_policies, indent=4, sort_keys=False)}" + "\n")

                ##### download via rest
                api.downloadPolicies(policies, f"{mainDir}/{outputDir}", device)

                moved_policies = api.movePoliciesToRest(policies)
                print(f"[*] {json.dumps(moved_policies, indent=4, sort_keys=False)}")
                outFilePerDevice.write(f"[*] {json.dumps(moved_policies, indent=4, sort_keys=False)}" + "\n")


                
                
                # #### download via SCP ##### 
                # api.connect()
                # api.connectScp()
                # output = api.getResponse(api.shell)
                # if api.printBanner:
                #     api.printOutput(output, outFilePerDevice)        
                #
                # prompt = api.runCommandSsh("\n")    
                # print(prompt)
                # outFilePerDevice.write(prompt + "\n") 
                #
                # api.downloadPoliciesScp(policies, f"{mainDir}/{outputDir}", device)
                # api.close()

            outFilePerDevice.close()  
            
    print("\n[*] DONE!\n")
    logFile.write("\n[*] DONE!\n")
    logFile.close()

def main():
    if len(sys.argv) == 2:
        iterate()
    else:
        print("Run api_multi.py <folder name>")

if __name__ == "__main__":
    main()