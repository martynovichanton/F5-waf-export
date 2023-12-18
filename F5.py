import os
import sys
from typing import Type
import paramiko
import time
from getpass import getpass
from datetime import datetime
import requests
import json
from Crypto import Crypto
import time
import gc
from scp import SCPClient, SCPException
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class F5():
    def __init__(self, ip, port, user, password):
        self.session = requests.Session()
        self.crypto = Crypto()
        self.ip = ip
        self.port = port
        self.sleepTimeCommand = 0.2

        self.user = self.crypto.encrypt_random_key(user)
        self.password = self.crypto.encrypt_random_key(password)

        self.headers = ""
        self.token = ""

        ########################################
        ### SSH
        ########################################
        self.ssh_port = 22
        self.client = None
        self.scp = None
        self.sleepTimeBanner = 1
        self.maxIterations = 1000
        self.bufferSize = 10000
        self.printBanner = False
        self.client = None
        self.shell = None
        self.scp = None
        self.stopList = [">", "%", "#", "$"]


    

    ##### API #####
    def runCommand(self, command):
        method = command.split('---')[0]
        #url = "https://" + self.ip + ":" + str(self.port) + command.split('---')[1]
        url = f"https://{self.ip}:{str(self.port)}{command.split('---')[1]}"
        payload = command.split('---')[2]  
        response = self.session.request(method, url, data=payload, headers=json.loads(self.crypto.decrypt_random_key(self.headers)), verify = False)
        return response.json()
        
    def getToken(self, device, user, password):
        url = "https://" + device + "/mgmt/shared/authn/login"
        crypto = Crypto()
        payload = crypto.encrypt_random_key("{\n    \"username\":" + user + ",\n    \"password\":" + password + ",\n    \"loginProviderName\": \"tmos\"\n}")
        headers = {
            'Content-Type': "application/json",
            'cache-control': "no-cache",
            }
        response = self.session.request("POST", url, data=crypto.decrypt_random_key(payload), headers=headers, verify = False)
        if response.status_code != 200:
            return {"Error":response.text}
        token = crypto.encrypt_random_key(response.json()['token']['token'])
        del response
        gc.collect()


        url = "https://" + device + "/mgmt/shared/authz/tokens"
        payload = ""
        headers = crypto.encrypt_random_key(json.dumps({
            'X-F5-Auth-Token': crypto.decrypt_random_key(token),
            'cache-control': "no-cache"
        }))
        response = self.session.request("GET", url, data=payload, headers=json.loads(crypto.decrypt_random_key(headers)), verify = False)
        if response.status_code != 200:
            return {"Error":response.text}
        del response
        gc.collect()


        url = "https://" + device + "/mgmt/shared/authz/tokens/" + crypto.decrypt_random_key(token)
        payload = "{\n    \"timeout\":\"1200\"\n}"
        headers = crypto.encrypt_random_key(json.dumps({
            'Content-Type': "application/json",
            'X-F5-Auth-Token': crypto.decrypt_random_key(token),
            'cache-control': "no-cache"
        }))
        response = self.session.request("PATCH", url, data=payload, headers=json.loads(crypto.decrypt_random_key(headers)), verify = False)
        if response.status_code != 200:
            return {"Error":response.text}
        token = crypto.encrypt_random_key(response.json()['token'])  
        timeout = response.json()['timeout']
        del response
        gc.collect()
        return {"token":crypto.decrypt_random_key(token), "timeout":timeout}

    def getPolicies(self):
        self.token = self.crypto.encrypt_random_key(self.getToken(self.ip, self.crypto.decrypt_random_key(self.user), self.crypto.decrypt_random_key(self.password))['token'])
        self.headers = self.crypto.encrypt_random_key(json.dumps({
            'Content-Type':"application/json",
            'X-F5-Auth-Token':self.crypto.decrypt_random_key(self.token),
            'cache-control':"no-cache"
        }))
        method = "get"
        #url = f"https://{self.ip}:{str(self.port)}/mgmt/tm/asm/policies/"
        url = "/mgmt/tm/asm/policies/"
        payload = ""
        #policiesData = requests.request("get", url, data=payload, headers=json.loads(self.crypto.decrypt_random_key(self.headers)), verify = False).json()
        policiesData = self.runCommand(f"{method}---{url}---{payload}")
        policies = []
        for i in policiesData['items']:
            policies.append({'id' : i['id'], 'name' : i['fullPath']})
        return policies
        
    def savePolicies(self, policies):
        saved_policies = []
        method = "post"
        #url = f"https://{self.ip}:{str(self.port)}/mgmt/tm/asm/tasks/export-policy"
        url = "/mgmt/tm/asm/tasks/export-policy"
        for policy in policies:
            time.sleep(10)
            payload = json.dumps({"filename":policy['name'] + ".xml","policyReference":{"link":"https://localhost/mgmt/tm/asm/policies/" + policy['id']}})
            #r = requests.request("post", url, data=payload, headers=json.loads(self.crypto.decrypt_random_key(self.headers)), verify = False).json()
            r = self.runCommand(f"{method}---{url}---{payload}")
            saved_policies.append(r)
        return saved_policies

    def movePoliciesToImages(self, policies):
        time.sleep(60)
        moved_policies = []
        method = "post"
        url = "/mgmt/tm/util/unix-mv"
        for policy in policies:
            time.sleep(1)
            #file name: user~policyname.xml
            #remove /Partition0X/ from the name
            pname = policy['name'].split("/")[2] + ".xml"

            source = f"/var/ts/var/rest/{self.crypto.decrypt_random_key(self.user)}~{pname}"
            destination = f"/shared/images/{self.crypto.decrypt_random_key(self.user)}~{pname}"

            payload = json.dumps({"command":"run", "utilCmdArgs": f"{source} {destination}"})

            r = self.runCommand(f"{method}---{url}---{payload}")
            moved_policies.append(r)
        return moved_policies
    
    def movePoliciesToRest(self, policies):
        time.sleep(60)
        moved_policies = []
        method = "post"
        url = "/mgmt/tm/util/unix-mv"
        for policy in policies:
            time.sleep(1)
            #file name: user~policyname.xml
            #remove /Partition0X/ from the name
            pname = policy['name'].split("/")[2] + ".xml"

            source = f"/shared/images/{self.crypto.decrypt_random_key(self.user)}~{pname}"
            destination = f"/var/ts/var/rest/{self.crypto.decrypt_random_key(self.user)}~{pname}"
            
            payload = json.dumps({"command":"run", "utilCmdArgs": f"{source} {destination}"})

            r = self.runCommand(f"{method}---{url}---{payload}")
            moved_policies.append(r)
        return moved_policies
        
    def downloadPolicies(self, policies, destDir, device):
        time.sleep(10)
        #file name: user~policyname.xml

        for policy in policies:
            time.sleep(1)
            #remove /Partition0X/ from the name
            pname = policy['name'].split("/")[2] + ".xml"

            self._download(destDir, device, pname)

            #method = "get"
            #downloads only 1024 KB from this location
            #file location on F5 /var/ts/var/rest/
            #url = f"https://{self.ip}:{str(self.port)}/mgmt/tm/asm/file-transfer/downloads/{pname}"
            #payload = ""
            #stream
            #r = self.session.request("get", url, data=payload, headers=json.loads(self.crypto.decrypt_random_key(self.headers)), verify = False, stream = True)
            #with open(f"{destDir}/{device}_{pname}", 'wb') as f:
            #    for chunk in r.iter_content(chunk_size=1024):  
            #        #print(chunk.decode("utf-8"))
            #        f.write(chunk)


        # after the download set headers['Content-Type'] = 'application/json'
        headers=json.loads(self.crypto.decrypt_random_key(self.headers))
        headers['Content-Type'] = 'application/json'
        self.headers = self.crypto.encrypt_random_key(json.dumps(headers))

    def _download(self, destDir, device, pname):
        chunk_size = 512 * 1024

        headers=json.loads(self.crypto.decrypt_random_key(self.headers))
        headers['Content-Type'] = 'application/octet-stream'
        
        filename = f"{self.crypto.decrypt_random_key(self.user)}~{pname}"
        # filename = f"{pname}"

        #download full file by chunks and content-range from this location
        #file location on F5 /shared/images/            
        url = f"https://{self.ip}:{str(self.port)}/mgmt/cm/autodeploy/software-image-downloads/{filename}"

        with open(f"{destDir}/{device}_{pname}", 'wb') as f:
            start = 0
            end = chunk_size - 1
            size = 0
            current_bytes = 0

            while True:
                content_range = f"{start}-{end}/{size}"
                headers['Content-Range'] = content_range
                self.headers = self.crypto.encrypt_random_key(json.dumps(headers))

                payload = ""

                r = self.session.request("get", url, data=payload, headers=json.loads(self.crypto.decrypt_random_key(self.headers)), verify = False, stream = True)
                
                if r.status_code == 400:
                    print("###########################")
                    print("break")
                    print(r.headers)
                    print(r.content.decode("utf-8"))
                    print("###########################")
                    break

                # print("###########################")
                # print(r.headers)
                # print(r.content.decode("utf-8"))
                # print("###########################")

                if r.status_code == 200:
                    # If the size is zero, then this is the first time through the
                    # loop and we don't want to write data because we haven't yet
                    # figured out the total size of the file.
                    if size > 0:
                        current_bytes += chunk_size
                        for chunk in r.iter_content(chunk_size):
                            f.write(chunk)

                    # Once we've downloaded the entire file, we can break out of
                    # the loop
                    if end == size:
                        break

                crange = r.headers['Content-Range']

                # Determine the total number of bytes to read
                if size == 0:
                    size = int(crange.split('/')[-1]) - 1

                    # If the file is smaller than the chunk size, BIG-IP will
                    # return an HTTP 400. So adjust the chunk_size down to the
                    # total file size...
                    if chunk_size > size:
                        end = size

                    # ...and pass on the rest of the code
                    continue

                start += chunk_size

                if (current_bytes + chunk_size) > size:
                    end = size
                else:
                    end = start + chunk_size - 1

    def _upload(self, filename):
        chunk_size = 512 * 1024

        headers=json.loads(self.crypto.decrypt_random_key(self.headers))
        headers['Content-Type'] = 'application/octet-stream'

        fileobj = open(filename, 'rb')


        # if os.path.splitext(filename)[-1] == '.iso':
        #     # file location /shared/images
        #     url = f"https://{self.ip}:{str(self.port)}/mgmt/cm/autodeploy/software-image-downloads/{filename}"
        # else:
        #     # file location /var/config/rest/downloads
        #     url = f"https://{self.ip}:{str(self.port)}/mgmt/shared/file-transfer/uploads/{filename}"


        # file location /var/config/rest/downloads
        url = f"https://{self.ip}:{str(self.port)}/mgmt/shared/file-transfer/uploads/{filename}"

        size = os.path.getsize(filename)

        start = 0

        while True:
            file_slice = fileobj.read(chunk_size)
            if not file_slice:
                break

            current_bytes = len(file_slice)
            if current_bytes < chunk_size:
                end = size
            else:
                end = start + current_bytes

            content_range = f"{start}-{end - 1}/{size}"
            headers['Content-Range'] = content_range
            self.headers = self.crypto.encrypt_random_key(json.dumps(headers))

            r = self.session.request("post", url, data=file_slice, headers=json.loads(self.crypto.decrypt_random_key(self.headers)), verify = False, stream = True)

            # print("###########################")
            # print(r.headers)
            # print(r.content.decode("utf-8"))
            # print("###########################")

            start += current_bytes





    ########################################
    ### SSH
    ########################################

    ##### SSH #####
    def getResponse(self, shell):
        count = 0
        recv_len = 1
        output = ""
        data = bytearray()
        while recv_len:
            time.sleep(self.sleepTimeCommand)
            if shell.recv_ready():
                data = shell.recv(self.bufferSize)
                recv_len = len(data)
                output += data.decode("utf-8")
            #check if stop char is in the last 2 chars of the data received
            if recv_len < self.bufferSize and any(l in data.decode("utf-8")[-2:] for l in self.stopList):
                break
            if count == self.maxIterations:    
                output = "!!!!!!!!!Too many iterations for reading output!!!!!!!!!"
                break
            count += 1
        return output
    
    ##### SSH #####
    def runCommandSsh(self, com):
        self.shell.send(com)
        out = self.getResponse(self.shell)
        return out

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.ip, self.ssh_port, self.crypto.decrypt_random_key(self.user), self.crypto.decrypt_random_key(self.password))
        self.shell = self.client.invoke_shell()

    def printOutput(self, out, file):
        for line in out.splitlines():
            print(line)
            file.write(line + "\n")

    def close(self):
        self.client.close()
        self.shell.close()
		
    def connectScp(self):
        self.scp = SCPClient(self.client.get_transport())

    def downloadFile(self, file, path):
        self.scp.get(file, path)

    def uploadFile(self, file, path):
        self.scp.put(file, path, recursive=True)

    def closeScp(self):
        self.scp.close()

    def downloadPoliciesScp(self, policies, destDir, device):
        for policy in policies:
            time.sleep(10)
            #remove /Partition0X/ from the name
            pname = policy['name'].split("/")[2] + ".xml"
            self.downloadFile(f"/var/ts/var/rest/{self.crypto.decrypt_random_key(self.user)}~{pname}", f"{destDir}/{device}_{pname}")
        



    

