import socket
import threading
import struct
import subprocess
import os
import fcntl
import select
from Device import *
from Encryptions import *

class VPNServer:
    def __init__(self, serverIp='xxx.xxx.xxx.xxx', serverPort=1194, tunIp='192.168.100.1', tunSubnet='192.168.100.0/24'):
        self.serverIp = serverIp
        self.serverPort = serverPort
        self.tunIp = tunIp
        self.tunSubnet = tunSubnet
        self.clients = {}
        self.device = Device()
        self.server_socket = None
        self.clientsenc = Encryptions() #right now there is a vunrability where the key is the same for all users it will be fixed.
        self.enc = Encryptions()
        self.enc.AESgenrateKey()
    def createTun(self):
        self.device.createTUNInterface(self.tunIp)
        subprocess.run(['sysctl', 'net.ipv4.ip_forward=1'], check=True)
            
        print(f"TUN interface vpn0 created with IP {self.tunIp}")
    
    def handleClient(self):

        strinnn = b"AES:" + self.enc.AESkey + b":" + self.enc.nonce

        while True:
            try:
                data, clientAddress = self.server_socket.recvfrom(4096)
                if not data:
                    continue
                
                clientID = f"{clientAddress[0]}:{clientAddress[1]}"
                self.clients[clientID] = clientAddress
                try:
                    self.server_socket.sendto(strinnn, clientAddress)
                    print("Send AES key.",flush=True)
                    self.server_socket.sendto(self.enc.AESencrypt(b"AESOK"), clientAddress)
                    print("Sent handshake.")
                except:
                    print("Error..")
                if len(data) >= 20:
                    try:
                        os.write(self.device.getFileDesc(), data)
                        print(f"Forwarded {len(data)} bytes from client {clientAddress} to TUN")
                    except OSError as e:
                        if e.errno == 22:
                            print(f"Invalid packet: {len(data)} bytes")
                        else:
                            raise
                else:
                    print(f"Short packet: {len(data)} bytes")
                    
            except Exception as e:
                print(e)
    
    def tunToClients(self):
        

        while True:
            try:
                ready, nothing1, nothing2 = select.select([self.device.getFileDesc()], [], [], 1.0)
                if ready:
                    packet = os.read(self.device.getFileDesc(), 4096)
                    if packet:
                        for clientID, clientAddress in list(self.clients.items()):
                            try:
                                #First encrpyt text
                                self.server_socket.sendto(self.enc.AESencrypt(packet), clientAddress)
                                print(f"Forwarded {len(packet)} bytes from TUN to client {clientAddress}")
                                
                            except Exception as e:
                                print(f"Failed to send to client {clientID}: {e}")
                                if clientID in self.clients:
                                    del self.clients[clientID]
                                    
            except Exception as e:
                print(f"Error in TUN forwarding: {e}")
                break
    
    def start(self):
        print("Starting VPN Server...")

        self.createTun()
        

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket = server_socket
        
        try:
            server_socket.bind((self.serverIp, self.serverPort))
            print(f"VPN Server listening on {self.serverIp}:{self.serverPort}")
            
            tun_thread = threading.Thread(target=self.tunToClients, daemon=True)
            tun_thread.start()
            
            client_thread = threading.Thread(target=self.handleClient, daemon=True)
            client_thread.start()

            while True:
                import time
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("Server shutting down...")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            if self.device.getFileDesc():
                os.close(self.device.getFileDesc())
            self.device.delete()


