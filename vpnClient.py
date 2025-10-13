import socket
import threading
import struct
import subprocess
import os
import fcntl
import select
import time
# My stuff:
from Device import *
from Packet import *
from Encryptions import *
class VPNClient:
    def __init__(self, serverIp='xxx.xxx.xxx.xxx', serverPort=1194, clientTunIp='192.168.100.2'):
        self.serverIp = serverIp
        self.serverPort = serverPort
        self.clientTunIp = clientTunIp
        self.server_socket = None
        self.device = Device()
        self.server_address = (serverIp, serverPort)
        self.enc = Encryptions()
        self.packet = Packet(self.serverIp, self.serverPort, self.device, self.enc)
        self.AESkey = None
        
    def createTunDevice(self):
        self.device.createTUNInterface(self.clientTunIp)

    def connect(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.enc.RSAgenrateKeys()
            handshake = b"RSA:" + self.enc.getPublicKeyBytes()
            self.server_socket.sendto(handshake, self.server_address)
            self.packet.setSocket(self.server_socket)
            print(f"Connected to {self.serverIp}:{self.serverPort} via UDP")
            while True:
                data, addr = self.server_socket.recvfrom(4096)
                print("got packet.")
                if (self.AESkey == None):
                        if data.startswith(b"AES:"):
                            _,key, nonce = data.split(b":::",2)
                            self.AESkey = self.enc.RSAdecrypt(key)
                            self.enc.nonce = nonce
                            print("AES packet recived.")
                            print("Setting AES key...")
                            self.enc.setKey(self.AESkey)
                            self.enc.nonce = nonce
                            print(f"Got the AES key from the server. {self.AESkey}")
                            continue
                else:
                    print("Expecting handshake..",flush=True)
                    print(self.enc.AESdecryptText(data))
                    if (self.enc.AESdecryptText(data) == b"AESOK"):
                        print("Handshake complete.", flush=True)
                        return True
                    return False
                    
                return True
        except Exception as e:
            print(e)
            return False

    def writeSeverToTun(self):
        self.packet.writeDataToTun()
    def sendTunToServer(self):
        
        while True:
            try:
                
                # skip unless there is something to read
                ready, nothing, nothing2 = select.select([self.device.getFileDesc()], [], [], 1.0)
                if ready:
                    packet = os.read(self.device.getFileDesc(), 4096)
                    if packet and len(packet) >= 20:
                        try:
                            self.server_socket.sendto(self.enc.AESencrypt(packet), self.server_address)
                            print(f"Forwarded {len(packet)} bytes.")
                        except Exception as send_error:
                            print(send_error)
                            break
                    else:
                        print(f"Invalid packet.")
            except Exception as e:
                print(e)
                break

    def start(self):
        print("Starting VPN Client...")
        
        if not self.connect():
            return
        self.createTunDevice()
            
        try:
            server_thread = threading.Thread(target=self.writeSeverToTun, daemon=True)
            tun_thread = threading.Thread(target=self.sendTunToServer, daemon=True)
            server_thread.start()
            tun_thread.start()
            
            print("Tunnel created!",flush=True)
            print(f"C_TUN IP: {self.clientTunIp}",flush=True)
            
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Client shutting down...")
        except Exception as e:
            print(f"Client error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            if self.device.getFileDesc():
                os.close(self.device.getFileDesc())
            self.device.delete()


