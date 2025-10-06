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

class VPNClient:
    def __init__(self, server_ip='xxx.xxx.xxx.xxx', server_port=1194, client_tun_ip='192.168.100.2'):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_tun_ip = client_tun_ip
        self.server_socket = None
        self.device = Device()
        self.server_address = (server_ip, server_port)
        self.packet = Packet(self.server_ip, self.server_port, self.device)
    def createTunDevice(self):
        self.device.createTUNInterface(self.client_tun_ip)

    def connect(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            handshake = b"VIRNA_CONNECT"
            self.server_socket.sendto(handshake, self.server_address)
            self.packet.setSocket(self.server_socket)
            print(f"Connected to {self.server_ip}:{self.server_port} via UDP")
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
                            self.server_socket.sendto(packet, self.server_address)
                            print(f"Forwarded{len(packet)}.")
                        except Exception as send_error:
                            print(send_error)
                            break
                    else:
                        print(f"Invalid packet: {len(packet) if packet else 0} bytes")
            except Exception as e:
                print(e)
                break

    def start(self):
        print("Starting VPN Client...")
        self.createTunDevice()
        
        if not self.connect():
            return
            
        try:
            server_thread = threading.Thread(target=self.writeSeverToTun, daemon=True)
            tun_thread = threading.Thread(target=self.sendTunToServer, daemon=True)
            server_thread.start()
            tun_thread.start()
            
            print("Tunnel created!")
            print(f"C_TUN IP: {self.client_tun_ip}")
            
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


