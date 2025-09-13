import socket
import threading
import struct
import subprocess
import os
import fcntl
import select
from Device import *


class VPNServer:
    def __init__(self, server_ip='xxx.xxx.xxx.xxx', server_port=1194, tun_ip='192.168.100.1', tun_subnet='192.168.100.0/24'):
        self.server_ip = server_ip
        self.server_port = server_port
        self.tun_ip = tun_ip
        self.tun_subnet = tun_subnet
        self.clients = {}
        self.device = Device()
        self.server_socket = None
    
    def createTun(self):
        self.device.createTUNInterface(self.tun_ip)
        subprocess.run(['sysctl', 'net.ipv4.ip_forward=1'], check=True)
            
        print(f"TUN interface vpn0 created with IP {self.tun_ip}")
    
    def handleClient(self):
        while True:
            try:
                data, client_address = self.server_socket.recvfrom(4096)
                if not data:
                    continue
                
                client_id = f"{client_address[0]}:{client_address[1]}"
                self.clients[client_id] = client_address
                
                if len(data) >= 20:
                    try:
                        os.write(self.device.getFileDesc(), data)
                        print(f"Forwarded {len(data)} bytes from client {client_address} to TUN")
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
                        for client_id, client_address in list(self.clients.items()):
                            try:
                                self.server_socket.sendto(packet, client_address)
                                print(f"Forwarded {len(packet)} bytes from TUN to client {client_address}")
                            except Exception as e:
                                print(f"Failed to send to client {client_id}: {e}")
                                if client_id in self.clients:
                                    del self.clients[client_id]
                                    
            except Exception as e:
                print(f"Error in TUN forwarding: {e}")
                break
    
    def start(self):
        print("Starting VPN Server...")

        self.createTun()
        

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket = server_socket
        
        try:
            server_socket.bind((self.server_ip, self.server_port))
            print(f"VPN Server listening on {self.server_ip}:{self.server_port}")
            
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


