import socket
import threading
import struct
import subprocess
import os
import fcntl
import select
import time
#My stuff:
from Device import *
class VPNClient:
    def __init__(self, server_ip='10.0.0.xxx', server_port=1194, client_tun_ip='192.168.100.2'):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_tun_ip = client_tun_ip
        self.server_socket = None
        self.device = Device()

    def create_tun_interface(self):
        self.device.createTUNInterface(self.client_tun_ip)
    
    def connect_to_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect((self.server_ip, self.server_port))
            print(f"Connected to VPN server at {self.server_ip}:{self.server_port}")
            return True
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            return False
    
    def server_to_tun(self):
        while True:
            try:
                data = self.server_socket.recv(4096)
                if not data:
                    print("Server connection closed")
                    break
                
                os.write(self.device.getFileDesc(), data)
                print(f"Forwarded {len(data)} bytes from server to TUN")
                
            except Exception as e:
                print(f"Error in server to TUN forwarding: {e}")
                break
    
    def tun_to_server(self):
        while True:
            try:
                #skip unless there is somthing to read
                ready, nothing, nothing2 = select.select([self.device.getFileDesc()], [], [], 1.0)
                if ready:
                    packet = os.read(self.device.getFileDesc(), 4096)
                    if packet and len(packet) >= 20:
                        try:
                            self.server_socket.send(packet)
                            print(f"Forwarded {len(packet)} bytes from TUN to server")
                        except BrokenPipeError:
                            print("Server connection lost")
                            break
                    else:
                        print.debug(f"Skipping invalid packet: {len(packet) if packet else 0} bytes")
                        
            except Exception as e:
                print(f"Error in TUN to server forwarding: {e}")
                break
    
    def start_client(self):
        print("Starting VPN Client...")
        self.create_tun_interface()
        self.connect_to_server()
        try:
            server_thread = threading.Thread(target=self.server_to_tun, daemon=True)
            tun_thread = threading.Thread(target=self.tun_to_server, daemon=True)
            
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

if __name__ == "__main__":
    client = VPNClient()
    client.start_client()
