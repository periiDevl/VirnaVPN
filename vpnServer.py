import socket
import threading
import struct
import subprocess
import os
import fcntl
import select
from Device import *


class VPNServer:
    def __init__(self, server_ip='10.0.0.xxx', server_port=1194, tun_ip='192.168.100.1', tun_subnet='192.168.100.0/24'):
        self.server_ip = server_ip
        self.server_port = server_port
        self.tun_ip = tun_ip
        self.tun_subnet = tun_subnet
        self.clients = {}
        self.device = Device()
    def create_tun_interface(self):
        try:  
            self.device.createTUNInterface(self.tun_ip)
            subprocess.run(['sysctl', 'net.ipv4.ip_forward=1'], check=True)
            
            print(f"TUN interface vpn0 created with IP {self.tun_ip}")
            return True
            
        except Exception as e:
            print(f"Failed to create TUN interface: {e}")
            return False
    
    def handle_client(self, client_socket, client_address):
        print(f"Client connected from {client_address}")
        client_id = f"{client_address[0]}:{client_address[1]}"
        self.clients[client_id] = client_socket
        
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                if len(data) >= 20:
                    try:
                        os.write(self.device.getFileDesc(), data)
                        print(f"Forwarded {len(data)} bytes from client to TUN")
                    except OSError as e:
                        if e.errno == 22:
                            print(f"Skipping invalid packet: {len(data)} bytes")
                        else:
                            raise
                else:
                    print(f"Skipping short packet: {len(data)} bytes")
                
        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
            client_socket.close()
            print(f"Client {client_address} disconnected")
    
    def tun_to_clients(self):
        while True:
            try:
                ready, nothing1, nothing2 = select.select([self.device.getFileDesc()], [], [], 1.0)
                if ready:
                    packet = os.read(self.device.getFileDesc(), 4096)
                    if packet:
                        for client_id, client_socket in list(self.clients.items()):
                            try:
                                client_socket.send(packet)
                                print(f"Forwarded {len(packet)} bytes from TUN to client")
                            except Exception as e:
                                print(f"Failed to send to client {client_id}: {e}")
                                client_socket.close()
                                if client_id in self.clients:
                                    del self.clients[client_id]
                                    
            except Exception as e:
                print(f"Error in TUN forwarding: {e}")
                break
    
    def start_server(self):
        print("Starting VPN Server...")

        if not self.create_tun_interface():
            return

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.server_ip, self.server_port))
            server_socket.listen(5)
            print(f"VPN Server listening on {self.server_ip}:{self.server_port}")
            
            tun_thread = threading.Thread(target=self.tun_to_clients, daemon=True)
            tun_thread.start()
            
            while True:
                client_socket, client_address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
        except KeyboardInterrupt:
            print("Server shutting down...")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            server_socket.close()
            if self.device.getFileDesc():
                os.close(self.device.getFileDesc())
            self.device.delete()

if __name__ == "__main__":
    server = VPNServer()
    server.start_server()