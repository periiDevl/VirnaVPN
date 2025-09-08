import os
import fcntl
import struct
import subprocess
class Device:
    def getFileDesc(self):
        return self.tunFd
    def createTUNInterface(self, tunIP):
        try:
            TUNSETIFF = 0x400454ca
            IFF_TUN = 0x0001
            IFF_NO_PI = 0x1000
            
            self.tunFd = os.open('/dev/net/tun', os.O_RDWR)
            ifr = struct.pack('16sH', b'vpn0', IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self.tunFd, TUNSETIFF, ifr)
            
            subprocess.run(['ip', 'addr', 'add', f'{tunIP}/24', 'dev', 'vpn0'], check=True)
            subprocess.run(['ip', 'link', 'set', 'vpn0', 'up'], check=True)
            
            print(f"TUN interface vpn0 created with IP {tunIP}\n")
            return True
            
        except Exception as e:
            print(f"Failed to create TUN interface: {e}")
            return False
    def delete():
        try:
            subprocess.run(['ip', 'link', 'delete', 'vpn0'], check=False)
        except:
            pass