import os
import fcntl
import struct
import subprocess

class Device:
    def __init__(self):
        self.isTap = False
        self.tunFd = None

    def getFileDesc(self):
        return self.tunFd

    def useTAP(self):
        self.isTap = True

    def createInterface(self, tunIP):
        try:
            TUNSETIFF = 0x400454ca
            IFF_TUN = 0x0001
            IFF_TAP = 0x0002
            IFF_NO_PI = 0x1000

            self.tunFd = os.open('/dev/net/tun', os.O_RDWR)

            mode = IFF_TAP if self.isTap else IFF_TUN
            ifr = struct.pack('16sH', b'vpn0', mode | IFF_NO_PI)

            fcntl.ioctl(self.tunFd, TUNSETIFF, ifr)

            subprocess.run(['ip', 'addr', 'add', f'{tunIP}/24', 'dev', 'vpn0'], check=True)
            subprocess.run(['ip', 'link', 'set', 'vpn0', 'up'], check=True)

            mode_name = "TAP" if self.isTap else "TUN"
            print(f"{mode_name} interface vpn0 created with IP {tunIP}\n")
            return True

        except Exception as e:
            print(f"Failed to create interface: {e}")
            return False

    def delete(self):
        try:
            subprocess.run(['ip', 'link', 'delete', 'vpn0'], check=False)
            print("Interface vpn0 deleted.")
        except Exception:
            pass
