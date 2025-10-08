from Device import *
class Packet:
    def __init__(self, serverip, severport,device):
        self.device = device
        self.serverip = serverip
        self.severport = severport
        self.serverAdrr = (serverip, severport)
    def getAESkey(self):
        return self.AESkey
    def setSocket(self,socket):
        self.socket = socket
    def writeDataToTun(self):
        while True:
            try:
                data, addr = self.socket.recvfrom(4096)
                if (addr != self.serverAdrr):
                    continue
                if not data:
                    print("Connection closed with the server.")
                if data == b"VIRNA_CONNECT":
                    continue


                os.write(self.device.getFileDesc(),data)
                print(f"Wrote {len(data)} bytes to the OS Tun", flush=True)

            except Exception as e:
                print(f"Error! : {e}")
                break
