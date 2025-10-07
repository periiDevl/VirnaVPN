import os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class Encryptions:
    def __init__(self):
        pass
    def AESgenrateKey(self):
        self.AESkey = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.AESkey)
        self.nonce = os.urandom(12)
        self.privateKey = None
        self.publicKey = None
    def AESencrypt(self, bytesText):
        return self.aesgcm.encrypt(self.nonce, bytesText, None)
    def AESdecryptText(self, text):
        return self.aesgcm.decrypt(self.nonce, text, None)
