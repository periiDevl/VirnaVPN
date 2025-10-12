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
    def setKey(self, key):
        self.AESkey = key;
        self.aesgcm = AESGCM(self.AESkey)
    def AESencrypt(self, bytesText):
        return self.aesgcm.encrypt(self.nonce, bytesText, None)
    def AESdecryptText(self, text):
        return self.aesgcm.decrypt(self.nonce, text, None)
    def RSAgenrateKeys(self, key_size=2048):
        self.privateKey = None
        self.publicKey = None
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()
    def RSAencrypt(self, plaintext):
        return self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    def RSAdecrypt(self, ciphertext):
        if not self.private_key:
            raise ValueError("Private key not set!")
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def getPublicKeyBytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
