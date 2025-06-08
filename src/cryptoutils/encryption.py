from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

class CryptoManager:
    def __init__(self):
        self.aes_key = None
        self.rsa_key = None
        self.public_key = None
        self.private_key = None

    def generate_rsa_keys(self):
        """Generate RSA key pair"""
        self.rsa_key = RSA.generate(2048)
        self.private_key = self.rsa_key
        self.public_key = self.rsa_key.publickey()

    def generate_aes_key(self):
        """Generate AES key"""
        self.aes_key = get_random_bytes(32)  

    def encrypt_aes_key(self, recipient_public_key):
        """Encrypt AES key with recipient public key"""
        if isinstance(recipient_public_key, bytes):
            recipient_key = RSA.import_key(recipient_public_key)
        else:
            recipient_key = recipient_public_key
        cipher = PKCS1_OAEP.new(recipient_key)
        return cipher.encrypt(self.aes_key)

    def decrypt_aes_key(self, encrypted_aes_key):
        """Decrypt AES key with private key"""
        cipher = PKCS1_OAEP.new(self.private_key)
        self.aes_key = cipher.decrypt(encrypted_aes_key)
        return self.aes_key

    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data with AES"""
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return cipher.iv + ct_bytes

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data with AES"""
        iv = encrypted_data[:16]
        ct = encrypted_data[16:]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt

    @staticmethod
    def calculate_checksum(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def verify_checksum(data: bytes, checksum: bytes) -> bool:
        return hashlib.sha256(data).digest() == checksum
