import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

class DSSManager:
    def __init__(self, key_size=2048):
        self.key_size = key_size

    def generate_and_save_keys(self, private_file, public_file):
        private_key = dsa.generate_private_key(key_size=self.key_size)
        public_key = private_key.public_key()

        with open(private_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(public_file, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def load_private_key(self, private_file):
        with open(private_file, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def load_public_key(self, public_file):
        with open(public_file, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def sign_data(self, data: bytes, private_file: str) -> str:
        private_key = self.load_private_key(private_file)
        signature = private_key.sign(data, hashes.SHA256())
        return signature.hex()

    def verify_data(self, data: bytes, signature_hex: str, public_file: str) -> bool:
        public_key = self.load_public_key(public_file)
        try:
            signature_bytes = bytes.fromhex(signature_hex.strip())
            public_key.verify(signature_bytes, data, hashes.SHA256())
            return True
        except (InvalidSignature, ValueError):
            return False
            
    def sign_file(self, filepath: str, private_file: str) -> str:
        with open(filepath, "rb") as f:
            return self.sign_data(f.read(), private_file)
            
    def verify_file(self, filepath: str, signature_hex: str, public_file: str) -> bool:
        with open(filepath, "rb") as f:
            return self.verify_data(f.read(), signature_hex, public_file)