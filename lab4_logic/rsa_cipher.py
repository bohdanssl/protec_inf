from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import time

class RSAFileManager:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.max_plain_chunk = (key_size // 8) - 42
        self.cipher_chunk = key_size // 8

    def generate_and_save_keys(self, private_file="private.pem", public_file="public.pem"):
        print("Генерування ключів RSA (це може зайняти кілька секунд)...")
        key = RSA.generate(self.key_size)
        
        with open(private_file, "wb") as priv_file:
            priv_file.write(key.export_key())
            
        with open(public_file, "wb") as pub_file:
            pub_file.write(key.publickey().export_key())
            
        print(f"Ключі збережено у {private_file} та {public_file}")

    def encrypt_file(self, input_file, output_file, public_key_file):
        with open(public_key_file, "rb") as k_file:
            public_key = RSA.import_key(k_file.read())
            
        cipher_rsa = PKCS1_OAEP.new(public_key)

        with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
            while True:
                chunk = f_in.read(self.max_plain_chunk)
                if not chunk:
                    break
                encrypted_chunk = cipher_rsa.encrypt(chunk)
                f_out.write(encrypted_chunk)

    def decrypt_file(self, input_file, output_file, private_key_file):
        with open(private_key_file, "rb") as k_file:
            private_key = RSA.import_key(k_file.read())
            
        cipher_rsa = PKCS1_OAEP.new(private_key)

        with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
            while True:
                chunk = f_in.read(self.cipher_chunk)
                if not chunk:
                    break
                decrypted_chunk = cipher_rsa.decrypt(chunk)
                f_out.write(decrypted_chunk)