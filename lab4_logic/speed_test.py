import time
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from rsa_cipher import RSAFileManager
from lab3_logic.rc5 import FileManagerRC5 

def create_dummy_file(filename, size_mb=1):
    """Створює тестовий файл заданого розміру"""
    print(f"Створення тестового файлу {size_mb} MB...")
    with open(filename, "wb") as f:
        f.write(os.urandom(size_mb * 1024 * 1024))

def main():
    test_file = "speed_test_data.bin"
    rc5_enc_file = "rc5_enc.bin"
    rsa_enc_file = "rsa_enc.bin"
    passphrase = "SpeedTestPassword123"
    
    create_dummy_file(test_file, size_mb=10)
    
    print("\n--- Тестування RC5 ---")
    start_time = time.time()
    FileManagerRC5.encrypt_file(test_file, rc5_enc_file, passphrase)
    rc5_time = time.time() - start_time
    print(f"Час шифрування RC5 (1 MB): {rc5_time:.4f} секунд")

    print("\n--- Тестування RSA ---")
    rsa_manager = RSAFileManager()
    rsa_manager.generate_and_save_keys("priv.pem", "pub.pem")
    
    start_time = time.time()
    rsa_manager.encrypt_file(test_file, rsa_enc_file, "pub.pem")
    rsa_time = time.time() - start_time
    print(f"Час шифрування RSA (1 MB): {rsa_time:.4f} секунд")

    print("\n=================================")
    print(f"RSA повільніший за RC5 у {rsa_time / rc5_time:.1f} разів!")
    print("=================================")

if __name__ == "__main__":
    main()