import unittest
import os
import struct
from lab3_logic.rc5 import RC5, FileManagerRC5  

class TestRC5Simple(unittest.TestCase):
    
    def setUp(self):
        self.passphrase = "MySecretKey"
        self.test_in = "test_input.txt"
        self.test_enc = "test_enc.bin"
        self.test_dec = "test_dec.txt"
        
        with open(self.test_in, "wb") as f:
            f.write(b"Hello RC5! This is a simple test.")

    def tearDown(self):
        for filepath in [self.test_in, self.test_enc, self.test_dec]:
            if os.path.exists(filepath):
                os.remove(filepath)

    def test_block_math(self):
        """1. Тест математики RC5 (один блок туди і назад)"""
        key = b'\x00' * 16  
        rc5 = RC5(key)
        
        original_block = struct.pack('<HH', 123, 456)
        encrypted_block = rc5.encrypt_block(original_block)
        decrypted_block = rc5.decrypt_block(encrypted_block)
        
        self.assertEqual(original_block, decrypted_block)

    def test_full_file_success(self):
        """2. Перевірка успішного шифрування та розшифрування файлу"""
        FileManagerRC5.encrypt_file(self.test_in, self.test_enc, self.passphrase)
        FileManagerRC5.decrypt_file(self.test_enc, self.test_dec, self.passphrase)
        
        with open(self.test_dec, "rb") as f:
            result = f.read()
            
        self.assertEqual(result, b"Hello RC5! This is a simple test.")

    def test_wrong_password(self):
        """3. Перевірка захисту (має виникнути помилка при поганому паролі)"""
        FileManagerRC5.encrypt_file(self.test_in, self.test_enc, self.passphrase)
        

        with self.assertRaises(ValueError):
            FileManagerRC5.decrypt_file(self.test_enc, self.test_dec, "WrongPassword")

if __name__ == '__main__':
    unittest.main()