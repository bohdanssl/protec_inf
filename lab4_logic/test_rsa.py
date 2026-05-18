#coverage.py прогнати %

import unittest
import os
import tempfile
from rsa_cipher import RSAFileManager  

class TestRSAFileManager(unittest.TestCase):
    def setUp(self):
        
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pub_key = os.path.join(self.temp_dir.name, "public.pem")
        self.priv_key = os.path.join(self.temp_dir.name, "private.pem")
        self.input_file = os.path.join(self.temp_dir.name, "input.txt")
        self.enc_file = os.path.join(self.temp_dir.name, "enc.bin")
        self.dec_file = os.path.join(self.temp_dir.name, "dec.txt")
        
        self.rsa = RSAFileManager(key_size=1024)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_init_calculations(self):
      
        self.assertEqual(self.rsa.key_size, 1024)
        self.assertEqual(self.rsa.max_plain_chunk, 86)
        self.assertEqual(self.rsa.cipher_chunk, 128)

    def test_generate_and_save_keys(self):
        self.rsa.generate_and_save_keys(self.priv_key, self.pub_key)
        
        self.assertTrue(os.path.exists(self.priv_key))
        self.assertTrue(os.path.exists(self.pub_key))
        
        with open(self.pub_key, 'rb') as f:
            content = f.read()
            self.assertIn(b"PUBLIC KEY", content)

    def test_encrypt_decrypt_flow(self):
        self.rsa.generate_and_save_keys(self.priv_key, self.pub_key)
        
        original_data = b"Hello, RSA testing! " * 50  
        with open(self.input_file, "wb") as f:
            f.write(original_data)
            
        self.rsa.encrypt_file(self.input_file, self.enc_file, self.pub_key)
        self.assertTrue(os.path.exists(self.enc_file))
        
        with open(self.enc_file, "rb") as f:
            encrypted_data = f.read()
        self.assertNotEqual(original_data, encrypted_data)
        
        self.rsa.decrypt_file(self.enc_file, self.dec_file, self.priv_key)
        self.assertTrue(os.path.exists(self.dec_file))
        
        with open(self.dec_file, "rb") as f:
            decrypted_data = f.read()
            
        self.assertEqual(original_data, decrypted_data)

if __name__ == '__main__':
    unittest.main()