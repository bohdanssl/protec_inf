import unittest
import os
import hashlib

from lab2_logic.md5 import MD5Hasher

class TestMD5Algorithm(unittest.TestCase):
    
    def setUp(self):
        self.hasher = MD5Hasher()



    def test_rfc1321_vectors(self):

        test_cases = {
            "": "D41D8CD98F00B204E9800998ECF8427E",
            "a": "0CC175B9C0F1B6A831C399E269772661",
            "abc": "900150983CD24FB0D6963F7D28E17F72",
            "message digest": "F96B697D7CB7938D525A2F31AAF161D0",
            "abcdefghijklmnopqrstuvwxyz": "C3FCD3D76192E4007DFB496CCA67E13B",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "D174AB98D277D9F5A5611C2C9F419D9F",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890": "57EDF4A22BE3C955AC49DA2E2107B67A"
        }

        for text, expected_hash in test_cases.items():
            result = self.hasher.compute_hash(text)
            self.assertEqual(result, expected_hash, f"Помилка на тексті: '{text}'")

    def test_hash_length_and_format(self):

        test_strings = [
            "", 
            "cat", 
            "ЛОІВЛФІВОЛТАОЛВТАЛОІВАДОИВАОДРВІДАРШІВРАЛВІАОІРВАДОЛРІВАОЛДРДВІАРІЛВА" * 100
        ]

        for text in test_strings:
            result = self.hasher.compute_hash(text)
            
            self.assertEqual(
                len(result), 32, 
                f"Помилка довжини! Вийшло {len(result)} символів замість 32."
            )
            
            
            try:
                int(result, 16)
            except ValueError:
                self.fail(f"Хеш містить недопустимі символи (не hex-формат): {result}")

if __name__ == '__main__':
    unittest.main()