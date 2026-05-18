import struct
import math
import os

class MD5Hasher:
    def __init__(self):
        self._init_state()
        self.K = [int(abs(math.sin(i + 1)) * (2**32)) & 0xFFFFFFFF for i in range(64)]
        self.s = [
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        ]

    def _init_state(self):
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476

    @staticmethod
    def _F(x, y, z): return (x & y) | (~x & z)
    @staticmethod
    def _G(x, y, z): return (x & z) | (y & ~z)
    @staticmethod
    def _H(x, y, z): return x ^ y ^ z
    @staticmethod
    def _I(x, y, z): return y ^ (x | ~z)
    @staticmethod
    def _left_rotate(x, amount):
        x &= 0xFFFFFFFF
        return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

    def _process_chunk(self, chunk):
        M = list(struct.unpack('<16I', chunk))
        A, B, C, D = self.A, self.B, self.C, self.D

        for j in range(64):
            if 0 <= j <= 15:
                F = self._F(B, C, D)
                g = j
            elif 16 <= j <= 31:
                F = self._G(B, C, D)
                g = (5 * j + 1) % 16
            elif 32 <= j <= 47:
                F = self._H(B, C, D)
                g = (3 * j + 5) % 16
            elif 48 <= j <= 63:
                F = self._I(B, C, D)
                g = (7 * j) % 16

            to_rotate = A + F + self.K[j] + M[g]
            new_B = (B + self._left_rotate(to_rotate, self.s[j])) & 0xFFFFFFFF
            A, B, C, D = D, new_B, B, C

        self.A = (self.A + A) & 0xFFFFFFFF
        self.B = (self.B + B) & 0xFFFFFFFF
        self.C = (self.C + C) & 0xFFFFFFFF
        self.D = (self.D + D) & 0xFFFFFFFF

    def compute_hash(self, message: str) -> str:
        self._init_state()
        msg_bytes = bytearray(message.encode('utf-8'))
        original_bit_len = len(msg_bytes) * 8
        
        msg_bytes.append(0x80)
        while len(msg_bytes) % 64 != 56:
            msg_bytes.append(0x00)
        msg_bytes += struct.pack('<Q', original_bit_len)

        for i in range(0, len(msg_bytes), 64):
            self._process_chunk(msg_bytes[i:i+64])

        return struct.pack('<4I', self.A, self.B, self.C, self.D).hex().upper()

    def compute_file_hash(self, filepath: str) -> str:

        self._init_state()
        file_size_bytes = 0

        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(64)
                
                if len(chunk) < 64:
                    file_size_bytes += len(chunk)
                    msg_bytes = bytearray(chunk) 
                    break
                    
                file_size_bytes += 64
                self._process_chunk(chunk) 

        original_bit_len = file_size_bytes * 8
        msg_bytes.append(0x80)
        while len(msg_bytes) % 64 != 56:
            msg_bytes.append(0x00)
        msg_bytes += struct.pack('<Q', original_bit_len)

        for i in range(0, len(msg_bytes), 64):
            self._process_chunk(msg_bytes[i:i+64])

        return struct.pack('<4I', self.A, self.B, self.C, self.D).hex().upper()