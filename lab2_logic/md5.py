import struct
import math
import os

class MD5Hasher:
    def __init__(self):
        self._init_state()
        self.k = [int(abs(math.sin(i + 1)) * (2**32)) & 0xFFFFFFFF for i in range(64)]
        self.s = [
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        ]

    def _init_state(self):
        self.a = 0x67452301
        self.b = 0xEFCDAB89
        self.c = 0x98BADCFE
        self.d = 0x10325476

    @staticmethod
    def _f(x, y, z): return (x & y) | (~x & z)
    
    @staticmethod
    def _g(x, y, z): return (x & z) | (y & ~z)
    
    @staticmethod
    def _h(x, y, z): return x ^ y ^ z
    
    @staticmethod
    def _i(x, y, z): return y ^ (x | ~z)
    
    @staticmethod
    def _left_rotate(x, amount):
        x &= 0xFFFFFFFF
        return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

    def _process_chunk(self, chunk):
        m = list(struct.unpack('<16I', chunk))
        a, b, c, d = self.a, self.b, self.c, self.d

        for j in range(64):
            if 0 <= j <= 15:
                f_val = self._f(b, c, d)
                g = j
            elif 16 <= j <= 31:
                f_val = self._g(b, c, d)
                g = (5 * j + 1) % 16
            elif 32 <= j <= 47:
                f_val = self._h(b, c, d)
                g = (3 * j + 5) % 16
            elif 48 <= j <= 63:
                f_val = self._i(b, c, d)
                g = (7 * j) % 16

            to_rotate = a + f_val + self.k[j] + m[g]
            new_b = (b + self._left_rotate(to_rotate, self.s[j])) & 0xFFFFFFFF
            a, b, c, d = d, new_b, b, c

        self.a = (self.a + a) & 0xFFFFFFFF
        self.b = (self.b + b) & 0xFFFFFFFF
        self.c = (self.c + c) & 0xFFFFFFFF
        self.d = (self.d + d) & 0xFFFFFFFF

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

        return struct.pack('<4I', self.a, self.b, self.c, self.d).hex().upper()

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

        return struct.pack('<4I', self.a, self.b, self.c, self.d).hex().upper()