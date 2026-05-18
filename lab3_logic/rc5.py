import struct
import random
from lab1_logic.logic import LCG
from lab2_logic.md5 import MD5Hasher

class RC5:
    def __init__(self, key: bytes, w=16, r=12, b=16):
        self.w = w
        self.r = r
        self.b = b
        self.u = w // 8
        self.mod = 2 ** w
        self.mask = self.mod - 1

        if w == 16:
            self.P = 0xB7E1
            self.Q = 0x9E37
        else:
            raise ValueError("Ця реалізація налаштована лише для w=16")

        self._key_expansion(key)

    def _rotl(self, val, shift):
        shift %= self.w
        return ((val << shift) & self.mask) | (val >> (self.w - shift))

    def _rotr(self, val, shift):
        shift %= self.w
        return (val >> shift) | ((val << (self.w - shift)) & self.mask)

    def _key_expansion(self, key):
        L = [0] * max(1, (self.b + self.u - 1) // self.u)
        for i in range(self.b - 1, -1, -1):
            L[i // self.u] = (L[i // self.u] << 8) + key[i]

        t = 2 * (self.r + 1)
        self.S = [0] * t
        self.S[0] = self.P
        for i in range(1, t):
            self.S[i] = (self.S[i - 1] + self.Q) % self.mod

        i = j = 0
        A = B = 0
        v = 3 * max(len(L), t)
        for _ in range(v):
            A = self.S[i] = self._rotl((self.S[i] + A + B) % self.mod, 3)
            B = L[j] = self._rotl((L[j] + A + B) % self.mod, (A + B) % self.w)
            i = (i + 1) % t
            j = (j + 1) % len(L)

    def encrypt_block(self, data: bytes) -> bytes:
        A, B = struct.unpack('<HH', data)
        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod
        for i in range(1, self.r + 1):
            A = (self._rotl(A ^ B, B) + self.S[2 * i]) % self.mod
            B = (self._rotl(B ^ A, A) + self.S[2 * i + 1]) % self.mod
        return struct.pack('<HH', A, B)

    def decrypt_block(self, data: bytes) -> bytes:
        A, B = struct.unpack('<HH', data)
        for i in range(self.r, 0, -1):
            B = self._rotr((B - self.S[2 * i + 1]) % self.mod, A) ^ A
            A = self._rotr((A - self.S[2 * i]) % self.mod, B) ^ B
        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod
        return struct.pack('<HH', A, B)

class FileManagerRC5:
    BLOCK_SIZE = 4 

    @staticmethod
    def derive_key(passphrase: str) -> bytes:
        hasher = MD5Hasher()
        md5_hex = hasher.compute_hash(passphrase)
        return bytes.fromhex(md5_hex)

    @staticmethod
    def generate_iv() -> bytes:
        random_seed = random.randint(1, 1000000)
        lcg = LCG(x_0=random_seed)
        seq = lcg.generate(FileManagerRC5.BLOCK_SIZE + 1)
        return bytes(x % 256 for x in seq[:FileManagerRC5.BLOCK_SIZE])

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, passphrase: str):
        key = FileManagerRC5.derive_key(passphrase)
        rc5 = RC5(key, w=16, r=12, b=16)
        
        iv = FileManagerRC5.generate_iv()
        enc_iv = rc5.encrypt_block(iv) 
        
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(enc_iv) 
            prev_block = iv
            
            while True:
                chunk = f_in.read(FileManagerRC5.BLOCK_SIZE)
                if len(chunk) < FileManagerRC5.BLOCK_SIZE:
                    pad_len = FileManagerRC5.BLOCK_SIZE - len(chunk)
                    chunk += bytes([pad_len] * pad_len)
                    xored = bytes(a ^ b for a, b in zip(chunk, prev_block))
                    enc_block = rc5.encrypt_block(xored)
                    f_out.write(enc_block)
                    break
                else:
                    xored = bytes(a ^ b for a, b in zip(chunk, prev_block))
                    enc_block = rc5.encrypt_block(xored)
                    f_out.write(enc_block)
                    prev_block = enc_block

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, passphrase: str):
        key = FileManagerRC5.derive_key(passphrase)
        rc5 = RC5(key, w=16, r=12, b=16)
        
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            enc_iv = f_in.read(FileManagerRC5.BLOCK_SIZE)
            if not enc_iv or len(enc_iv) < FileManagerRC5.BLOCK_SIZE:
                raise ValueError("Файл занадто малий, відсутній IV")
                
            iv = rc5.decrypt_block(enc_iv) 
            prev_block = iv
            
            next_chunk = f_in.read(FileManagerRC5.BLOCK_SIZE)
            while True:
                chunk = next_chunk
                next_chunk = f_in.read(FileManagerRC5.BLOCK_SIZE)
                
                if len(chunk) < FileManagerRC5.BLOCK_SIZE:
                    raise ValueError("Пошкоджений файл або неправильний розмір блоку")
                    
                dec_block = rc5.decrypt_block(chunk)
                plain = bytes(a ^ b for a, b in zip(dec_block, prev_block))
                prev_block = chunk
                
                if not next_chunk:
                    pad_len = plain[-1]
                    if pad_len < 1 or pad_len > FileManagerRC5.BLOCK_SIZE:
                        raise ValueError("Невірний пароль або пошкоджені дані (помилка padding)")
                    plain = plain[:-pad_len]
                    f_out.write(plain)
                    break
                else:
                    f_out.write(plain)