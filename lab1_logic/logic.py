import os
import random
from abc import ABC, abstractmethod

class IRandomGenerator(ABC):
    @abstractmethod
    def generate(self, k: int) -> list[int]:
        pass

class LCG(IRandomGenerator):
    def __init__(self, m=int(2e19)-1, a=6**3, c=55, x_0=1024):
        self.m = m
        self.a = a
        self.c = c
        self.x_0 = x_0

    def generate(self, k: int) -> list[int]:
        x_p = (self.a * self.x_0 + self.c) % self.m
        x = x_p
        xm = [x_p]
        for _ in range(k - 1):
            x = (self.a * x + self.c) % self.m
            if x == x_p:
                break
            xm.append(x)
        return xm

    def get_period(self, max_steps=5000000):
        x1 = (self.a * self.x_0 + self.c) % self.m
        x2 = (self.a * ((self.a * self.x_0 + self.c) % self.m) + self.c) % self.m
        steps = 0
        
        while True:
            x1 = (self.a * x1 + self.c) % self.m
            x2 = (self.a * ((self.a * x2 + self.c) % self.m) + self.c) % self.m
            steps += 1
            if x1 == x2:
                break
            if steps > max_steps:
                return f"Більший за {max_steps} кроків"
                
        t = x1
        i = 0
        t_0 = t
        while True:
            t = (self.a * t + self.c) % self.m
            i += 1
            if t_0 == t:
                break
        return i

class SystemGenerator(IRandomGenerator):
    def generate(self, k: int) -> list[int]:
        return [random.randint(1, int(2e19)-1) for _ in range(k)]


class PiEstimator:
    @staticmethod
    def gcd(a: int, b: int) -> int:
        if b == 0:
            return a
        return PiEstimator.gcd(b, a % b)

    @staticmethod
    def estimate_cesaro(sequence: list[int]):
        pairs = len(sequence) // 2
        k_success = 0
        
        for i in range(0, len(sequence)-1, 2):
            if PiEstimator.gcd(sequence[i], sequence[i+1]) == 1:
                k_success += 1
                
        if k_success == 0:
            return 0.0
            
        return (6 / (k_success / pairs)) ** 0.5


class FileManager:
    @staticmethod
    def save_sequence(filename: str, sequence: list[int]):
        with open(filename, 'w') as f:
            f.write(' '.join(map(str, sequence)))

    @staticmethod
    def exists(filename: str) -> bool:
        return os.path.exists(filename)