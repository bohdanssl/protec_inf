import unittest
import os
from app import app
from logic import LCG, PiEstimator, FileManager

class TestMathFunctions(unittest.TestCase):
    
    def test_gcd(self):
        self.assertEqual(PiEstimator.gcd(10, 5), 5)    
        self.assertEqual(PiEstimator.gcd(17, 13), 1)   
        self.assertEqual(PiEstimator.gcd(100, 0), 100) 
        
    def test_randomnumb_length(self):
        k = 150
        lcg = LCG()
        result = lcg.generate(k)
        self.assertEqual(len(result), k)
        
    def test_chezaro_returns_float(self):
        test_array = [10, 3, 15, 4, 20, 7]
        pi_estimate = PiEstimator.estimate_cesaro(test_array)

        self.assertIsInstance(pi_estimate, float)
        self.assertGreater(pi_estimate, 0)

class TestFlaskRoutes(unittest.TestCase):
    
    def setUp(self):
        app.testing = True
        self.client = app.test_client()
        self.filename = 'example.txt'

    def test_index_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_lab1_post(self):
        response = self.client.post('/lab1', data={'k_val': '100'})
        self.assertEqual(response.status_code, 200)
        
        self.assertIn(b'100', response.data)
    
    def test_file_creation(self):
        if os.path.exists(self.filename):
            os.remove(self.filename)

        self.client.post('/lab1', data={'k_val': '50'})

        self.assertTrue(FileManager.exists(self.filename), "Файл example.txt не був створений!")

        with open(self.filename, 'r') as f:
            content = f.read()
            self.assertGreater(len(content), 0, "Файл створився, але він порожній!")

        if os.path.exists(self.filename):
            os.remove(self.filename)

if __name__ == '__main__':
    unittest.main()