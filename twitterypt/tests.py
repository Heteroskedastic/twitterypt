import unittest

from twitterypt.utils import rand_str, encrypt, decrypt, generate_key_pair


class UtilsTest(unittest.TestCase):

    def setUp(self):
        self.private_key, self.public_key = generate_key_pair()

    def test_encrypt_decrypt1(self):
        for i in range(100):
            s = rand_str(1).encode()
            enc = encrypt(s, self.public_key)
            dec = decrypt(enc, self.private_key)
            self.assertEqual(dec, s)

    def test_encrypt_decrypt2(self):
        for i in range(100):
            s = rand_str(10).encode()
            enc = encrypt(s, self.public_key)
            dec = decrypt(enc, self.private_key)
            self.assertEqual(dec, s)

    def test_encrypt_decrypt3(self):
        for i in range(100):
            s = rand_str(128).encode()
            enc = encrypt(s, self.public_key)
            dec = decrypt(enc, self.private_key)
            self.assertEqual(dec, s)

    def test_encrypt_decrypt4(self):
        for i in range(100):
            s = rand_str(256).encode()
            enc = encrypt(s, self.public_key)
            dec = decrypt(enc, self.private_key)
            self.assertEqual(dec, s)

if __name__ == '__main__':
    unittest.main()
