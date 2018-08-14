import unittest

from pycodec.crypto.valid.sha2 import SHA2


class Testing_SHA_256(unittest.TestCase):
    def setUp(self):
        """Currently nothing to do. Use it for initialization data before test"""
        pass

    def tearDown(self):
        """Currently nothing to do. Use it for reinitialization data after test"""
        pass

    def test__SHA_256_Encrypt_PeriodicA__Valid(self):
        sha_256 = SHA2.hash_sha256(bytes('The quick brown fox jumps over the lazy cog', encoding='ascii'))
        self.assertEqual(sha_256, bytes.fromhex('e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be'))
