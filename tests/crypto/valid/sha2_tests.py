import unittest

from pycodec.crypto.valid.sha2 import SHA2


class Testing_SHA2(unittest.TestCase):
    def setUp(self):
        """Currently nothing to do. Use it for initialization data before test"""
        pass

    def tearDown(self):
        """Currently nothing to do. Use it for reinitialization data after test"""
        pass

    def test__SHA224_Encrypt_PeriodicA__Valid(self):
        sha_224 = SHA2.hash_sha224(bytes('The quick brown fox jumps over the lazy cog', encoding='ascii'))
        self.assertEqual(sha_224, bytes.fromhex('fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b'))

    def test__SHA256_Encrypt_PeriodicA__Valid(self):
        sha_256 = SHA2.hash_sha256(bytes('The quick brown fox jumps over the lazy cog', encoding='ascii'))
        self.assertEqual(sha_256, bytes.fromhex('e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be'))

    def test__SHA512_Encrypt_PeriodicA__Valid(self):
        sha_512 = SHA2.hash_sha512(bytes('The quick brown fox jumps over the lazy cog', encoding='ascii'))
        self.assertEqual(sha_512, bytes.fromhex('3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045'))
