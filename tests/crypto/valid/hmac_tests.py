import unittest

from pycodec.crypto.valid.hmac import HMAC
from pycodec.hash.sha2 import SHA2


class Testing_HMAC_ECB(unittest.TestCase):
    def setUp(self):
        """Currently nothing to do. Use it for initialization data before test"""
        pass

    def tearDown(self):
        """Currently nothing to do. Use it for reinitialization data after test"""
        pass

    def test__HMAC_Encrypt_PeriodicA__Valid(self):
        enc_msg = HMAC.hash(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                            bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                            SHA2.hash_sha256)
        self.assertEqual(enc_msg, bytes.fromhex('e368615587628035cc1f875e1f1093c7826c36742eec538be8c7e125353e52f7'))

    def test__HMAC_Encrypt_TooLongKey_PeriodicA__Valid(self):
        enc_msg = HMAC.hash(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                            bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                            SHA2.hash_sha256)
        self.assertEqual(enc_msg, bytes.fromhex('51bef6b07642a2680d1b39e8a54992bbbc3489117e41e262963ff5f9f8cf5547'))
