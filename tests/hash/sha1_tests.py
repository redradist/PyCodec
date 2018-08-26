import unittest

from pycodec.hash.sha1 import SHA1


class Testing_SHA1(unittest.TestCase):
    def setUp(self):
        """Currently nothing to do. Use it for initialization data before test"""
        pass

    def tearDown(self):
        """Currently nothing to do. Use it for reinitialization data after test"""
        pass

    def test__SHA1_Encrypt_Pangramma__Valid(self):
        sha1 = SHA1.hash(bytes('The quick brown fox jumps over the lazy dog', encoding='ascii'))
        self.assertEqual(sha1, bytes.fromhex('2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'))

    def test__SHA1_Encrypt_sha__Valid(self):
        sha1 = SHA1.hash(bytes('sha', encoding='ascii'))
        self.assertEqual(sha1, bytes.fromhex('d8f4590320e1343a915b6394170650a8f35d6926'))

    def test__SHA1_Encrypt_Sha__Valid(self):
        sha1 = SHA1.hash(bytes('Sha', encoding='ascii'))
        self.assertEqual(sha1, bytes.fromhex('ba79baeb9f10896a46ae74715271b7f586e74640'))

    def test__SHA1_Encrypt_EmptyString__Valid(self):
        sha1 = SHA1.hash(bytes('', encoding='ascii'))
        self.assertEqual(sha1, bytes.fromhex('da39a3ee5e6b4b0d3255bfef95601890afd80709'))