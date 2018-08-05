import unittest

from pycodec.crypto.aes import AES


class Testing_AES_CBC(unittest.TestCase):
    def setUp(self):
        """Currently nothing to do. Use it for initialization data before test"""
        pass

    def tearDown(self):
        """Currently nothing to do. Use it for reinitialization data after test"""
        pass

    def test__AES128_Encrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x08, 0xfc, 0x4d, 0xe7, 0x7b, 0xb3, 0x4b, 0xd3, 0x1a, 0xdc, 0x4b, 0x2f, 0x11, 0x5d, 0x22, 0xf3])
        enc_msg = aes.encrypt(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'), mode='CTR')
        self.assertEqual(enc_msg, bytes.fromhex('cf719179e45932a7e0017a418b84bb3cabeb01b573a2314d656012db4d832a4f'))

    def test__AES128_Encrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x2e, 0x5e, 0x3b, 0x51, 0xb3, 0x1e, 0xb1, 0x48, 0x33, 0x15, 0xba, 0xeb, 0x48, 0x36, 0xdc, 0x22])
        enc_msg = aes.encrypt(bytes('abababababababababababababababab', encoding='ascii'), mode='CTR')
        self.assertEqual(enc_msg, bytes.fromhex('3d594de7781a8131333d640c35cae716d74fd95d07b9c3075ed2380e41e504b8'))

    def test__AES128_Encrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xeb, 0xa9, 0x3f, 0x32, 0x70, 0xe9, 0xe0, 0x64, 0x34, 0x83, 0x8e, 0x47, 0x5b, 0x22, 0xcc, 0x3e])
        enc_msg = aes.encrypt(bytes('bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc', encoding='ascii'), mode='CTR')
        self.assertEqual(enc_msg, bytes.fromhex('f085abba1b8ae6b78664a84768707ab9fd5683984f67be9cc6bf7828af28ca6e'))

    def test__AES128_Encrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xa3, 0xa7, 0xe0, 0xad, 0xe7, 0x52, 0x67, 0x66, 0x41, 0x14, 0x83, 0xe9, 0x42, 0x85, 0x82, 0x11])
        enc_msg = aes.encrypt(bytes('abcdefghijklmnopabcdefghijklmnop', encoding='ascii'), mode='CTR')
        self.assertEqual(enc_msg, bytes.fromhex('2a24626a7305e14f61cb195f678cb9b9daf2676d7915786912458b0a198ebd94'))

    def test__AES128_Decrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x08, 0xfc, 0x4d, 0xe7, 0x7b, 0xb3, 0x4b, 0xd3, 0x1a, 0xdc, 0x4b, 0x2f, 0x11, 0x5d, 0x22, 0xf3])
        dec_msg = aes.decrypt(bytes.fromhex('cf719179e45932a7e0017a418b84bb3cabeb01b573a2314d656012db4d832a4f'), mode='CTR')
        self.assertEqual(dec_msg, bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x2e, 0x5e, 0x3b, 0x51, 0xb3, 0x1e, 0xb1, 0x48, 0x33, 0x15, 0xba, 0xeb, 0x48, 0x36, 0xdc, 0x22])
        dec_msg = aes.decrypt(bytes.fromhex('3d594de7781a8131333d640c35cae716d74fd95d07b9c3075ed2380e41e504b8'), mode='CTR')
        self.assertEqual(dec_msg, bytes('abababababababababababababababab', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xeb, 0xa9, 0x3f, 0x32, 0x70, 0xe9, 0xe0, 0x64, 0x34, 0x83, 0x8e, 0x47, 0x5b, 0x22, 0xcc, 0x3e])
        dec_msg = aes.decrypt(bytes.fromhex('f085abba1b8ae6b78664a84768707ab9fd5683984f67be9cc6bf7828af28ca6e'), mode='CTR')
        self.assertEqual(dec_msg, bytes('bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xa3, 0xa7, 0xe0, 0xad, 0xe7, 0x52, 0x67, 0x66, 0x41, 0x14, 0x83, 0xe9, 0x42, 0x85, 0x82, 0x11])
        dec_msg = aes.decrypt(bytes.fromhex('2a24626a7305e14f61cb195f678cb9b9daf2676d7915786912458b0a198ebd94'), mode='CTR')
        self.assertEqual(dec_msg, bytes('abcdefghijklmnopabcdefghijklmnop', encoding='ascii'))
