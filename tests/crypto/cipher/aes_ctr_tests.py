import unittest

from pycodec.crypto.cipher.aes import AES


class Testing_AES_CTR(unittest.TestCase):
    def setUp(self):
        """Currently nothing to do. Use it for initialization data before test"""
        pass

    def tearDown(self):
        """Currently nothing to do. Use it for reinitialization data after test"""
        pass

    def test__AES128_Encrypt_PeriodicASDASDA__Valid(self):
        aes = AES(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'),
                  [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff])
        enc_msg = aes.encrypt(bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'), mode='CTR')
        self.assertEqual(enc_msg, bytes.fromhex('874d6191b620e3261bef6864990db6ce'))

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

    def test__AES128_Encrypt_OnlineTest__Valid(self):
        """
        Test from https://tools.ietf.org/html/rfc3686#page-2
        """
        aes = AES(bytes.fromhex('7691be035e5020a8ac6e618529f9a0dc'),
                  [0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0, 0x00, 0x00, 0x00, 0x01])
        enc_msg = aes.encrypt(bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), mode='CTR')
        self.assertEqual(enc_msg, bytes.fromhex('c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef31053'))

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

    def test__AES128_Decrypt_OnlineTest__Valid(self):
        """
        Test from https://tools.ietf.org/html/rfc3686#page-2
        """
        aes = AES(bytes.fromhex('7691be035e5020a8ac6e618529f9a0dc'),
                  [0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0, 0x00, 0x00, 0x00, 0x01])
        dec_msg = aes.decrypt(bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), mode='CTR')
        self.assertEqual(dec_msg, bytes.fromhex('c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef31053'))

    def test__AES192_Encrypt_OnlineTest__Valid(self):
        """
        Test from https://tools.ietf.org/html/rfc3686#page-2
        """
        aes = AES(bytes.fromhex('7c5cb2401b3dc33c19e7340819e0f69c678c3db8e6f6a91a'),
                  [0x00, 0x96, 0xB0 , 0x3B, 0x02, 0x0C, 0x6E, 0xAD, 0xC2, 0xCB, 0x50, 0x0D, 0x00, 0x00, 0x00, 0x01])
        enc_msg = aes.encrypt(bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), mode='CTR')
        self.assertEqual(enc_msg, bytes.fromhex('453243fc609b23327edfaafa7131cd9f8490701c5ad4a79cfc1fe0ff42f4fb00'))

    def test__AES192_Decrypt_OnlineTest__Valid(self):
        """
        Test from https://tools.ietf.org/html/rfc3686#page-2
        """
        aes = AES(bytes.fromhex('7c5cb2401b3dc33c19e7340819e0f69c678c3db8e6f6a91a'),
                  [0x00, 0x96, 0xB0 , 0x3B, 0x02, 0x0C, 0x6E, 0xAD, 0xC2, 0xCB, 0x50, 0x0D, 0x00, 0x00, 0x00, 0x01])
        dec_msg = aes.decrypt(bytes.fromhex('453243fc609b23327edfaafa7131cd9f8490701c5ad4a79cfc1fe0ff42f4fb00'), mode='CTR')
        self.assertEqual(dec_msg, bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'))

    def test__AES256_Encrypt_OnlineTest__Valid(self):
        """
        Test from https://tools.ietf.org/html/rfc3686#page-2
        """
        aes = AES(bytes.fromhex('f6d66d6bd52d59bb0796365879eff886c66dd51a5b6a99744b50590c87a23884'),
                  [0x00, 0xFA, 0xAC, 0x24, 0xC1, 0x58, 0x5E, 0xF1, 0x5A, 0x43, 0xD8, 0x75, 0x00, 0x00, 0x00, 0x01])
        enc_msg = aes.encrypt(bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), mode='CTR')
        self.assertEqual(enc_msg, bytes.fromhex('f05e231b3894612c49ee000b804eb2a9b8306b508f839d6a5530831d9344af1c'))

    def test__AES256_Decrypt_OnlineTest__Valid(self):
        """
        Test from https://tools.ietf.org/html/rfc3686#page-2
        """
        aes = AES(bytes.fromhex('f6d66d6bd52d59bb0796365879eff886c66dd51a5b6a99744b50590c87a23884'),
                  [0x00, 0xFA, 0xAC, 0x24, 0xC1, 0x58, 0x5E, 0xF1, 0x5A, 0x43, 0xD8, 0x75, 0x00, 0x00, 0x00, 0x01])
        dec_msg = aes.decrypt(bytes.fromhex('f05e231b3894612c49ee000b804eb2a9b8306b508f839d6a5530831d9344af1c'), mode='CTR')
        self.assertEqual(dec_msg, bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'))

