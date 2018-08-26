#!/usr/bin/python3
import copy

from bitstring import BitArray


class SHA1:
    """
    Family of SHA2 hash functions
    """

    @staticmethod
    def hash(msg):
        h0 = BitArray(uint=0x67452301, length=32)
        h1 = BitArray(uint=0xefcdab89, length=32)
        h2 = BitArray(uint=0x98badcfe, length=32)
        h3 = BitArray(uint=0x10325476, length=32)
        h4 = BitArray(uint=0xc3d2e1f0, length=32)

        bit_msg = BitArray(msg)
        len_msg = len(bit_msg)
        bit_msg += BitArray(bin='1')
        k = (448 - (len_msg + 1)) % 512
        bit_msg += BitArray(bin='0'*k)
        bit_msg += BitArray(int=len_msg, length=64)
        num_chunks = len(bit_msg) // 512
        assert len(bit_msg) % 512 == 0

        bit_msg_chunks = list(bit_msg[512 * num_chunk:
                                      512 * (num_chunk + 1)]
                              for num_chunk in range(num_chunks))
        for bit_msg_chunk in bit_msg_chunks:
            msg_sub_chunks = list(bit_msg_chunk[32 * num_chunk:
                                                32 * (num_chunk + 1)]
                                  for num_chunk in range(16))
            for i in range(16, 80):
                xor_chunks = msg_sub_chunks[i-3] ^ \
                             msg_sub_chunks[i-8] ^ \
                             msg_sub_chunks[i-14] ^ \
                             msg_sub_chunks[i-16]
                xor_chunks.rol(1)
                msg_sub_chunks.append(xor_chunks)

            a = h0
            b = h1
            c = h2
            d = h3
            e = h4

            for i in range(0, 80):
                if 0 <= i <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5a827999
                elif 20 <= i <= 39:
                    f = b ^ c ^ d
                    k = 0x6ed9eba1
                elif 40 <= i <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8f1bbcdc
                else:
                    f = b ^ c ^ d
                    k = 0xca62c1d6

                a_rol5 = copy.copy(a)
                a_rol5.rol(5)
                temp = BitArray(uint=(a_rol5.uint + f.uint + e.uint + k + msg_sub_chunks[i].uint) % (2 ** 32),
                                length=32)
                e = copy.copy(d)
                d = copy.copy(c)
                c = copy.copy(b)
                c.rol(30)
                b = copy.copy(a)
                a = temp

            h0 = BitArray(uint=(h0.uint + a.uint) % (2 ** 32),
                          length=32)
            h1 = BitArray(uint=(h1.uint + b.uint) % (2 ** 32),
                          length=32)
            h2 = BitArray(uint=(h2.uint + c.uint) % (2 ** 32),
                          length=32)
            h3 = BitArray(uint=(h3.uint + d.uint) % (2 ** 32),
                          length=32)
            h4 = BitArray(uint=(h4.uint + e.uint) % (2 ** 32),
                          length=32)

        hash = h0 + h1 + h2 + h3 + h4
        return hash.tobytes()