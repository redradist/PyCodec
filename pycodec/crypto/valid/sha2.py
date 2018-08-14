#!/usr/bin/python3
import copy

from bitstring import BitArray


class SHA2:
    """
    Family of SHA2 hash functions
    """
    constants = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    @staticmethod
    def hash_sha224(msg):
        h0 = BitArray(uint=0xC1059ED8, length=32)
        h1 = BitArray(uint=0x367cd507, length=32)
        h2 = BitArray(uint=0x3070dd17, length=32)
        h3 = BitArray(uint=0xf70e5939, length=32)
        h4 = BitArray(uint=0xffc00b31, length=32)
        h5 = BitArray(uint=0x68581511, length=32)
        h6 = BitArray(uint=0x64f98fa7, length=32)
        h7 = BitArray(uint=0xbefa4fa4, length=32)

        bit_msg = BitArray(msg)
        len_msg = len(bit_msg)
        bit_msg += BitArray(bin='1')
        k = (448 + 512 - (len_msg % 512 + 1)) % 512
        bit_msg += BitArray(bin='0' * k)
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
            for i in range(16, 64):
                chunk_i_15 = msg_sub_chunks[i - 15]
                temp0 = copy.deepcopy(chunk_i_15)
                temp0.ror(7)
                temp1 = copy.deepcopy(chunk_i_15)
                temp1.ror(18)
                temp2 = copy.deepcopy(chunk_i_15)
                temp2 = temp2 >> 3
                s0 = temp0 ^ temp1 ^ temp2

                chunk_i_2 = msg_sub_chunks[i - 2]
                temp0 = copy.deepcopy(chunk_i_2)
                temp0.ror(17)
                temp1 = copy.deepcopy(chunk_i_2)
                temp1.ror(19)
                temp2 = copy.deepcopy(chunk_i_2)
                temp2 = temp2 >> 10
                s1 = temp0 ^ temp1 ^ temp2

                msg_sub_chunks.append(BitArray(
                    uint=(msg_sub_chunks[i - 16].uint + s0.uint + msg_sub_chunks[i - 7].uint + s1.uint) % (2 ** 32),
                    length=32))

            a = copy.deepcopy(h0)
            b = copy.deepcopy(h1)
            c = copy.deepcopy(h2)
            d = copy.deepcopy(h3)
            e = copy.deepcopy(h4)
            f = copy.deepcopy(h5)
            g = copy.deepcopy(h6)
            h = copy.deepcopy(h7)

            for i in range(0, 64):
                temp0 = copy.deepcopy(a)
                temp0.ror(2)
                temp1 = copy.deepcopy(a)
                temp1.ror(13)
                temp2 = copy.deepcopy(a)
                temp2.ror(22)
                Sum0 = temp0 ^ temp1 ^ temp2

                Ma = (a & b) ^ (a & c) ^ (b & c)

                t2 = BitArray(uint=(Sum0.uint + Ma.uint) % (2 ** 32),
                              length=32)

                temp0 = copy.deepcopy(e)
                temp0.ror(6)
                temp1 = copy.deepcopy(e)
                temp1.ror(11)
                temp2 = copy.deepcopy(e)
                temp2.ror(25)
                Sum1 = temp0 ^ temp1 ^ temp2

                temp0 = e & f
                temp1 = ~e
                temp2 = copy.deepcopy(g)
                Ch = temp0 ^ (temp1 & temp2)

                t1 = BitArray(
                    uint=(h.uint + Sum1.uint + Ch.uint + SHA2.constants[i] + msg_sub_chunks[i].uint) % (2 ** 32),
                    length=32)

                h = copy.deepcopy(g)
                g = copy.deepcopy(f)
                f = copy.deepcopy(e)
                e = BitArray(uint=(d.uint + t1.uint) % (2 ** 32),
                             length=32)
                d = copy.deepcopy(c)
                c = copy.deepcopy(b)
                b = copy.deepcopy(a)
                a = BitArray(uint=(t1.uint + t2.uint) % (2 ** 32),
                             length=32)

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
            h5 = BitArray(uint=(h5.uint + f.uint) % (2 ** 32),
                          length=32)
            h6 = BitArray(uint=(h6.uint + g.uint) % (2 ** 32),
                          length=32)
            h7 = BitArray(uint=(h7.uint + h.uint) % (2 ** 32),
                          length=32)

        hash = h0 + h1 + h2 + h3 + h4 + h5 + h6
        return hash.tobytes()

    @staticmethod
    def hash_sha256(msg):
        h0 = BitArray(uint=0x6a09e667, length=32)
        h1 = BitArray(uint=0xbb67ae85, length=32)
        h2 = BitArray(uint=0x3c6ef372, length=32)
        h3 = BitArray(uint=0xa54ff53a, length=32)
        h4 = BitArray(uint=0x510e527f, length=32)
        h5 = BitArray(uint=0x9b05688c, length=32)
        h6 = BitArray(uint=0x1f83d9ab, length=32)
        h7 = BitArray(uint=0x5be0cd19, length=32)

        bit_msg = BitArray(msg)
        len_msg = len(bit_msg)
        bit_msg += BitArray(bin='1')
        k = (448 + 512 - (len_msg % 512 + 1)) % 512
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
            for i in range(16, 64):
                chunk_i_15 = msg_sub_chunks[i-15]
                temp0 = copy.deepcopy(chunk_i_15)
                temp0.ror(7)
                temp1 = copy.deepcopy(chunk_i_15)
                temp1.ror(18)
                temp2 = copy.deepcopy(chunk_i_15)
                temp2 = temp2 >> 3
                s0 = temp0 ^ temp1 ^ temp2

                chunk_i_2 = msg_sub_chunks[i-2]
                temp0 = copy.deepcopy(chunk_i_2)
                temp0.ror(17)
                temp1 = copy.deepcopy(chunk_i_2)
                temp1.ror(19)
                temp2 = copy.deepcopy(chunk_i_2)
                temp2 = temp2 >> 10
                s1 = temp0 ^ temp1 ^ temp2

                msg_sub_chunks.append(BitArray(uint=(msg_sub_chunks[i-16].uint + s0.uint + msg_sub_chunks[i-7].uint + s1.uint) % (2 ** 32),
                                       length=32))

            a = copy.deepcopy(h0)
            b = copy.deepcopy(h1)
            c = copy.deepcopy(h2)
            d = copy.deepcopy(h3)
            e = copy.deepcopy(h4)
            f = copy.deepcopy(h5)
            g = copy.deepcopy(h6)
            h = copy.deepcopy(h7)

            for i in range(0, 64):
                temp0 = copy.deepcopy(a)
                temp0.ror(2)
                temp1 = copy.deepcopy(a)
                temp1.ror(13)
                temp2 = copy.deepcopy(a)
                temp2.ror(22)
                Sum0 = temp0 ^ temp1 ^ temp2

                Ma = (a & b) ^ (a & c) ^ (b & c)

                t2 = BitArray(uint=(Sum0.uint + Ma.uint) % (2 ** 32),
                              length=32)

                temp0 = copy.deepcopy(e)
                temp0.ror(6)
                temp1 = copy.deepcopy(e)
                temp1.ror(11)
                temp2 = copy.deepcopy(e)
                temp2.ror(25)
                Sum1 = temp0 ^ temp1 ^ temp2

                temp0 = e & f
                temp1 = ~e
                temp2 = copy.deepcopy(g)
                Ch = temp0 ^ (temp1 & temp2)

                t1 = BitArray(uint=(h.uint + Sum1.uint + Ch.uint + SHA2.constants[i] + msg_sub_chunks[i].uint) % (2 ** 32),
                              length=32)

                h = copy.deepcopy(g)
                g = copy.deepcopy(f)
                f = copy.deepcopy(e)
                e = BitArray(uint=(d.uint + t1.uint) % (2 ** 32),
                             length=32)
                d = copy.deepcopy(c)
                c = copy.deepcopy(b)
                b = copy.deepcopy(a)
                a = BitArray(uint=(t1.uint + t2.uint) % (2 ** 32),
                             length=32)

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
            h5 = BitArray(uint=(h5.uint + f.uint) % (2 ** 32),
                          length=32)
            h6 = BitArray(uint=(h6.uint + g.uint) % (2 ** 32),
                          length=32)
            h7 = BitArray(uint=(h7.uint + h.uint) % (2 ** 32),
                          length=32)

        hash = h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7
        return hash.tobytes()
