#!/usr/bin/python3
from bitstring import BitArray


class HMAC:
    """
    HMAC function
    """
    def __init__(self, key, hash_func):
        self.key = key
        self.hash_func = hash_func

    def calculate(self, msg):
        return HMAC.hash(self.key, msg, self.hash_func)

    @staticmethod
    def new(key, hash_func):
        return HMAC(key, hash_func)

    @staticmethod
    def hash(key, msg, hash_func):
        block_size = hash_func.block_size // 8

        if len(key) > block_size:
            key = hash_func(key)
        if len(key) < block_size:
            key += bytes([0x00] * (block_size - len(key)))

        o_key_pad = (BitArray(key) ^ BitArray(bytes([0x5c] * block_size))).tobytes()
        i_key_pad = (BitArray(key) ^ BitArray(bytes([0x36] * block_size))).tobytes()

        return hash_func(o_key_pad + hash_func(i_key_pad + msg))
