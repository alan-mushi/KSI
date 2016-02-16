from ctypes import *

from ksi import LIBHARAKA_PATH

#
# The source & Makefile for libharaka.so are in a separate repository:
# https://github.com/alan-mushi/Haraka-wrapper-Python
#
# Native (C lib) support for Haraka is **experimental** and has created some _un-explicable_ bugs during benchmark.
#

lib = cdll.LoadLibrary(LIBHARAKA_PATH + 'libharaka.so')


def haraka512256(msg: bytes) -> bytes:
    assert len(msg) == 64

    h = create_string_buffer(32)
    lib.haraka512256(h, create_string_buffer(msg))

    return h.value


def haraka256256(msg: bytes) -> bytes:
    assert len(msg) == 32

    h = create_string_buffer(32)
    lib.haraka256256(h, create_string_buffer(msg))

    return h.value


class Haraka512_256:
    def __init__(self, data: bytes):
        self.digest_size = int(512 / 8)

        # Adjust the size if it's not correct
        if len(data) < self.digest_size:
            data = data + b'\x01' + b'\x00' * (self.digest_size - len(data) - 1)
            assert len(data) == self.digest_size

        elif len(data) > self.digest_size:
            raise ValueError("The input size is too large")

        self._digest = bytes(haraka512256(data))

    def digest(self) -> bytes:
        return self._digest

    def hexdigest(self) -> str:
        return self._digest.hex()


class Haraka256_256:
    def __init__(self, data: bytes):
        self.digest_size = int(256 / 8)

        if len(data) < self.digest_size:
            data = data + b'\x01' + b'\x00' * (self.digest_size - len(data) - 1)
            assert len(data) == self.digest_size

        elif len(data) > self.digest_size:
            raise ValueError("The input size is too large")

        self._digest = bytes(haraka256256(data))

    def digest(self) -> bytes:
        return self._digest

    def hexdigest(self) -> str:
        return self._digest.hex()
