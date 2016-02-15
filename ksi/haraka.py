import itertools

#
# This is a slightly modified version of: https://github.com/kste/haraka/blob/master/code/python/ref.py
# Mostly it was stripped for what we don't need and class were added (to comply with hashlib hash objects).
#

MPAR = 1
ROUNDS = 5
AES_ROUNDS = 2

# AES S-box
S = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
     [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
     [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
     [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
     [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
     [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
     [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
     [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
     [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
     [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
     [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
     [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
     [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
     [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
     [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
     [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]


# get padded hex for single byte
def hexbyte(x):
    return hex(x)[2:].zfill(2)


# print list of bytes in hex
def ps(s):
    return " ".join([hexbyte(x) for x in s])


# multiply by 2 over GF(2^128)
def xtime(x):
    if (x >> 7):
        return ((x << 1) ^ 0x1b) & 0xff
    else:
        return (x << 1) & 0xff


# xor two lists element-wise
def xor(x, y):
    return [x[i] ^ y[i] for i in range(16)]


# apply a single S-box
def sbox(x):
    return S[(x >> 4)][x & 0xF]


# AES SubBytes
def subbytes(s):
    return [sbox(x) for x in s]


# AES ShiftRows
def shiftrows(s):
    return [s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11]]


# AES MixColumns
def mixcolumns(s):
    return list(itertools.chain(*
                                [[xtime(s[4 * i]) ^ xtime(s[4 * i + 1]) ^ s[4 * i + 1] ^ s[4 * i + 2] ^ s[4 * i + 3],
                                  s[4 * i] ^ xtime(s[4 * i + 1]) ^ xtime(s[4 * i + 2]) ^ s[4 * i + 2] ^ s[4 * i + 3],
                                  s[4 * i] ^ s[4 * i + 1] ^ xtime(s[4 * i + 2]) ^ xtime(s[4 * i + 3]) ^ s[4 * i + 3],
                                  xtime(s[4 * i]) ^ s[4 * i] ^ s[4 * i + 1] ^ s[4 * i + 2] ^ xtime(s[4 * i + 3])]
                                 for i in range(4)]))


# AES single regular round
def aesenc(s, rk):
    # s = subbytes(s[::-1])
    s = subbytes(s)
    s = shiftrows(s)
    s = mixcolumns(s)
    # s = xor(s, rk[::-1])
    s = xor(s, rk[::-1])
    # return s[::-1]
    return s


# consider 4 consecutive entries as 32-bit values and shift each of them to the left
def shift32(x):
    # make list of 32-bit elements
    w = [((x[i] << 24) ^ (x[i + 1] << 16) ^ (x[i + 2] << 8) ^ x[i + 3]) << 1 for i in [0, 4, 8, 12]]
    return list(itertools.chain(*[[(q >> 24) & 0xFF, (q >> 16) & 0xFF, (q >> 8) & 0xFF, (q >> 0) & 0xFF] for q in w]))


# linear mixing for Haraka-512/256
def mix512(s):
    return [s[0][12:16] + s[2][12:16] + s[1][12:16] + s[3][12:16],
            s[2][0:4] + s[0][0:4] + s[3][0:4] + s[1][0:4],
            s[2][4:8] + s[0][4:8] + s[3][4:8] + s[1][4:8],
            s[0][8:12] + s[2][8:12] + s[1][8:12] + s[3][8:12]]


# linear mixing for Haraka-256/256
def mix256(s):
    return [s[0][0:4] + s[1][0:4] + s[0][4:8] + s[1][4:8],
            s[0][8:12] + s[1][8:12] + s[0][12:16] + s[1][12:16]]


# Haraka-512/256
def haraka512256(msg):
    # obtain state from msg input and set initial rcon
    s = [msg[i:i + 16] for i in [0, 16, 32, 48]]
    rcon = [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]

    # apply round functions
    for t in range(ROUNDS):
        # first we do AES_ROUNDS of AES rounds and update the round constant each time
        for m in range(AES_ROUNDS):
            s = [aesenc(s[i], rcon) for i in range(4)]
            rcon = shift32(rcon)

        # now apply mixing
        s = mix512(s)

    # apply feed-forward
    s = [xor(s[i], msg[16 * i:16 * (i + 1)]) for i in range(4)]
    # truncation
    return s[0][8:] + s[1][8:] + s[2][0:8] + s[3][0:8]


# Haraka-256/256
def haraka256256(msg):
    # obtain state from msg input and set initial rcon
    s = [msg[i:i + 16] for i in [0, 16]]
    rcon = [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]

    # apply round functions
    for t in range(ROUNDS):
        # first we do AES_ROUNDS of AES rounds and update the round constant each time
        for m in range(AES_ROUNDS):
            s = [aesenc(s[i], rcon) for i in range(2)]
            rcon = shift32(rcon)

        # now apply mixing
        s = mix256(s)

    # apply feed-forward
    s = [xor(s[i], msg[16 * i:16 * (i + 1)]) for i in range(2)]

    # truncation
    return list(itertools.chain(*s))


# _digest = haraka256256([m for m in range(32)])
# print(bytes(_digest).hex())  # 'cbb4e2a4a7b471c6cc448cd264d1083eaf8f75d0d40ac4f973da6d53bfc05cc0'

# _digest = haraka512256([m for m in range(64)])
# print(bytes(_digest).hex())  # '2f62a31be6eb3a1cd643fea5e869ff7cbe863b265db4b00e7cf3e319bfa166c1'


class Haraka512_256:
    def __init__(self, data: bytes):
        self.digest_size = int(512 / 8)

        # Adjust the size if it's not correct
        if len(data) != self.digest_size:
            data = data + b'01' + b'00' * self.digest_size - len(data) - 1
            print("data = " + str(data))
            assert len(data) == self.digest_size

        self._digest = bytes(haraka512256(data))

    def digest(self) -> bytes:
        return self._digest

    def hexdigest(self) -> str:
        return self._digest.hex()


class Haraka256_256:
    def __init__(self, data: bytes):
        self.digest_size = int(256 / 8)

        if len(data) != self.digest_size:
            raise ValueError("Wrong input size for Haraka 256 -> 256")

        self._digest = bytes(haraka256256(data))

    def digest(self) -> bytes:
        return self._digest

    def hexdigest(self) -> str:
        return self._digest.hex()
