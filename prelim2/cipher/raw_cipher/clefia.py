#!/usr/bin/python3
#
# Author: Joao H de A Franco (jhafranco@acm.org)
#
# Description: CLEFIA implementation in Python 3
#
# Date: 2012-02-02
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
# ===========================================================
import sys

# Key size supported
ksTable = {"SIZE_128": 16, "SIZE_192": 24, "SIZE_256": 32}

# Number of rounds related to key size
nrTable = {"SIZE_128": 18, "SIZE_192": 22, "SIZE_256": 26}

# Number of round keys related to key size
nrkTable = {"SIZE_128": 36, "SIZE_192": 44, "SIZE_256": 52}

# Number of rounds
nr = None

# Number of round keys effectively used
nrk = None

# Number of whitening keys
nwk = 4

# Round keys vector
rk = [None] * 2 * nrTable[max(nrTable)]

# Whitening keys
wk = [None] * 4

# First S-Box
s0 = [
    0x57,
    0x49,
    0xD1,
    0xC6,
    0x2F,
    0x33,
    0x74,
    0xFB,
    0x95,
    0x6D,
    0x82,
    0xEA,
    0x0E,
    0xB0,
    0xA8,
    0x1C,
    0x28,
    0xD0,
    0x4B,
    0x92,
    0x5C,
    0xEE,
    0x85,
    0xB1,
    0xC4,
    0x0A,
    0x76,
    0x3D,
    0x63,
    0xF9,
    0x17,
    0xAF,
    0xBF,
    0xA1,
    0x19,
    0x65,
    0xF7,
    0x7A,
    0x32,
    0x20,
    0x06,
    0xCE,
    0xE4,
    0x83,
    0x9D,
    0x5B,
    0x4C,
    0xD8,
    0x42,
    0x5D,
    0x2E,
    0xE8,
    0xD4,
    0x9B,
    0x0F,
    0x13,
    0x3C,
    0x89,
    0x67,
    0xC0,
    0x71,
    0xAA,
    0xB6,
    0xF5,
    0xA4,
    0xBE,
    0xFD,
    0x8C,
    0x12,
    0x00,
    0x97,
    0xDA,
    0x78,
    0xE1,
    0xCF,
    0x6B,
    0x39,
    0x43,
    0x55,
    0x26,
    0x30,
    0x98,
    0xCC,
    0xDD,
    0xEB,
    0x54,
    0xB3,
    0x8F,
    0x4E,
    0x16,
    0xFA,
    0x22,
    0xA5,
    0x77,
    0x09,
    0x61,
    0xD6,
    0x2A,
    0x53,
    0x37,
    0x45,
    0xC1,
    0x6C,
    0xAE,
    0xEF,
    0x70,
    0x08,
    0x99,
    0x8B,
    0x1D,
    0xF2,
    0xB4,
    0xE9,
    0xC7,
    0x9F,
    0x4A,
    0x31,
    0x25,
    0xFE,
    0x7C,
    0xD3,
    0xA2,
    0xBD,
    0x56,
    0x14,
    0x88,
    0x60,
    0x0B,
    0xCD,
    0xE2,
    0x34,
    0x50,
    0x9E,
    0xDC,
    0x11,
    0x05,
    0x2B,
    0xB7,
    0xA9,
    0x48,
    0xFF,
    0x66,
    0x8A,
    0x73,
    0x03,
    0x75,
    0x86,
    0xF1,
    0x6A,
    0xA7,
    0x40,
    0xC2,
    0xB9,
    0x2C,
    0xDB,
    0x1F,
    0x58,
    0x94,
    0x3E,
    0xED,
    0xFC,
    0x1B,
    0xA0,
    0x04,
    0xB8,
    0x8D,
    0xE6,
    0x59,
    0x62,
    0x93,
    0x35,
    0x7E,
    0xCA,
    0x21,
    0xDF,
    0x47,
    0x15,
    0xF3,
    0xBA,
    0x7F,
    0xA6,
    0x69,
    0xC8,
    0x4D,
    0x87,
    0x3B,
    0x9C,
    0x01,
    0xE0,
    0xDE,
    0x24,
    0x52,
    0x7B,
    0x0C,
    0x68,
    0x1E,
    0x80,
    0xB2,
    0x5A,
    0xE7,
    0xAD,
    0xD5,
    0x23,
    0xF4,
    0x46,
    0x3F,
    0x91,
    0xC9,
    0x6E,
    0x84,
    0x72,
    0xBB,
    0x0D,
    0x18,
    0xD9,
    0x96,
    0xF0,
    0x5F,
    0x41,
    0xAC,
    0x27,
    0xC5,
    0xE3,
    0x3A,
    0x81,
    0x6F,
    0x07,
    0xA3,
    0x79,
    0xF6,
    0x2D,
    0x38,
    0x1A,
    0x44,
    0x5E,
    0xB5,
    0xD2,
    0xEC,
    0xCB,
    0x90,
    0x9A,
    0x36,
    0xE5,
    0x29,
    0xC3,
    0x4F,
    0xAB,
    0x64,
    0x51,
    0xF8,
    0x10,
    0xD7,
    0xBC,
    0x02,
    0x7D,
    0x8E,
]

# Second S-Box
s1 = [
    0x6C,
    0xDA,
    0xC3,
    0xE9,
    0x4E,
    0x9D,
    0x0A,
    0x3D,
    0xB8,
    0x36,
    0xB4,
    0x38,
    0x13,
    0x34,
    0x0C,
    0xD9,
    0xBF,
    0x74,
    0x94,
    0x8F,
    0xB7,
    0x9C,
    0xE5,
    0xDC,
    0x9E,
    0x07,
    0x49,
    0x4F,
    0x98,
    0x2C,
    0xB0,
    0x93,
    0x12,
    0xEB,
    0xCD,
    0xB3,
    0x92,
    0xE7,
    0x41,
    0x60,
    0xE3,
    0x21,
    0x27,
    0x3B,
    0xE6,
    0x19,
    0xD2,
    0x0E,
    0x91,
    0x11,
    0xC7,
    0x3F,
    0x2A,
    0x8E,
    0xA1,
    0xBC,
    0x2B,
    0xC8,
    0xC5,
    0x0F,
    0x5B,
    0xF3,
    0x87,
    0x8B,
    0xFB,
    0xF5,
    0xDE,
    0x20,
    0xC6,
    0xA7,
    0x84,
    0xCE,
    0xD8,
    0x65,
    0x51,
    0xC9,
    0xA4,
    0xEF,
    0x43,
    0x53,
    0x25,
    0x5D,
    0x9B,
    0x31,
    0xE8,
    0x3E,
    0x0D,
    0xD7,
    0x80,
    0xFF,
    0x69,
    0x8A,
    0xBA,
    0x0B,
    0x73,
    0x5C,
    0x6E,
    0x54,
    0x15,
    0x62,
    0xF6,
    0x35,
    0x30,
    0x52,
    0xA3,
    0x16,
    0xD3,
    0x28,
    0x32,
    0xFA,
    0xAA,
    0x5E,
    0xCF,
    0xEA,
    0xED,
    0x78,
    0x33,
    0x58,
    0x09,
    0x7B,
    0x63,
    0xC0,
    0xC1,
    0x46,
    0x1E,
    0xDF,
    0xA9,
    0x99,
    0x55,
    0x04,
    0xC4,
    0x86,
    0x39,
    0x77,
    0x82,
    0xEC,
    0x40,
    0x18,
    0x90,
    0x97,
    0x59,
    0xDD,
    0x83,
    0x1F,
    0x9A,
    0x37,
    0x06,
    0x24,
    0x64,
    0x7C,
    0xA5,
    0x56,
    0x48,
    0x08,
    0x85,
    0xD0,
    0x61,
    0x26,
    0xCA,
    0x6F,
    0x7E,
    0x6A,
    0xB6,
    0x71,
    0xA0,
    0x70,
    0x05,
    0xD1,
    0x45,
    0x8C,
    0x23,
    0x1C,
    0xF0,
    0xEE,
    0x89,
    0xAD,
    0x7A,
    0x4B,
    0xC2,
    0x2F,
    0xDB,
    0x5A,
    0x4D,
    0x76,
    0x67,
    0x17,
    0x2D,
    0xF4,
    0xCB,
    0xB1,
    0x4A,
    0xA8,
    0xB5,
    0x22,
    0x47,
    0x3A,
    0xD5,
    0x10,
    0x4C,
    0x72,
    0xCC,
    0x00,
    0xF9,
    0xE0,
    0xFD,
    0xE2,
    0xFE,
    0xAE,
    0xF8,
    0x5F,
    0xAB,
    0xF1,
    0x1B,
    0x42,
    0x81,
    0xD6,
    0xBE,
    0x44,
    0x29,
    0xA6,
    0x57,
    0xB9,
    0xAF,
    0xF2,
    0xD4,
    0x75,
    0x66,
    0xBB,
    0x68,
    0x9F,
    0x50,
    0x02,
    0x01,
    0x3C,
    0x7F,
    0x8D,
    0x1A,
    0x88,
    0xBD,
    0xAC,
    0xF7,
    0xE4,
    0x79,
    0x96,
    0xA2,
    0xFC,
    0x6D,
    0xB2,
    0x6B,
    0x03,
    0xE1,
    0x2E,
    0x7D,
    0x14,
    0x95,
    0x1D,
]

m0 = [
    0x01,
    0x02,
    0x04,
    0x06,
    0x02,
    0x01,
    0x06,
    0x04,
    0x04,
    0x06,
    0x01,
    0x02,
    0x06,
    0x04,
    0x02,
    0x01,
]

m1 = [
    0x01,
    0x08,
    0x02,
    0x0A,
    0x08,
    0x01,
    0x0A,
    0x02,
    0x02,
    0x0A,
    0x01,
    0x08,
    0x0A,
    0x02,
    0x08,
    0x01,
]

con128 = [
    0xF56B7AEB,
    0x994A8A42,
    0x96A4BD75,
    0xFA854521,
    0x735B768A,
    0x1F7ABAC4,
    0xD5BC3B45,
    0xB99D5D62,
    0x52D73592,
    0x3EF636E5,
    0xC57A1AC9,
    0xA95B9B72,
    0x5AB42554,
    0x369555ED,
    0x1553BA9A,
    0x7972B2A2,
    0xE6B85D4D,
    0x8A995951,
    0x4B550696,
    0x2774B4FC,
    0xC9BB034B,
    0xA59A5A7E,
    0x88CC81A5,
    0xE4ED2D3F,
    0x7C6F68E2,
    0x104E8ECB,
    0xD2263471,
    0xBE07C765,
    0x511A3208,
    0x3D3BFBE6,
    0x1084B134,
    0x7CA565A7,
    0x304BF0AA,
    0x5C6AAA87,
    0xF4347855,
    0x9815D543,
    0x4213141A,
    0x2E32F2F5,
    0xCD180A0D,
    0xA139F97A,
    0x5E852D36,
    0x32A464E9,
    0xC353169B,
    0xAF72B274,
    0x8DB88B4D,
    0xE199593A,
    0x7ED56D96,
    0x12F434C9,
    0xD37B36CB,
    0xBF5A9A64,
    0x85AC9B65,
    0xE98D4D32,
    0x7ADF6582,
    0x16FE3ECD,
    0xD17E32C1,
    0xBD5F9F66,
    0x50B63150,
    0x3C9757E7,
    0x1052B098,
    0x7C73B3A7,
]

con192 = [
    0xC6D61D91,
    0xAAF73771,
    0x5B6226F8,
    0x374383EC,
    0x15B8BB4C,
    0x799959A2,
    0x32D5F596,
    0x5EF43485,
    0xF57B7ACB,
    0x995A9A42,
    0x96ACBD65,
    0xFA8D4D21,
    0x735F7682,
    0x1F7EBEC4,
    0xD5BE3B41,
    0xB99F5F62,
    0x52D63590,
    0x3EF737E5,
    0x1162B2F8,
    0x7D4383A6,
    0x30B8F14C,
    0x5C995987,
    0x2055D096,
    0x4C74B497,
    0xFC3B684B,
    0x901ADA4B,
    0x920CB425,
    0xFE2DED25,
    0x710F7222,
    0x1D2EEEC6,
    0xD4963911,
    0xB8B77763,
    0x524234B8,
    0x3E63A3E5,
    0x1128B26C,
    0x7D09C9A6,
    0x309DF106,
    0x5CBC7C87,
    0xF45F7883,
    0x987EBE43,
    0x963EBC41,
    0xFA1FDF21,
    0x73167610,
    0x1F37F7C4,
    0x01829338,
    0x6DA363B6,
    0x38C8E1AC,
    0x54E9298F,
    0x246DD8E6,
    0x484C8C93,
    0xFE276C73,
    0x9206C649,
    0x9302B639,
    0xFF23E324,
    0x7188732C,
    0x1DA969C6,
    0x00CD91A6,
    0x6CEC2CB7,
    0xEC7748D3,
    0x8056965B,
    0x9A2AA469,
    0xF60BCB2D,
    0x751C7A04,
    0x193DFDC2,
    0x02879532,
    0x6EA666B5,
    0xED524A99,
    0x8173B35A,
    0x4EA00D7C,
    0x228141F9,
    0x1F59AE8E,
    0x7378B8A8,
    0xE3BD5747,
    0x8F9C5C54,
    0x9DCFABA3,
    0xF1EE2E2A,
    0xA2F6D5D1,
    0xCED71715,
    0x697242D8,
    0x055393DE,
    0x0CB0895C,
    0x609151BB,
    0x3E51EC9E,
    0x5270B089,
]

con256 = [
    0x0221947E,
    0x6E00C0B5,
    0xED014A3F,
    0x8120E05A,
    0x9A91A51F,
    0xF6B0702D,
    0xA159D28F,
    0xCD78B816,
    0xBCBDE947,
    0xD09C5C0B,
    0xB24FF4A3,
    0xDE6EAE05,
    0xB536FA51,
    0xD917D702,
    0x62925518,
    0x0EB373D5,
    0x094082BC,
    0x6561A1BE,
    0x3CA9E96E,
    0x5088488B,
    0xF24574B7,
    0x9E64A445,
    0x9533BA5B,
    0xF912D222,
    0xA688DD2D,
    0xCAA96911,
    0x6B4D46A6,
    0x076CACDC,
    0xD9B72353,
    0xB596566E,
    0x80CA91A9,
    0xECEB2B37,
    0x786C60E4,
    0x144D8DCF,
    0x043F9842,
    0x681EDEB3,
    0xEE0E4C21,
    0x822FEF59,
    0x4F0E0E20,
    0x232FEFF8,
    0x1F8EAF20,
    0x73AF6FA8,
    0x37CEFFA0,
    0x5BEF2F80,
    0x23EED7E0,
    0x4FCF0F94,
    0x29FEC3C0,
    0x45DF1F9E,
    0x2CF6C9D0,
    0x40D7179B,
    0x2E72CCD8,
    0x42539399,
    0x2F30CE5C,
    0x4311D198,
    0x2F91CF1E,
    0x43B07098,
    0xFBD9678F,
    0x97F8384C,
    0x91FDB3C7,
    0xFDDC1C26,
    0xA4EFD9E3,
    0xC8CE0E13,
    0xBE66ECF1,
    0xD2478709,
    0x673A5E48,
    0x0B1BDBD0,
    0x0B948714,
    0x67B575BC,
    0x3DC3EBBA,
    0x51E2228A,
    0xF2F075DD,
    0x9ED11145,
    0x417112DE,
    0x2D5090F6,
    0xCCA9096F,
    0xA088487B,
    0x8A4584B7,
    0xE664A43D,
    0xA933C25B,
    0xC512D21E,
    0xB888E12D,
    0xD4A9690F,
    0x644D58A6,
    0x086CACD3,
    0xDE372C53,
    0xB216D669,
    0x830A9629,
    0xEF2BEB34,
    0x798C6324,
    0x15AD6DCE,
    0x04CF99A2,
    0x68EE2EB3,
]


def _8To32(x32):
    return ((x32[0] * 256 + x32[1]) * 256 + x32[2]) * 256 + x32[3]


def _32To8(x32):
    return [(x32 >> 8 * i) & 0xFF for i in reversed(range(4))]


def _32To128(x32):
    return ((x32[0] * 256**4 + x32[1]) * 256**4 + x32[2]) * 256**4 + x32[3]


def _128To32(x128):
    return [(x128 >> 32 * i) & 0xFFFFFFFF for i in reversed(range(4))]


def _192To32(x192):
    return [(x192 >> 32 * i) & 0xFFFFFFFF for i in reversed(range(6))]


def _256To32(x256):
    return [(x256 >> 32 * i) & 0xFFFFFFFF for i in reversed(range(8))]


def sigma(x128):
    return [
        (x128[0] << 7) & 0xFFFFFF80 | (x128[1] >> 25),
        (x128[1] << 7) & 0xFFFFFF80 | (x128[3] & 0x7F),
        (x128[0] & 0xFE000000) | (x128[2] >> 7),
        (x128[2] << 25) & 0xFE000000 | (x128[3] >> 7),
    ]


def mMult(m, t):
    """Multiply a 4x4 matrix by a transposed 1x4 vector in GF(2^8)"""

    def mult(p1, p2):
        """Multiply two polynomials in GF(2^8)"""
        p = 0
        while p2:
            if p2 & 1:
                p ^= p1
            p1 <<= 1
            if p1 & 256:
                p1 ^= 0x1D
            p2 >>= 1
        return p & 255

    s = [0] * 4
    for i in range(4):
        for j in range(4):
            s[i] ^= mult(m[4 * i + j], t[j])
    return s


def f0(rk, x32):
    """F0 function"""
    t8 = _32To8(rk ^ x32)
    return _8To32(mMult(m0, [s0[t8[0]], s1[t8[1]], s0[t8[2]], s1[t8[3]]]))


def f1(rk, x32):
    """F1 function"""
    t8 = _32To8(rk ^ x32)
    return _8To32(mMult(m1, [s1[t8[0]], s0[t8[1]], s1[t8[2]], s0[t8[3]]]))


def gfn4(x32, n):
    """4-branch Generalized Feistel Network function"""
    t32 = x32[:]
    for i in range(n):
        t32[1] ^= f0(rk[2 * i], t32[0])
        t32[3] ^= f1(rk[2 * i + 1], t32[2])
        t32 = t32[1:] + t32[:1]
    return t32[3:] + t32[:3]


def gfn4i(x32, n):
    """4-branch Generalized Feistel Network inverse function"""
    t32 = x32[:]
    for i in reversed(range(n)):
        t32[1] ^= f0(rk[2 * i], t32[0])
        t32[3] ^= f1(rk[2 * i + 1], t32[2])
        t32 = t32[3:] + t32[:3]
    return t32[1:] + t32[:1]


def gfn8(x32, n):
    """8-branch Generalized Feistel Network function"""
    t32 = x32[:]
    for i in range(n):
        t32[1] ^= f0(rk[4 * i], t32[0])
        t32[3] ^= f1(rk[4 * i + 1], t32[2])
        t32[5] ^= f0(rk[4 * i + 2], t32[4])
        t32[7] ^= f1(rk[4 * i + 3], t32[6])
        t32 = t32[1:] + t32[:1]
    return t32[7:] + t32[:7]


def setKey128(k128):
    """Generate round/whitening keys from 128-bit key"""
    k32 = _128To32(k128)
    for i in range(len(con128) - nrk):
        rk[i] = con128[i]
    l = gfn4(k32, 12)
    for i in range(nwk):
        wk[i] = k32[i]
    for i in range(nrk // 4):
        t32 = [r ^ s for r, s in zip(l, con128[4 * i + 24 : 4 * i + 28])]
        l = sigma(l)
        if i % 2:
            t32 = [r ^ s for r, s in zip(t32, k32)]
        rk[4 * i : 4 * i + 4] = t32


def setKey192(k192):
    """Generate round/whitening keys from 192-bit key"""
    k32 = _192To32(k192)
    kl = k32[:4]
    kr = k32[4:6] + [k32[0] ^ 0xFFFFFFFF] + [k32[1] ^ 0xFFFFFFFF]
    for i in range(len(con192) - nrk):
        rk[i] = con192[i]
    l = gfn8(kl + kr, 10)
    ll, lr = l[:4], l[4:]
    kk = [r ^ s for r, s in zip(kl, kr)]
    for i in range(nwk):
        wk[i] = kk[i]
    for i in range(nrk // 4):
        if i % 4 == 0 or i % 4 == 1:
            t32 = [r ^ s for r, s in zip(ll, con192[4 * i + 40 : 4 * i + 44])]
            ll = sigma(ll)
            if i % 2:
                t32 = [r ^ s for r, s in zip(t32, kr)]
        else:
            t32 = [r ^ s for r, s in zip(lr, con192[4 * i + 40 : 4 * i + 44])]
            lr = sigma(lr)
            if i % 2:
                t32 = [r ^ s for r, s in zip(t32, kl)]
        rk[4 * i : 4 * i + 4] = t32


def setKey256(k256):
    """Generate round/whitening keys from 256-bit key"""
    k32 = _256To32(k256)
    kl = k32[:4]
    kr = k32[4:]
    for i in range(len(con256) - nrk):
        rk[i] = con256[i]
    l = gfn8(kl + kr, 10)
    ll, lr = l[:4], l[4:]
    kk = [r ^ s for r, s in zip(kl, kr)]
    for i in range(nwk):
        wk[i] = kk[i]
    for i in range(nrk // 4):
        if i % 4 == 0 or i % 4 == 1:
            t32 = [r ^ s for r, s in zip(ll, con256[4 * i + 40 : 4 * i + 44])]
            ll = sigma(ll)
            if i % 2:
                t32 = [r ^ s for r, s in zip(t32, kr)]
        else:
            t32 = [r ^ s for r, s in zip(lr, con256[4 * i + 40 : 4 * i + 44])]
            lr = sigma(lr)
            if i % 2:
                t32 = [r ^ s for r, s in zip(t32, kl)]
        rk[4 * i : 4 * i + 4] = t32


def setKey(key, keySize):
    """Generate round/whitening keys"""
    global nr, nrk
    try:
        assert keySize in ksTable
    except AssertionError:
        print("Key size identifier not valid")
        sys.exit("ValueError")
    try:
        assert isinstance(key, int)
    except AssertionError:
        print("Invalid key")
        sys.exit("ValueError")
    try:
        assert key.bit_length() // 8 <= ksTable[keySize]
    except AssertionError:
        print("Key size mismatch")
        sys.exit("ValueError")
    nr = nrTable[keySize]
    nrk = nrkTable[keySize]
    if keySize == "SIZE_128":
        setKey128(key)
    elif keySize == "SIZE_192":
        setKey192(key)
    elif keySize == "SIZE_256":
        setKey256(key)
    else:
        sys.exit("Invalid key size identifier")


def enc(ptext):
    t32 = _128To32(ptext)
    t32[1] ^= wk[0]
    t32[3] ^= wk[1]
    t32 = gfn4(t32, nr)
    t32[1] ^= wk[2]
    t32[3] ^= wk[3]
    return _32To128(t32)


def dec(ctext):
    t32 = _128To32(ctext)
    t32[1] ^= wk[2]
    t32[3] ^= wk[3]
    t32 = gfn4i(t32, nr)
    t32[1] ^= wk[0]
    t32[3] ^= wk[1]
    return _32To128(t32)


# if __name__ == "__main__":

#     def checkTestVector(key, keySize, plaintext, ciphertext, nIter=1000):
#         testSuccess = True
#         setKey(key, keySize)
#         ks = ksTable[keySize] * 8
#         try:
#             assert enc(plaintext) == ciphertext
#         except AssertionError:
#             print("Error in encryption")
#             print("Resulted ciphertext: {:s}".format(ctext))
#             print("Expected ciphertext: {:s}".format(ciphertext))
#             testSuccess = False
#         try:
#             assert dec(enc(plaintext)) == plaintext
#         except AssertionError:
#             print("Error in decryption:")
#             print("Recovered plaintext: {:s}".format(ptext))
#             print("Expected plaintext: {:s}".format(plaintext))
#             testSuccess = False
#         if not testSuccess:
#             return False
#         t1 = time()
#         for i in range(nIter):
#             setKey(key, keySize)
#             ctext = enc(plaintext)
#         t2 = time()
#         avg_elapsed_time = (t2 - t1) * 1000 / nIter
#         print("{:3d}-bit key test ok!".format(ksTable[keySize] * 8))
#         print("Average elapsed time for 16-byte block ", end="")
#         print("ECB-{0:3d} encryption: {1:0.3f}ms".format(ks, avg_elapsed_time))
#         t3 = time()
#         for i in range(nIter):
#             setKey(key, keySize)
#             ptext = dec(ctext)
#         t4 = time()
#         avg_elapsed_time = (t4 - t3) * 1000 / nIter
#         print("{:3d}-bit key test ok!".format(ksTable[keySize] * 8))
#         print("Average elapsed time for 16-byte block ", end="")
#         print("ECB-{0:3d} decryption: {1:0.3f}ms".format(ks, avg_elapsed_time))
#         return True

#     # The test vectors below are described in document "The 128-bit Blockcipher
#     # CLEFIA Algorithm Specification" rev.1, June 1, 2007, Sony Corporation.

#     ptext = 0x000102030405060708090A0B0C0D0E0F

#     # Test vector for 128-bit key
#     key1 = 0xFFEEDDCCBBAA99887766554433221100
#     ctext1 = 0xDE2BF2FD9B74AACDF1298555459494FD

#     # Test vector for 192-bit key
#     key2 = 0xFFEEDDCCBBAA99887766554433221100F0E0D0C0B0A09080
#     ctext2 = 0xE2482F649F028DC480DDA184FDE181AD

#     # Test vector for 256-bit key
#     key3 = 0xFFEEDDCCBBAA99887766554433221100F0E0D0C0B0A090807060504030201000
#     ctext3 = 0xA1397814289DE80C10DA46D1FA48B38A

#     try:
#         assert (
#             checkTestVector(key1, "SIZE_128", ptext, ctext1)
#             and checkTestVector(key2, "SIZE_192", ptext, ctext2)
#             and checkTestVector(key3, "SIZE_256", ptext, ctext3)
#         )
#     except AssertionError:
#         print("At least one test failed")
#         sys.exit(1)
#     print("All tests passed!")
#     sys.exit()
