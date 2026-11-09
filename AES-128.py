"""AES-128 block cipher (FIPS 197), single 16-byte block. Educational only: not constant-time."""


def xtime(a): return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def gmul(a, b):  # multiplication in GF(2^8) mod x^8 + x^4 + x^3 + x + 1
    p = 0
    while b:
        if b & 1:
            p ^= a
        a, b = xtime(a), b >> 1
    return p


def build_sbox():  # S(x) = affine(x^-1)
    sbox = [0] * 256
    for x in range(256):
        b = next((y for y in range(1, 256) if gmul(x, y) == 1), 0)
        r = b
        for i in range(1, 5):
            r ^= ((b << i) | (b >> (8 - i))) & 0xFF
        sbox[x] = r ^ 0x63
    return sbox


SBOX = build_sbox()
INV_SBOX = [SBOX.index(i) for i in range(256)]
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def expand_key(key):  # 16-byte key -> 11 round keys of 16 bytes
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]  # RotWord, SubWord
            t[0] ^= RCON[i // 4 - 1]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(11)]


# state is 16 bytes, column-major: s[r + 4c]
def add_round_key(s, k): return [a ^ b for a, b in zip(s, k)]
def shift_rows(s): return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]
def inv_shift_rows(s): return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def mix(s, m):
    out = []
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        out += [gmul(m[r][0], col[0]) ^ gmul(m[r][1], col[1]) ^ gmul(m[r][2], col[2]) ^ gmul(m[r][3], col[3])
                for r in range(4)]
    return out


MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


def encrypt(key, block):
    rk = expand_key(key)
    s = add_round_key(list(block), rk[0])
    for r in range(1, 11):
        s = shift_rows([SBOX[b] for b in s])
        if r != 10:
            s = mix(s, MIX)
        s = add_round_key(s, rk[r])
    return bytes(s)


def decrypt(key, block):
    rk = expand_key(key)
    s = add_round_key(list(block), rk[10])
    for r in range(9, -1, -1):
        s = [INV_SBOX[b] for b in inv_shift_rows(s)]
        s = add_round_key(s, rk[r])
        if r != 0:
            s = mix(s, INV_MIX)
    return bytes(s)


if __name__ == "__main__":  # FIPS 197, Appendix C.1
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = encrypt(key, pt)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert decrypt(key, ct) == pt
    print("AES-128 OK:", ct.hex())
