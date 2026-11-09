"""ML-KEM-512 (Kyber) following FIPS 203. Educational only: not constant-time."""
import hashlib
import os

from ntt import basemul, bitrev
from ntt import intt as _intt
from ntt import ntt as _ntt

Q, N, K, ETA1, ETA2, DU, DV = 3329, 256, 2, 3, 2, 10, 4
GAMMAS = [pow(17, 2 * bitrev(i, 7) + 1, Q) for i in range(128)]


def ntt(f): return _ntt(f, Q, 17, 7)
def intt(f): return _intt(f, Q, 17, 7)
def add(a, b): return [(x + y) % Q for x, y in zip(a, b)]
def sub(a, b): return [(x - y) % Q for x, y in zip(a, b)]


def dot(u, v):  # sum_i u[i] * v[i], all in NTT domain
    r = [0] * N
    for a, b in zip(u, v):
        r = add(r, basemul(a, b, Q, GAMMAS))
    return r


# ---- hash functions (FIPS 203, Sec. 4.1) ----
def G(x): h = hashlib.sha3_512(x).digest(); return h[:32], h[32:]
def H(x): return hashlib.sha3_256(x).digest()
def J(x): return hashlib.shake_256(x).digest(32)
def PRF(eta, s, b): return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def xof_stream(seed):
    n, i = 1024, 0
    while True:
        buf = hashlib.shake_128(seed).digest(n)
        while i < n:
            yield buf[i]
            i += 1
        n *= 2


# ---- sampling ----
def sample_ntt(seed):
    it, a = xof_stream(seed), []
    while len(a) < N:
        b0, b1, b2 = next(it), next(it), next(it)
        d1, d2 = b0 + 256 * (b1 % 16), b1 // 16 + 16 * b2
        if d1 < Q:
            a.append(d1)
        if d2 < Q and len(a) < N:
            a.append(d2)
    return a


def cbd(B, eta):
    x = int.from_bytes(B, "little")
    bit = lambda i: (x >> i) & 1
    return [(sum(bit(2 * i * eta + j) for j in range(eta))
             - sum(bit(2 * i * eta + eta + j) for j in range(eta))) % Q for i in range(N)]


# ---- encoding and compression ----
def encode(f, d): return sum(c << (d * i) for i, c in enumerate(f)).to_bytes(32 * d, "little")
def decode(B, d): x = int.from_bytes(B, "little"); return [(x >> (d * i)) & ((1 << d) - 1) for i in range(N)]
def compress(f, d): return [((x << d) + Q // 2) // Q % (1 << d) for x in f]
def decompress(f, d): return [(y * Q + (1 << (d - 1))) >> d for y in f]


def gen_A(rho):  # A_hat[i][j] = SampleNTT(rho || j || i)
    return [[sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]


# ---- K-PKE (the inner public-key encryption) ----
def pke_keygen(d):
    rho, sigma = G(d + bytes([K]))
    A = gen_A(rho)
    s_hat = [ntt(cbd(PRF(ETA1, sigma, i), ETA1)) for i in range(K)]
    e_hat = [ntt(cbd(PRF(ETA1, sigma, K + i), ETA1)) for i in range(K)]
    t_hat = [add(dot(A[i], s_hat), e_hat[i]) for i in range(K)]
    ek = b"".join(encode(t, 12) for t in t_hat) + rho
    dk = b"".join(encode(s, 12) for s in s_hat)
    return ek, dk


def pke_encrypt(ek, m, r):
    t_hat = [decode(ek[384 * i:384 * (i + 1)], 12) for i in range(K)]
    A = gen_A(ek[384 * K:])
    y_hat = [ntt(cbd(PRF(ETA1, r, i), ETA1)) for i in range(K)]
    e1 = [cbd(PRF(ETA2, r, K + i), ETA2) for i in range(K)]
    e2 = cbd(PRF(ETA2, r, 2 * K), ETA2)
    u = [add(intt(dot([A[j][i] for j in range(K)], y_hat)), e1[i]) for i in range(K)]  # A^T y + e1
    mu = decompress(decode(m, 1), 1)
    v = add(add(intt(dot(t_hat, y_hat)), e2), mu)                                       # t^T y + e2 + mu
    return b"".join(encode(compress(p, DU), DU) for p in u) + encode(compress(v, DV), DV)


def pke_decrypt(dk, c):
    u = [decompress(decode(c[32 * DU * i:32 * DU * (i + 1)], DU), DU) for i in range(K)]
    v = decompress(decode(c[32 * DU * K:], DV), DV)
    s_hat = [decode(dk[384 * i:384 * (i + 1)], 12) for i in range(K)]
    w = sub(v, intt(dot(s_hat, [ntt(p) for p in u])))  # v - s^T u
    return encode(compress(w, 1), 1)


# ---- ML-KEM (Fujisaki-Okamoto transform on top of K-PKE) ----
def keygen():
    d, z = os.urandom(32), os.urandom(32)
    ek, dk_pke = pke_keygen(d)
    return ek, dk_pke + ek + H(ek) + z


def encaps(ek):
    m = os.urandom(32)
    key, r = G(m + H(ek))
    return key, pke_encrypt(ek, m, r)


def decaps(dk, c):
    dk_pke, ek = dk[:384 * K], dk[384 * K:768 * K + 32]
    h, z = dk[768 * K + 32:768 * K + 64], dk[768 * K + 64:]
    m = pke_decrypt(dk_pke, c)
    key, r = G(m + h)
    return key if pke_encrypt(ek, m, r) == c else J(z + c)  # implicit rejection


if __name__ == "__main__":
    ek, dk = keygen()
    key1, c = encaps(ek)
    key2 = decaps(dk, c)
    print(f"ek {len(ek)} B, dk {len(dk)} B, ct {len(c)} B")
    assert key1 == key2, "shared keys differ"
    bad = bytes([c[0] ^ 1]) + c[1:]
    assert decaps(dk, bad) != key1, "tampered ciphertext accepted"
    print("Kyber OK, shared key:", key1.hex())
