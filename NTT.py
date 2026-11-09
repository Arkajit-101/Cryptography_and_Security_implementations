"""Number Theoretic Transform over Z_q[X]/(X^n + 1), as used in FIPS 203 (Kyber) and FIPS 204 (Dilithium).

Kyber : q = 3329,    zeta = 17,   7 layers (incomplete NTT, leaves 128 degree-1 pieces)
Dilithium : q = 8380417, zeta = 1753, 8 layers (complete NTT, 256 scalars)
"""


def bitrev(x, bits):
    return int(format(x, f"0{bits}b")[::-1], 2)


def ntt(f, q, zeta, layers):
    f = [x % q for x in f]
    n, k, length = len(f), 1, len(f) // 2
    for _ in range(layers):
        for start in range(0, n, 2 * length):
            z = pow(zeta, bitrev(k, layers), q)
            k += 1
            for j in range(start, start + length):
                t = z * f[j + length] % q
                f[j + length] = (f[j] - t) % q
                f[j] = (f[j] + t) % q
        length //= 2
    return f


def intt(f, q, zeta, layers):
    f = list(f)
    n, k, length = len(f), 2 ** layers - 1, len(f) >> layers
    for _ in range(layers):
        for start in range(0, n, 2 * length):
            z = pow(zeta, bitrev(k, layers), q)
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % q
                f[j + length] = z * (f[j + length] - t) % q
        length *= 2
    inv = pow(2 ** layers, -1, q)
    return [x * inv % q for x in f]


def basemul(a, b, q, gammas):
    """Multiply in Kyber's NTT domain: 128 products in Z_q[X]/(X^2 - gamma_i)."""
    c = [0] * len(a)
    for i, g in enumerate(gammas):
        a0, a1, b0, b1 = a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1]
        c[2 * i] = (a0 * b0 + a1 * b1 * g) % q
        c[2 * i + 1] = (a0 * b1 + a1 * b0) % q
    return c


def schoolbook(a, b, q):
    """Reference negacyclic product, used only for testing."""
    n, c = len(a), [0] * len(a)
    for i in range(n):
        for j in range(n):
            if i + j < n:
                c[i + j] += a[i] * b[j]
            else:
                c[i + j - n] -= a[i] * b[j]
    return [x % q for x in c]


if __name__ == "__main__":
    import random

    # Kyber
    q = 3329
    a, b = [random.randrange(q) for _ in range(256)], [random.randrange(q) for _ in range(256)]
    gammas = [pow(17, 2 * bitrev(i, 7) + 1, q) for i in range(128)]
    assert intt(ntt(a, q, 17, 7), q, 17, 7) == a
    assert intt(basemul(ntt(a, q, 17, 7), ntt(b, q, 17, 7), q, gammas), q, 17, 7) == schoolbook(a, b, q)

    # Dilithium
    q = 8380417
    a, b = [random.randrange(q) for _ in range(256)], [random.randrange(q) for _ in range(256)]
    A, B = ntt(a, q, 1753, 8), ntt(b, q, 1753, 8)
    assert intt([x * y % q for x, y in zip(A, B)], q, 1753, 8) == schoolbook(a, b, q)
    print("NTT OK (Kyber and Dilithium parameters)")
