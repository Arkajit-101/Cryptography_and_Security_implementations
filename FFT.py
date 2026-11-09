"""Fast Fourier Transform (recursive radix-2 Cooley-Tukey) over the complex numbers.

Same butterfly idea as ntt.py, but with complex roots of unity e^(-2*pi*i/n) instead of roots mod q.
Input length must be a power of 2.
"""
import cmath


def fft(a, invert=False):
    n = len(a)
    if n == 1:
        return list(a)
    even, odd = fft(a[0::2], invert), fft(a[1::2], invert)
    sign = 1 if invert else -1
    out = [0] * n
    for k in range(n // 2):
        t = cmath.exp(sign * 2j * cmath.pi * k / n) * odd[k]  # twiddle factor * odd part
        out[k] = even[k] + t
        out[k + n // 2] = even[k] - t
    return out


def ifft(a):
    n = len(a)
    return [x / n for x in fft(a, invert=True)]


def poly_mul(p, q):
    """Multiply integer polynomials (coefficient lists, lowest degree first) using FFT."""
    n = 1
    while n < len(p) + len(q) - 1:
        n *= 2
    P, Q = fft(p + [0] * (n - len(p))), fft(q + [0] * (n - len(q)))
    r = ifft([x * y for x, y in zip(P, Q)])
    return [round(x.real) for x in r[:len(p) + len(q) - 1]]


def dft(a):
    """Naive O(n^2) DFT, used only for testing."""
    n = len(a)
    return [sum(a[j] * cmath.exp(-2j * cmath.pi * j * k / n) for j in range(n)) for k in range(n)]


if __name__ == "__main__":
    import random

    a = [random.uniform(-1, 1) for _ in range(64)]
    assert all(abs(x - y) < 1e-9 for x, y in zip(fft(a), dft(a)))
    assert all(abs(x - y) < 1e-9 for x, y in zip(ifft(fft(a)), a))

    p, q = [random.randint(-9, 9) for _ in range(50)], [random.randint(-9, 9) for _ in range(30)]
    naive = [0] * (len(p) + len(q) - 1)
    for i, x in enumerate(p):
        for j, y in enumerate(q):
            naive[i + j] += x * y
    assert poly_mul(p, q) == naive
    print("FFT OK, (1 + 2x)(3 + 4x) =", poly_mul([1, 2], [3, 4]))
