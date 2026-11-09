"""Key generation: choose a code, build G, scramble G' = S G P, write both keys."""
import random
from mceliece_lib import *

rng = random.SystemRandom()                  # OS randomness for keys

code = ask("Code [random / grs / rm / goppa]: ", ["random", "grs", "rm", "goppa"])
mode = ask("Parameters [default / custom]: ", ["default", "custom"])
F, sec = None, {}

if code == "random":
    if mode == "default":
        n, k, t = 1024, 524, 50
    else:
        n = ask_int("n: ", 2, 4096)
        k = ask_int("k (< n): ", 1, n - 1)
        t = ask_int("t (errors): ", 1, n)
    sec, G = make_random(n, k, t, rng)

elif code == "grs":
    if mode == "default":
        m, n, k = 8, 256, 128
    else:
        m = ask_int("m (field GF(2^m)): ", 2, 16)
        n = ask_int("n (<= 2^m): ", 2, 1 << m)
        k = ask_int("k (< n): ", 1, n - 1)
    sec, G, F = make_grs(m, n, k, rng)

elif code == "rm":
    if mode == "default":
        r, m = 4, 10
    else:
        m = ask_int("m (length 2^m): ", 2, 14)
        r = ask_int("r (degree, < m-1): ", 0, m - 2)
    sec, G = make_rm(r, m)

else:  # goppa
    if mode == "default":
        m, n, t = 10, 1024, 50
    else:
        m = ask_int("m (field GF(2^m)): ", 2, 16)
        t = ask_int("t (deg g, errors): ", 2, (1 << m) // m)
        n = ask_int("n (mt < n <= 2^m): ", m * t + 1, 1 << m)
    print("searching for an irreducible g ...")
    sec, G, F = make_goppa(m, n, t, rng)

n, k = sec["n"], sec["k"]
binary = F is None or code == "goppa"         # codewords are bits?

# S: random invertible k x k, P: random n x n permutation
perm = list(range(n)); rng.shuffle(perm)
if binary:
    while True:
        S = [rng.getrandbits(k) for _ in range(k)]
        if inverse_bits(S, k) is not None:
            break
    Gpub = [list_to_bits(apply_P(bits_to_list(row, n), perm))
            for row in mat_mul_bits(S, G)]
    S_l = [bits_to_list(x, k) for x in S]
    G_l = [bits_to_list(x, n) for x in G]
    Gp_l = [bits_to_list(x, n) for x in Gpub]
else:
    while True:
        S_l = [[rng.randrange(F.q) for _ in range(k)] for _ in range(k)]
        if inverse(F, S_l) is not None:
            break
    G_l = G
    Gp_l = [apply_P(row, perm) for row in mat_mul(F, S_l, G)]

# ---- write keys
w = 1 if binary else F.m                     # bit width of a code symbol
head = [("code", code)]
if code in ("grs", "goppa"):
    head.append(("field", F.poly_str()))
if code == "rm":
    head += [("r", sec["r"]), ("m", sec["m"])]
head += [("n", n), ("k", k), ("t", sec["t"])]

trap = []
if code == "grs":
    trap = [("alpha", sec["alpha"], F.m), ("v", sec["v"], F.m)]
if code == "goppa":
    trap = [("g (X^t..X^0)", sec["g"][::-1], F.m), ("L", sec["L"], F.m)]

write_file("secret_key.txt", head + trap +
           [("S", S_l, w), ("P", perm_to_matrix(perm), 1), ("G", G_l, w)])
write_file("public_key.txt", head + [("G_pub", Gp_l, w)])

print("code: %s  n = %d  k = %d  t = %d" % (code, n, k, sec["t"]))
print("wrote secret_key.txt, public_key.txt")
