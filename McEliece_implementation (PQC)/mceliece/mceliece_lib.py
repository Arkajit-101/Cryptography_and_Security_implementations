"""Shared code: GF(2^m), polynomials, matrices, the four codes, file I/O."""
import os, random
from itertools import combinations
from math import comb

BASE = os.path.dirname(os.path.abspath(__file__))
FILES = ["secret_key.txt", "public_key.txt", "msg_n_error.txt",
         "ciphertext.txt", "decrypted_Message.txt"]
def path(name): return os.path.join(BASE, name)

# ---------------------------------------------------------------- GF(2^m)
# Primitive polynomials, as bit masks (bit i = coefficient of x^i).
PRIM = {1: 0b11, 2: 0b111, 3: 0b1011, 4: 0b10011, 5: 0b100101, 6: 0b1000011,
        7: 0b10001001, 8: 0b100011101, 9: 0b1000010001, 10: 0b10000001001,
        11: 0b100000000101, 12: 0b1000001010011, 13: 0b10000000011011,
        14: 0b100010001000011, 15: 0b1000000000000011, 16: 0b10001000000001011}

class GF:
    """GF(2^m) = F2[x]/(p(x)). Elements are ints whose bits are coefficients.
    Addition is XOR; multiplication uses log/antilog tables."""
    def __init__(self, m):
        self.m, self.q, self.poly = m, 1 << m, PRIM[m]
        self.exp, self.log = [0] * (2 * self.q), [0] * self.q
        x = 1
        for i in range(self.q - 1):
            self.exp[i], self.log[x] = x, i
            x <<= 1
            if x >> m:
                x ^= self.poly
        for i in range(self.q - 1, 2 * self.q):
            self.exp[i] = self.exp[i - (self.q - 1)]

    def mul(self, a, b):
        return 0 if a == 0 or b == 0 else self.exp[self.log[a] + self.log[b]]

    def inv(self, a):
        return self.exp[(self.q - 1 - self.log[a]) % (self.q - 1)]

    def poly_str(self):                      # e.g. "x^10+x^3+1"
        terms = [("x^%d" % i if i > 1 else "x" if i == 1 else "1")
                 for i in range(self.m, -1, -1) if self.poly >> i & 1]
        return "+".join(terms)

def gf_from_str(s):
    m = max(int(t[2:]) if t.startswith("x^") else (1 if t == "x" else 0)
            for t in s.split("+"))
    F = GF(m)
    assert F.poly_str() == s, "unknown field polynomial"
    return F

# ------------------------------------------- polynomials over GF(2^m)
# A polynomial is a list of coefficients, lowest degree first: [c0, c1, ...].
def deg(p):
    for i in range(len(p) - 1, -1, -1):
        if p[i]:
            return i
    return -1

def trim(p):
    return p[:deg(p) + 1] or [0]

def p_add(a, b):
    if len(a) < len(b):
        a, b = b, a
    r = a[:]
    for i, c in enumerate(b):
        r[i] ^= c
    return trim(r)

def p_mul(F, a, b):
    r = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                if y:
                    r[i + j] ^= F.mul(x, y)
    return trim(r)

def p_divmod(F, a, b):
    a, db = trim(a)[:], deg(b)
    inv_lead = F.inv(b[db])
    q = [0] * max(len(a) - db, 1)
    for i in range(deg(a), db - 1, -1):
        if a[i]:
            c = F.mul(a[i], inv_lead)
            q[i - db] = c
            for j in range(db + 1):
                if b[j]:
                    a[i - db + j] ^= F.mul(c, b[j])
    return trim(q), trim(a)

def p_mod(F, a, b):
    return p_divmod(F, a, b)[1]

def p_eval(F, p, x):                         # Horner
    r = 0
    for c in reversed(p):
        r = F.mul(r, x) ^ c
    return r

def p_sqr(F, a):                             # char 2: (sum c_i X^i)^2 = sum c_i^2 X^2i
    r = [0] * (2 * len(a) - 1)
    for i, c in enumerate(a):
        r[2 * i] = F.mul(c, c)
    return trim(r)

def p_gcd(F, a, b):
    while deg(b) >= 0:
        a, b = b, p_mod(F, a, b)
    return a

def p_inv_mod(F, a, g):
    """Extended Euclid: returns u with u*a = 1 mod g."""
    r0, r1, u0, u1 = g, p_mod(F, a, g), [0], [1]
    while deg(r1) > 0:
        q, r = p_divmod(F, r0, r1)
        r0, r1, u0, u1 = r1, r, u1, p_add(u0, p_mul(F, q, u1))
    assert deg(r1) == 0, "not invertible"
    return p_mul(F, u1, [F.inv(r1[0])])

def is_irreducible(F, g):
    """Ben-Or test: g of degree t is irreducible iff gcd(g, X^(q^i) - X) = 1
    for i = 1..t/2 (no factor of degree <= t/2)."""
    h = [0, 1]
    for _ in range(deg(g) // 2):
        for _ in range(F.m):                 # h <- h^q (q = 2^m: m squarings)
            h = p_mod(F, p_sqr(F, h), g)
        if deg(p_gcd(F, g, p_add(h, [0, 1]))) > 0:
            return False
    return True

# ----------------------------------------------- binary matrices
# A binary row is an int: bit j = column j. Matrices are lists of such ints.
def bits_to_list(x, n): return [(x >> j) & 1 for j in range(n)]
def list_to_bits(v): return sum(b << j for j, b in enumerate(v))

def rref_bits(rows, ncols):
    rows, piv, r = rows[:], [], 0
    for c in range(ncols):
        p = next((i for i in range(r, len(rows)) if rows[i] >> c & 1), None)
        if p is None:
            continue
        rows[r], rows[p] = rows[p], rows[r]
        for i in range(len(rows)):
            if i != r and rows[i] >> c & 1:
                rows[i] ^= rows[r]
        piv.append(c)
        r += 1
        if r == len(rows):
            break
    return rows[:r], piv

def kernel_bits(rows, n):
    """Basis of {x : A x^T = 0}."""
    R, piv = rref_bits(rows, n)
    basis = []
    for f in (c for c in range(n) if c not in set(piv)):
        v = 1 << f
        for row, p in zip(R, piv):
            if row >> f & 1:
                v |= 1 << p
        basis.append(v)
    return basis

def inverse_bits(A, k):
    aug = [A[i] | (1 << (k + i)) for i in range(k)]
    R, piv = rref_bits(aug, k)
    if len(piv) < k:
        return None
    return [row >> k for row in R]

def mat_mul_bits(A, B):
    out = []
    for a in A:
        r, j = 0, 0
        while a:
            if a & 1:
                r ^= B[j]
            a >>= 1
            j += 1
        out.append(r)
    return out

def solve_left_bits(G, c, n):
    """Find u with u*G = c."""
    k = len(G)
    aug = [G[i] | (1 << (n + i)) for i in range(k)]
    R, piv = rref_bits(aug, n)
    for row, p in zip(R, piv):
        if c >> p & 1:
            c ^= row
    assert c & ((1 << n) - 1) == 0, "not a codeword"
    return bits_to_list(c >> n, k)

# ----------------------------------------------- matrices over GF(2^m)
def mat_mul(F, A, B):
    out = []
    for a in A:
        r = [0] * len(B[0])
        for x, brow in zip(a, B):
            if x:
                for j, y in enumerate(brow):
                    if y:
                        r[j] ^= F.mul(x, y)
        out.append(r)
    return out

def inverse(F, A):
    k = len(A)
    M = [A[i][:] + [int(i == j) for j in range(k)] for i in range(k)]
    for c in range(k):
        p = next((i for i in range(c, k) if M[i][c]), None)
        if p is None:
            return None
        M[c], M[p] = M[p], M[c]
        iv = F.inv(M[c][c])
        M[c] = [F.mul(iv, x) for x in M[c]]
        for i in range(k):
            if i != c and M[i][c]:
                f = M[i][c]
                M[i] = [x ^ F.mul(f, y) for x, y in zip(M[i], M[c])]
    return [row[k:] for row in M]

def vec_mat(F, v, A):
    return mat_mul(F, [v], A)[0]

# ---------------------------------------------------- permutations
# P is the n x n matrix with P[i][perm[i]] = 1, so (vP)[perm[i]] = v[i].
def perm_to_matrix(perm):
    n = len(perm)
    return [[int(j == perm[i]) for j in range(n)] for i in range(n)]

def matrix_to_perm(P):
    return [row.index(1) for row in P]

def apply_P(v, perm):                        # v -> vP
    out = [0] * len(v)
    for i, x in enumerate(v):
        out[perm[i]] = x
    return out

def apply_P_inv(v, perm):                    # v -> vP^-1
    return [v[perm[i]] for i in range(len(v))]

# =========================================================== CODES
# Each make_* returns (secret dict, G as list-of-lists, F).
# Each decode_* takes the codeword-with-errors y (list) and returns u' = mS.

# ---- random binary linear code ------------------------------------
def make_random(n, k, t, rng):
    while True:
        G = [rng.getrandbits(n) for _ in range(k)]
        if len(rref_bits(G, n)[1]) == k:
            break
    return {"n": n, "k": k, "t": t}, G

BRUTE_LIMIT = 2_000_000

def decode_random(G, n, t, y):
    """No trapdoor: search all error patterns of weight <= t."""
    work = sum(comb(n, w) for w in range(t + 1))
    if work > BRUTE_LIMIT:
        raise RuntimeError(
            "Random linear code: no efficient decoder. Brute force needs "
            "~%.2e syndrome checks (limit %d). Use custom small n, t."
            % (work, BRUTE_LIMIT))
    H = kernel_bits(G, n)                    # rows of a parity-check matrix
    col = [sum(((h >> i) & 1) << r for r, h in enumerate(H)) for i in range(n)]
    s = 0
    for i, yi in enumerate(y):
        if yi:
            s ^= col[i]
    for w in range(t + 1):
        for pos in combinations(range(n), w):
            acc = 0
            for i in pos:
                acc ^= col[i]
            if acc == s:
                e = sum(1 << i for i in pos)
                return solve_left_bits(G, list_to_bits(y) ^ e, n)
    raise RuntimeError("no error pattern of weight <= t found")

# ---- Generalized Reed-Solomon over GF(2^m) -----------------------
def make_grs(m, n, k, rng):
    F = GF(m)
    alpha = rng.sample(range(F.q), n)        # distinct evaluation points
    v = [rng.randrange(1, F.q) for _ in range(n)]   # nonzero multipliers
    G, row = [], [1] * n                     # row j: v_i * alpha_i^j
    for _ in range(k):
        G.append([F.mul(vi, r) for vi, r in zip(v, row)])
        row = [F.mul(r, a) for r, a in zip(row, alpha)]
    return {"n": n, "k": k, "t": (n - k) // 2, "alpha": alpha, "v": v}, G, F

def decode_grs(F, alpha, v, k, y):
    """Gao's decoder: interpolate, then run Euclid until deg < (n+k)/2."""
    n = len(y)
    r = [F.mul(yi, F.inv(vi)) for yi, vi in zip(y, v)]   # undo multipliers
    g0 = [1]
    for a in alpha:
        g0 = p_mul(F, g0, [a, 1])            # prod (X - a)
    dg0 = [g0[i] if i % 2 else 0 for i in range(1, len(g0))]  # derivative
    g1 = [0]
    for a, ri in zip(alpha, r):              # Lagrange interpolation
        if ri:
            q, _ = p_divmod(F, g0, [a, 1])   # g0 / (X - a)
            c = F.mul(ri, F.inv(p_eval(F, dg0, a)))
            g1 = p_add(g1, p_mul(F, q, [c]))
    r0, r1, s0, s1 = g0, g1, [0], [1]
    while 2 * deg(r1) >= n + k:
        q, rem = p_divmod(F, r0, r1)
        r0, r1, s0, s1 = r1, rem, s1, p_add(s0, p_mul(F, q, s1))
    f, rem = p_divmod(F, r1, s1)
    if deg(rem) >= 0 or deg(f) >= k:
        raise RuntimeError("too many errors")
    return f + [0] * (k - len(f))

# ---- binary Reed-Muller RM(r, m) ----------------------------------
# Position i <-> point x in F2^m with x_j = bit j of i.
# Message coordinate <-> monomial x_A = prod_{j in A} x_j, |A| <= r.
def rm_monomials(r, m):
    return [A for d in range(r + 1) for A in combinations(range(m), d)]

def rm_row(A, m):
    mask = sum(1 << j for j in A)
    return sum(1 << i for i in range(1 << m) if i & mask == mask)

def make_rm(r, m):
    n = 1 << m
    G = [rm_row(A, m) for A in rm_monomials(r, m)]
    return {"r": r, "m": m, "n": n, "k": len(G),
            "t": (1 << (m - r - 1)) - 1}, G

def decode_rm(r, m, y):
    """Reed's majority-logic decoder, highest degree first."""
    monos = rm_monomials(r, m)
    y, coef = y[:], {}
    for d in range(r, -1, -1):
        level = [A for A in monos if len(A) == d]
        for A in level:
            subs = [sum(((s >> b) & 1) << j for b, j in enumerate(A))
                    for s in range(1 << d)]          # all x_A values
            comp = [j for j in range(m) if j not in A]
            votes = 0
            for s in range(1 << len(comp)):          # fix the other variables
                base = sum(((s >> b) & 1) << j for b, j in enumerate(comp))
                bit = 0
                for o in subs:
                    bit ^= y[base | o]
                votes += bit
            coef[A] = int(2 * votes > (1 << len(comp)))
        for A in level:                              # remove decided terms
            if coef[A]:
                mask = sum(1 << j for j in A)
                for i in range(1 << m):
                    if i & mask == mask:
                        y[i] ^= 1
    return [coef[A] for A in monos]

# ---- binary Goppa -------------------------------------------------
def inv_linear(F, g, a):
    """(X - a)^-1 mod g = g(a)^-1 * (g(X) - g(a)) / (X - a)."""
    t = deg(g)
    q = [0] * t
    q[t - 1] = g[t]
    for j in range(t - 1, 0, -1):            # synthetic division
        q[j - 1] = g[j] ^ F.mul(a, q[j])
    ga = g[0] ^ F.mul(a, q[0])
    return p_mul(F, q, [F.inv(ga)])

def make_goppa(m, n, t, rng):
    F = GF(m)
    while True:                              # random monic irreducible g
        g = [rng.randrange(F.q) for _ in range(t)] + [1]
        if is_irreducible(F, g):
            break
    L = rng.sample(range(F.q), n)            # support (g has no roots in F)
    Hbin = []                                # row j: alpha_i^j / g(alpha_i), as m bit-rows
    cols = [F.inv(p_eval(F, g, a)) for a in L]
    for _ in range(t):
        for b in range(m):
            Hbin.append(sum(((c >> b) & 1) << i for i, c in enumerate(cols)))
        cols = [F.mul(c, a) for c, a in zip(cols, L)]
    G = kernel_bits(Hbin, n)
    return {"n": n, "k": len(G), "t": t, "g": g, "L": L}, G, F

def decode_goppa(F, g, L, y):
    """Patterson's algorithm. Returns the corrected codeword (list of bits)."""
    t = deg(g)
    S = [0]
    for yi, a in zip(y, L):                  # syndrome sum y_i / (X - a_i) mod g
        if yi:
            S = p_add(S, inv_linear(F, g, a))
    if deg(S) < 0:
        return y[:]
    T = p_inv_mod(F, S, g)
    if T == [0, 1]:
        sigma = [0, 1]
    else:
        tau = p_add(T, [0, 1])               # sqrt in GF(2^mt): raise to 2^(mt-1)
        for _ in range(F.m * t - 1):
            tau = p_mod(F, p_sqr(F, tau), g)
        r0, r1, b0, b1 = g, tau, [0], [1]    # find a = b*tau, deg a <= t/2
        while deg(r1) > t // 2:
            q, rem = p_divmod(F, r0, r1)
            r0, r1, b0, b1 = r1, rem, b1, p_add(b0, p_mul(F, q, b1))
        sigma = p_add(p_sqr(F, r1), p_mul(F, [0, 1], p_sqr(F, b1)))
    return [yi ^ (p_eval(F, sigma, a) == 0) for yi, a in zip(y, L)]

# ============================================================ FILE I/O
def fmt_elem(x, m):
    return str(x) if m <= 1 else format(x, "0%db" % m)

def write_file(name, items, m=1):
    """items: (key, value) or (key, value, width). value: str/int, vector, or matrix.
    Entries are printed as width-bit strings (width 1 = plain 0/1)."""
    out = []
    for item in items:
        key, val = item[0], item[1]
        w = item[2] if len(item) == 3 else m
        if isinstance(val, list) and out and out[-1]:
            out.append("")                   # blank line before each block
        if isinstance(val, list) and val and isinstance(val[0], list):
            out.append(key + ":")
            out += [" ".join(fmt_elem(x, w) for x in row) for row in val]
        elif isinstance(val, list):
            out.append(key + ":")
            out.append(" ".join(fmt_elem(x, w) for x in val))
        else:
            out.append("%s: %s" % (key, val))
            continue
        out.append("")
    with open(path(name), "w") as f:
        f.write("\n".join(out))

def read_file(name):
    """Returns dict: scalars as int/str, vectors as list, matrices as list of lists."""
    d, key, rows = {}, None, []
    def close():
        if key is not None:
            d[key] = rows[0] if len(rows) == 1 else rows
    with open(path(name)) as f:
        for line in f:
            line = line.strip()
            if not line:
                close(); key, rows = None, []
            elif key is None and line.endswith(":"):
                key, rows = line[:-1], []
            elif key is None:
                k, v = line.split(":", 1)
                v = v.strip()
                d[k] = int(v) if v.isdigit() else v
            else:
                rows.append([int(tok, 2) for tok in line.split()])
    close()
    return d

def as_matrix(x):
    """A 1-row matrix is read back as a vector; wrap it again."""
    return x if x and isinstance(x[0], list) else [x]

def ask(prompt, choices=None, default=None):
    while True:
        s = input(prompt).strip().lower()
        if not s and default is not None:
            return default
        if choices is None or s in choices:
            return s
        print("  choose one of:", ", ".join(choices))

def ask_int(prompt, lo, hi):
    while True:
        try:
            v = int(input(prompt))
            if lo <= v <= hi:
                return v
        except ValueError:
            pass
        print("  enter an integer in [%d, %d]" % (lo, hi))
