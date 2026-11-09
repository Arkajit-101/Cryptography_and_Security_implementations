"""Decrypt: y = c P^-1, decode y to u' = m S, then m = u' S^-1."""
import os
from mceliece_lib import *

sec = read_file("secret_key.txt")
c = read_file("ciphertext.txt")["c"]
code, n, k, t = sec["code"], sec["n"], sec["k"], sec["t"]
perm = matrix_to_perm(as_matrix(sec["P"]))
S, G = as_matrix(sec["S"]), as_matrix(sec["G"])

y = apply_P_inv(c, perm)                     # y = (mS) G + e P^-1

try:
    if code == "grs":
        F = gf_from_str(sec["field"])
        u = decode_grs(F, sec["alpha"], sec["v"], k, y)
        m = vec_mat(F, u, inverse(F, S))
    else:
        Gb = [list_to_bits(row) for row in G]
        if code == "random":
            u = decode_random(Gb, n, t, y)
        elif code == "rm":
            u = decode_rm(sec["r"], sec["m"], y)
        else:
            F = gf_from_str(sec["field"])
            g = sec["g (X^t..X^0)"][::-1]
            cw = decode_goppa(F, g, sec["L"], y)
            u = solve_left_bits(Gb, list_to_bits(cw), n)
        Sinv = inverse_bits([list_to_bits(r) for r in S], k)
        m = [sum(u[i] & (Sinv[i] >> j & 1) for i in range(k)) % 2 for j in range(k)]
        F = GF(1)
except RuntimeError as err:
    print("decryption failed:", err)
    raise SystemExit(1)

write_file("decrypted_Message.txt", [("message", m)], F.m)
print("wrote decrypted_Message.txt")
if os.path.exists(path("msg_n_error.txt")):
    ok = read_file("msg_n_error.txt")["message"] == m
    print("matches original message:", "yes" if ok else "NO")
