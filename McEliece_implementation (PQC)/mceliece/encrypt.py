"""Encrypt: c = m G_pub + e."""
from mceliece_lib import *

pub = read_file("public_key.txt")
me = read_file("msg_n_error.txt")
F = gf_from_str(pub["field"]) if pub["code"] == "grs" else GF(1)

c = vec_mat(F, me["message"], as_matrix(pub["G_pub"]))
c = [x ^ y for x, y in zip(c, me["error"])]

write_file("ciphertext.txt", [("c", c)], F.m)
print("wrote ciphertext.txt")
