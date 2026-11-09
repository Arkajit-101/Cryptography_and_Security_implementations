"""Pick a random message m in F_q^k and an error e of weight exactly t."""
import random
from mceliece_lib import *

pub = read_file("public_key.txt")
n, k, t = pub["n"], pub["k"], pub["t"]
F = gf_from_str(pub["field"]) if pub["code"] == "grs" else None
q, w = (F.q, F.m) if F else (2, 1)

# separate generators, so the message and error never share a random state
rng_m = random.Random(ask_int("seed for message: ", 0, 2**63))
rng_e = random.Random(ask_int("seed for error:   ", 0, 2**63))

msg = [rng_m.randrange(q) for _ in range(k)]
e = [0] * n
for i in rng_e.sample(range(n), t):
    e[i] = rng_e.randrange(1, q)             # nonzero symbol

write_file("msg_n_error.txt", [("message", msg), ("error", e)], w)
print("message in F_%d^%d, error weight %d -> msg_n_error.txt" % (q, k, t))
