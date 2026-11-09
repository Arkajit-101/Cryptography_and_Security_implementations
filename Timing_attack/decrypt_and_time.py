"""Victim side: decrypt every ciphertext with the SECRET key, timing each one,
and write traces.csv  (columns: ciphertext_hex, cycles, opcount).
cycles  = real CPU cycles (CPUID+RDTSC, min over reps)
opcount = count of key-dependent reduction steps (noise-free 'time')."""
import sys, subprocess
from rsa_common import read_kv
reps = int(sys.argv[1]) if len(sys.argv)>1 else 7
sk = read_kv("secret_key.txt"); pk = read_kv("public_key.txt")
n, d = pk["n"], sk["d"]
ciph = [c.strip() for c in open("ciphertexts.txt") if c.strip()]
inp = "%x %x %d\n"%(n, d, reps) + "\n".join(ciph) + "\n"
cmd = ["taskset","-c","0","./victim"]
try: res = subprocess.run(cmd, input=inp, capture_output=True, text=True)
except FileNotFoundError: res = subprocess.run(["./victim"], input=inp, capture_output=True, text=True)
rows = res.stdout.strip().split("\n")
with open("traces.csv","w") as f:
    f.write("ciphertext_hex,cycles,opcount\n")
    for r in rows: f.write(r+"\n")
print(f"timed {len(rows)} decryptions (reps={reps}) -> traces.csv")
