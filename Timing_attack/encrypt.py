"""Encrypt each line of messages.txt with the RSA PUBLIC key -> ciphertexts.txt.
(Public-key step; nothing secret here.)"""
from Crypto.Util.number import bytes_to_long
from rsa_common import read_kv
pk = read_kv("public_key.txt"); n, e = pk["n"], pk["e"]
out=[]
for line in open("messages.txt"):
    line=line.rstrip("\n")
    if not line: continue
    m = bytes_to_long(line.encode()) % n          # map message into [0,n)
    if m == 0: m = 1
    c = pow(m, e, n)                               # RSA encryption
    out.append(c)
with open("ciphertexts.txt","w") as f:
    for c in out: f.write("%x\n"%c)
print(f"encrypted {len(out)} messages -> ciphertexts.txt")
