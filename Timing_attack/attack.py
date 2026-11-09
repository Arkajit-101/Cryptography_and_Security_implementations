"""Attacker side: using ONLY the public modulus n and traces.csv (ciphertexts +
their timings), reconstruct the secret exponent d one bit at a time with
Kocher's variance test. Runs on both timing columns and reports each.
(The secret key file is read ONLY to check the answer and to bound the bit
length -- the recovery itself uses just n and the timings.)"""
import csv
from rsa_common import read_kv, reduce_corr
n = read_kv("public_key.txt")["n"]
dtrue = read_kv("secret_key.txt")["d"]; w = dtrue.bit_length()
cips=[]; cyc=[]; opc=[]
for row in csv.DictReader(open("traces.csv")):
    cips.append(int(row["ciphertext_hex"],16)); cyc.append(float(row["cycles"])); opc.append(float(row["opcount"]))
Ns=len(cips)
def variance(xs):
    m=sum(xs)/len(xs); return sum((v-m)**2 for v in xs)/len(xs)
def recover(T):
    s=[1]*Ns; rem=list(T); bits=[1]                       # d's top bit is 1
    for i,y in enumerate(cips):
        r,_=reduce_corr(s[i]*s[i],n); s[i]=r; r,_=reduce_corr(s[i]*y,n); s[i]=r
    for _ in range(w-1):
        ssq=[0]*Ns; csq=[0]*Ns; cmul=[0]*Ns
        for i,y in enumerate(cips):
            r,csq[i]=reduce_corr(s[i]*s[i],n); ssq[i]=r     # square (always)
            _,cmul[i]=reduce_corr(ssq[i]*y,n)               # multiply (if bit=1)
        v0=variance([rem[i]-csq[i] for i in range(Ns)])
        v1=variance([rem[i]-csq[i]-cmul[i] for i in range(Ns)])
        g=0 if v0<v1 else 1
        bits.append(g)
        for i,y in enumerate(cips):
            s[i]=ssq[i]; rem[i]-=csq[i]
            if g:
                r,_=reduce_corr(s[i]*y,n); s[i]=r; rem[i]-=cmul[i]
    dd=0
    for b in bits: dd=(dd<<1)|b
    return dd
print(f"{Ns} timing samples, modulus {n.bit_length()} bits, exponent {w} bits\n")
for label, T in (("REAL cycles", cyc), ("opcount (noise-free)", opc)):
    dd=recover(T)
    acc=sum(((dd>>b)&1)==((dtrue>>b)&1) for b in range(w))/w
    print(f"[{label:22}] recovered d == secret d : {dd==dtrue}    (per-bit {acc:.1%})")
    if dd==dtrue:
        open("recovered_key.txt","w").write(f"# recovered via {label}\nd = {dd}\n")
        print(f"{'':24} wrote recovered_key.txt")
