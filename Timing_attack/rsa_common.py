"""Shared helpers: the SAME variable-time modular reduction the C victim uses,
so the attacker can predict operation counts without knowing the key."""
def reduce_corr(P, N):
    """P mod N via base-2^16 long division. Returns (remainder, #corrections).
    #corrections = data-dependent work = the timing signal. Mirrors victim.c."""
    if P < N: return P, 0
    def nl(x):
        n=0
        while x: n+=1; x>>=16
        return max(n,1)
    Rn=nl(P); Nn=nl(N); corr=0; top=N>>((Nn-1)*16); R=P
    for j in range(Rn-Nn, -1, -1):
        hi=(R>>((j+Nn-1)*16))&0xFFFFFFFF
        q=min(hi//top, 65535)
        t=(N*q)<<(j*16); sh=N<<(j*16)
        while t>R: t-=sh; corr+=1
        R-=t
        while R>=sh: R-=sh; corr+=1
    return R, corr

def modexp_count(y, d, N):
    """y^d mod N; returns (result, total corrections). Square-and-multiply."""
    s=1; tot=0
    for k in range(d.bit_length()-1, -1, -1):
        s,c=reduce_corr(s*s, N); tot+=c
        if (d>>k)&1:
            s,c=reduce_corr(s*y, N); tot+=c
    return s, tot

def read_kv(path):
    d={}
    for line in open(path):
        line=line.strip()
        if line and not line.startswith("#"):
            k,v=line.split("=",1); d[k.strip()]=int(v.strip())
    return d
