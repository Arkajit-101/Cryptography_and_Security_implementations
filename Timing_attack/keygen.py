"""Generate or set an RSA key.
  [1] generate p,q with pycryptodome (trustworthy, standard)
  [2] enter your own p, q, e
Writes public_key.txt (n,e) and secret_key.txt (p,q,d)."""
from Crypto.Util.number import getPrime, isPrime
from math import gcd, lcm

def finish(p, q, e):
    assert p != q, "p and q must differ"
    assert isPrime(p) and isPrime(q), "p and q must be prime"
    n = p*q; lam = lcm(p-1, q-1)
    assert gcd(e, lam) == 1, "e must be coprime with lcm(p-1,q-1); pick another e"
    d = pow(e, -1, lam)
    open("public_key.txt","w").write(f"# RSA public key\nn = {n}\ne = {e}\n")
    open("secret_key.txt","w").write(f"# RSA SECRET key (attacker never reads this)\np = {p}\nq = {q}\nd = {d}\n")
    print(f"\nkey ready: modulus n is {n.bit_length()} bits, secret exponent d is {d.bit_length()} bits")
    print("wrote public_key.txt  and  secret_key.txt")

print(__doc__)
choice = input("choose [1]=generate  [2]=enter your own : ").strip()
if choice == "2":
    p = int(input("  p (prime) = ").strip())
    q = int(input("  q (prime) = ").strip())
    e = int(input("  e (e.g. 65537) = ").strip())
    finish(p, q, e)
else:
    bits = input("  prime size in bits [default 64] : ").strip()
    bits = int(bits) if bits else 64
    e = 65537
    p = getPrime(bits)
    q = getPrime(bits)
    while q == p: q = getPrime(bits)
    # ensure e coprime (retry if unlucky)
    from math import gcd as _g, lcm as _l
    while _g(e, _l(p-1,q-1)) != 1:
        q = getPrime(bits)
    finish(p, q, e)
