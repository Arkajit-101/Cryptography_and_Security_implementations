# Crypto primitives in pure Python

Short, readable implementations for learning. No dependencies (Python 3.8+).

| File | What it is |
|------|------------|
| `ntt.py` | Negacyclic NTT / inverse NTT over Z_q[X]/(X^256+1), shared by Kyber and Dilithium |
| `kyber.py` | ML-KEM-512 (FIPS 203): keygen, encaps, decaps |
| `dilithium.py` | ML-DSA-44 (FIPS 204 structure): keygen, sign, verify |
| `aes128.py` | AES-128 block encrypt/decrypt (FIPS 197) |

Run any file to execute its self-test:

```
python ntt.py
python aes128.py
python kyber.py
python dilithium.py
```

`aes128.py` is checked against the FIPS 197 test vector. `kyber.py` follows FIPS 203 byte formats
(800 B ek, 1632 B dk, 768 B ciphertext) but has only been tested by round-trip, not against the official KATs.
`dilithium.py` keeps the secret key and signature as Python objects and omits the FIPS 204 context prefix,
so it will not match official KATs.

**Not for real use:** none of this is constant-time or side-channel hardened.
