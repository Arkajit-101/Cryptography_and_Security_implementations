import time
import os
import ChaCha20 as cc

#CPU's clock speed(GHz). Checked with:  lscpu | grep MHz
GHZ = 2.1

KEY = bytes(range(32))
NONCE = bytes.fromhex("000000090000004a00000000")


def measure(fn, args, repeat):
    """Time one call to fn(*args). Returns (seconds, cycles)."""
    start = time.perf_counter()
    for _ in range(repeat):
        fn(*args)
    sec = (time.perf_counter() - start) / repeat
    return sec, sec * GHZ * 1e9


# ============ (a) CORRECTNESS ============
print("--- correctness ---")

# 1. RFC 8439 known-answer vectors
cc._self_test()

# 2. determinism: same key, counter, nonce -> same keystream
k1 = cc.keystream_bytes(KEY, NONCE, 256, counter=1)
k2 = cc.keystream_bytes(KEY, NONCE, 256, counter=1)
print("same key/nonce/counter gives same keystream:", k1 == k2)

# 3. changing any one input changes the keystream
other_key = bytes([KEY[0] ^ 1]) + KEY[1:]          # flip 1 bit of the key
other_nonce = bytes([NONCE[0] ^ 1]) + NONCE[1:]    # flip 1 bit of the nonce
print("different key    gives different keystream:",
      cc.keystream_bytes(other_key, NONCE, 256, 1) != k1)
print("different nonce  gives different keystream:",
      cc.keystream_bytes(KEY, other_nonce, 256, 1) != k1)
print("different counter gives different keystream:",
      cc.keystream_bytes(KEY, NONCE, 256, 2) != k1)

# 4. decrypt(encrypt(m)) == m
msg = os.urandom(1000)
ct = cc.chacha20_encrypt(KEY, NONCE, msg)
print("decrypt(encrypt(m)) == m:", cc.chacha20_decrypt(KEY, NONCE, ct) == msg)

# 5. block counter chains correctly: keystream is just blocks concatenated
manual = cc.chacha20_block(KEY, 1, NONCE) + cc.chacha20_block(KEY, 2, NONCE)
print("keystream == concatenated blocks:", manual == k1[:128])


# ============ (b) COST ============
print("\n--- one 64-byte block ---")
sec, cyc = measure(cc.chacha20_block, (KEY, 1, NONCE), 300)
print(f"time   = {sec*1e6:8.2f} us")
print(f"cycles = {cyc:8.0f}")
print(f"cycles per byte = {cyc/64:.1f}")

print("\n--- encryption, by message size ---")
print(f"{'bytes':>8} {'time(ms)':>10} {'cycles':>12} {'cyc/byte':>10} {'MB/s':>8}")
for size in (64, 256, 1024, 4096, 16384):
    data = os.urandom(size)
    reps = max(3, 20000 // size)
    sec, cyc = measure(cc.chacha20_encrypt, (KEY, NONCE, data), reps)
    print(f"{size:>8} {sec*1e3:>10.3f} {cyc:>12.0f} {cyc/size:>10.1f} "
          f"{size/sec/1e6:>8.3f}")

print("\n--- where the time goes (per block) ---")
state = cc.build_state(KEY, 1, NONCE)
for name, fn, args in (
    ("quarter_round", cc.quarter_round, (1, 2, 3, 4)),
    ("double_round ", cc.double_round, (list(state),)),
    ("permute (20r)", cc.permute, (state,)),
    ("full block   ", cc.chacha20_block, (KEY, 1, NONCE)),
):
    sec, cyc = measure(fn, args, 2000 if "quarter" in name else 300)
    print(f"{name}: {sec*1e6:8.2f} us   {cyc:9.0f} cycles")
