#CONFIGURATION and SETUP

MASK32 = 0xFFFFFFFF
WORD_BYTES = 4
STATE_WORDS = 16
BLOCK_BYTES = STATE_WORDS * WORD_BYTES          # 64
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"
ROUNDS = 20


# ---------------------------------------------------------------------------
# Layer 0 — 32-bit word arithmetic
# ---------------------------------------------------------------------------

def add32(x, y):
    """Addition modulo 2**32."""
    return (x + y) & MASK32


def xor32(x, y):
    """Bitwise XOR of two 32-bit words (mask kept for hygiene)."""
    return (x ^ y) & MASK32


def rotl32(x, n):
    """Rotate a 32-bit word left by n bits.

    Bits shifted off the top re-enter at the bottom; the mask discards the
    overflow of the left shift before the two halves are recombined.
    """
    x &= MASK32
    n &= 31
    return ((x << n) & MASK32) | (x >> (32 - n))


# ---------------------------------------------------------------------------
# Layer 1 — the quarter round (the ARX core)
# ---------------------------------------------------------------------------

def quarter_round(a, b, c, d):
    """The ChaCha quarter round on four words; returns the new (a, b, c, d).

    Four times: add, xor, rotate — with rotation constants 16, 12, 8, 7.
    """
    a = add32(a, b); d = xor32(d, a); d = rotl32(d, 16)
    c = add32(c, d); b = xor32(b, c); b = rotl32(b, 12)
    a = add32(a, b); d = xor32(d, a); d = rotl32(d, 8)
    c = add32(c, d); b = xor32(b, c); b = rotl32(b, 7)
    return a, b, c, d


def quarter_round_state(state, i, j, k, l):
    """Apply quarter_round in place to the four indexed words of the state."""
    state[i], state[j], state[k], state[l] = quarter_round(
        state[i], state[j], state[k], state[l]
    )


# ---------------------------------------------------------------------------
# Layer 2 — rounds over the 4x4 state
# ---------------------------------------------------------------------------

def column_round(state):
    """Odd round: four quarter rounds down the four columns."""
    quarter_round_state(state, 0, 4, 8, 12)
    quarter_round_state(state, 1, 5, 9, 13)
    quarter_round_state(state, 2, 6, 10, 14)
    quarter_round_state(state, 3, 7, 11, 15)
    return state


def diagonal_round(state):
    """Even round: four quarter rounds along the four diagonals."""
    quarter_round_state(state, 0, 5, 10, 15)
    quarter_round_state(state, 1, 6, 11, 12)
    quarter_round_state(state, 2, 7, 8, 13)
    quarter_round_state(state, 3, 4, 9, 14)
    return state


def double_round(state):
    """One column round followed by one diagonal round (= 2 of the 20)."""
    return diagonal_round(column_round(state))


# ---------------------------------------------------------------------------
# Layer 3 — state construction and serialisation
# ---------------------------------------------------------------------------

def bytes_to_words_le(data):
    """Little-endian 4-byte groups -> list of 32-bit words."""
    if len(data) % WORD_BYTES:
        raise ValueError("length must be a multiple of 4")
    return [int.from_bytes(data[i:i + WORD_BYTES], "little")
            for i in range(0, len(data), WORD_BYTES)]


def words_to_bytes_le(words):
    """List of 32-bit words -> little-endian byte string."""
    return b"".join(w.to_bytes(WORD_BYTES, "little") for w in words)


def build_state(key, counter, nonce):
    """Assemble the 16-word initial state.

        words  0.. 3 : the four sigma constants
        words  4..11 : the 256-bit key
        word      12 : the 32-bit block counter
        words 13..15 : the 96-bit nonce
    """
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if not 0 <= counter <= MASK32:
        raise ValueError("counter must fit in 32 bits")
    return list(CONSTANTS) + bytes_to_words_le(key) + [counter] + bytes_to_words_le(nonce)


# ---------------------------------------------------------------------------
# Layer 4 — the block function
# ---------------------------------------------------------------------------

def permute(state):
    """Run the 20 rounds (10 double rounds) on a *copy* of the state."""
    working = list(state)
    for _ in range(ROUNDS // 2):
        double_round(working)
    return working


def feed_forward(initial, permuted):
    """Word-wise addition of the original state into the permuted one.

    This is what makes the block function non-invertible; without it the
    permutation alone would leak the key by running the rounds backwards.
    """
    return [add32(x, y) for x, y in zip(initial, permuted)]


def chacha20_block(key, counter, nonce):
    """Produce one 64-byte keystream block."""
    initial = build_state(key, counter, nonce)
    permuted = permute(initial)
    return words_to_bytes_le(feed_forward(initial, permuted))


# ---------------------------------------------------------------------------
# Layer 5 — keystream and the stream cipher
# ---------------------------------------------------------------------------

def keystream_bytes(key, nonce, length, counter=1):
    """Concatenate as many blocks as needed, then truncate to `length`."""
    out = bytearray()
    block_index = counter
    while len(out) < length:
        out += chacha20_block(key, block_index, nonce)
        block_index = (block_index + 1) & MASK32
    return bytes(out[:length])


def xor_bytes(a, b):
    """Byte-wise XOR of two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def chacha20_encrypt(key, nonce, plaintext, counter=1):
    """Encrypt (or decrypt — the operation is its own inverse)."""
    return xor_bytes(plaintext, keystream_bytes(key, nonce, len(plaintext), counter))


chacha20_decrypt = chacha20_encrypt


# ---------------------------------------------------------------------------
# Self-test against the RFC 8439 vectors
# ---------------------------------------------------------------------------

def _self_test():
    # 2.1.1 — single quarter round
    assert quarter_round(0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567) == \
        (0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB)

    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")

    # 2.3.2 — block function output for counter = 1
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    assert chacha20_block(key, 1, nonce) == expected

    # 2.4.2 — full encryption
    plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
                 b"only one tip for the future, sunscreen would be it.")
    nonce_2 = bytes.fromhex("000000000000004a00000000")
    ciphertext = chacha20_encrypt(key, nonce_2, plaintext, counter=1)
    assert ciphertext[:8] == bytes.fromhex("6e2e359a2568f980")
    assert chacha20_decrypt(key, nonce_2, ciphertext, counter=1) == plaintext

    print("all RFC 8439 vectors pass")


if __name__ == "__main__":
    _self_test()
