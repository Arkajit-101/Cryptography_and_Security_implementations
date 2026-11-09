RSA TIMING ATTACK -- live demo (Kocher, CRYPTO '96)
===================================================

THE STORY
A server decrypts RSA ciphertexts with a secret exponent d. Its modular
reduction takes a data-dependent amount of time. By timing many decryptions,
an attacker who sees ONLY the ciphertexts and the timings (never d) rebuilds
d one bit at a time.

PIECES
  rsa_common.py         shared math (the variable-time reduction, used by both
                        the victim and the attacker's predictions)
  keygen.py             make the RSA key -- [1] generate p,q (pycryptodome)
                        or [2] type your own p, q, e
  make_messages.py      create messages.txt (sample messages)
  encrypt.py            encrypt messages with the PUBLIC key -> ciphertexts.txt
  victim.c / victim     decrypt with the SECRET key, timing each one
  decrypt_and_time.py   runs the victim -> traces.csv
  attack.py             rebuild d from n + traces.csv only

FILES PRODUCED (the things to show)
  public_key.txt    n, e              (public)
  secret_key.txt    p, q, d           (Simona's secret)
  messages.txt      the messages
  ciphertexts.txt   encrypted messages
  traces.csv        ciphertext, cycles, opcount   <- the timing evidence
  recovered_key.txt the rebuilt d

traces.csv has TWO time columns:
  cycles  = real CPU time (CPUID+RDTSC). Realistic, but noisy.
  opcount = count of key-dependent steps. A perfect, noise-free timer.
The attack is run on BOTH and reports each.

RUN ORDER
  gcc -O2 -o victim victim.c
  python3 keygen.py                 # pick [1] generate, or [2] enter p,q,e
  python3 make_messages.py 4000     # 4000 messages
  python3 encrypt.py
  python3 decrypt_and_time.py 15    # 15 = timing repeats (higher = less noise)
  python3 attack.py

WHAT YOU SHOULD SEE
  [opcount (noise-free)] recovered d == secret d : True   (per-bit 100%)
  [REAL cycles]          True on a quiet machine; ~50-60% if the CPU is noisy.

IMPORTANT -- SAMPLE COUNT SCALES WITH KEY SIZE (this is Kocher's point, sec 6/9)
  ~1500 messages  -> ~48-bit modulus
  ~4000 messages  -> ~64-96-bit modulus
  bigger keys need proportionally MORE messages. 200 is far too few.
  Default here: 32-bit primes (64-bit modulus), 4000 messages.
  Change prime size in keygen.py; change message count in make_messages.py.

FOR THE REAL (cycles) COLUMN TO CRACK
  run on a quiet machine, pinned to one core, turbo off:
     sudo cpupower frequency-set -g performance   # or disable turbo
     taskset -c 0 python3 decrypt_and_time.py 50  # more repeats
  The noise-free opcount column always cracks and proves the method is correct.
