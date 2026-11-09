"""Delete all generated .txt files (keys, message, ciphertext, decryption)."""
from mceliece_lib import *

for name in FILES:
    if os.path.exists(path(name)):
        os.remove(path(name))
        print("deleted", name)
