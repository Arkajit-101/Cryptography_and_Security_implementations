"""Create messages.txt with N sample messages (only if it doesn't exist)."""
import os, sys
N = int(sys.argv[1]) if len(sys.argv)>1 else 200
if os.path.exists("messages.txt"):
    print("messages.txt already exists, leaving it."); raise SystemExit
words=["invoice","transfer","login","report","contract","meeting","payment",
       "secret","hello","update","order","balance","renewal","access","ticket"]
with open("messages.txt","w") as f:
    for i in range(N):
        f.write(f"message {i:03d}: {words[i%len(words)]} reference {1000+i*7}\n")
print(f"wrote messages.txt with {N} messages")
