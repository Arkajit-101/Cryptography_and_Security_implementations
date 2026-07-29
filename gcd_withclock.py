import time

#CPU's clock speed(GHz). Checked with:  lscpu | grep MHz
GHZ = 2.1


def gcd(a, b):
    """Non-recursive Euclid. Returns gcd and the number of steps."""
    steps = 0
    while b:
        a, b = b, a % b
        steps += 1
    return a, steps


def measure(a, b, repeat=100000):
    """Time one gcd(a,b) call, and convert to cycles."""
    start = time.perf_counter()
    for _ in range(repeat):
        gcd(a, b)
    end = time.perf_counter()
    seconds = (end - start) / repeat
    cycles = seconds * GHZ * 1e9
    return seconds, cycles


# ---- worst case is consecutive Fibonacci numbers ----
fib = [1, 1]
while len(fib) < 40:
    fib.append(fib[-1] + fib[-2])

print(" bits   steps   1.44*bits    time(us)    cycles")
for i in range(5, 40, 5):
    a, b = fib[i + 1], fib[i]
    g, steps = gcd(a, b)
    bits = b.bit_length()
    sec, cyc = measure(a, b)
    print(f"{bits:5}  {steps:6}  {1.44*bits:10.1f}  {sec*1e6:10.2f}  {cyc:8.0f}")
