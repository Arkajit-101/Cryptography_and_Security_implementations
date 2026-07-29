import time
import random
import math
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

#CPU's clock speed(GHz). Checked with:  lscpu | grep MHz
GHZ = 2.1


# ---------------- the three sorts ----------------

def merge_sort(a):
    if len(a) <= 1:
        return a
    mid = len(a) // 2
    left = merge_sort(a[:mid])
    right = merge_sort(a[mid:])
    out = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            out.append(left[i]); i += 1
        else:
            out.append(right[j]); j += 1
    out.extend(left[i:])
    out.extend(right[j:])
    return out


def quick_sort(a):
    if len(a) <= 1:
        return a
    p = a[random.randrange(len(a))]        # random pivot
    lo = [x for x in a if x < p]
    eq = [x for x in a if x == p]
    hi = [x for x in a if x > p]
    return quick_sort(lo) + eq + quick_sort(hi)


def heap_sort(a):
    a = a[:]
    n = len(a)

    def sift(i, size):
        while True:
            big, l, r = i, 2 * i + 1, 2 * i + 2
            if l < size and a[l] > a[big]:
                big = l
            if r < size and a[r] > a[big]:
                big = r
            if big == i:
                return
            a[i], a[big] = a[big], a[i]
            i = big

    for i in range(n // 2 - 1, -1, -1):
        sift(i, n)
    for end in range(n - 1, 0, -1):
        a[0], a[end] = a[end], a[0]
        sift(0, end)
    return a


# ---------------- measurement ----------------

def measure(sort_fn, n, arrays=7, reps=3):
    """Best-of-reps on each array kills timing noise;
       averaging over arrays gives the expected cost over inputs."""
    times = []
    for _ in range(arrays):
        data = [random.random() for _ in range(n)]
        best = None
        for _ in range(reps):
            start = time.perf_counter()
            sort_fn(data)
            t = time.perf_counter() - start
            if best is None or t < best:
                best = t
        times.append(best)
    sec = sum(times) / len(times)
    return sec, sec * GHZ * 1e9


sizes = list(range(100, 1501, 50))
sorts = [("Merge", merge_sort), ("Quick", quick_sort), ("Heap", heap_sort)]
results = {name: {"c": [], "sec": [], "cyc": []} for name, _ in sorts}

print(f"{'n':>6}" + "".join(f"{name+' c':>12}" for name, _ in sorts))
for n in sizes:
    nlogn = n * math.log2(n)
    row = f"{n:>6}"
    for name, fn in sorts:
        sec, cyc = measure(fn, n)
        c = cyc / nlogn                      # constant in cycles per n*log2(n)
        results[name]["c"].append(c)
        results[name]["sec"].append(sec)
        results[name]["cyc"].append(cyc)
        row += f"{c:>12.2f}"
    print(row)

print("\nAverage constant c  (cycles per n*log2(n)):")
for name, _ in sorts:
    cs = results[name]["c"]
    avg = sum(cs) / len(cs)
    sd = (sum((x - avg) ** 2 for x in cs) / len(cs)) ** 0.5
    print(f"  {name:>6}:  c = {avg:7.2f}   std = {sd:5.2f}   "
          f"(= {avg/GHZ:5.2f} ns per n*log2(n))")

# ---------------- plots ----------------
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))

for name, _ in sorts:
    ax1.plot(sizes, results[name]["c"], marker="o", ms=3, label=name)
ax1.set_xlabel("n"); ax1.set_ylabel("c  (cycles / n log2 n)")
ax1.set_title("Constant c vs n"); ax1.legend(); ax1.grid(alpha=.3)

for name, _ in sorts:
    ax2.plot(sizes, [s * 1e3 for s in results[name]["sec"]],
             marker="o", ms=3, label=name)
ax2.set_xlabel("n"); ax2.set_ylabel("time (ms)")
ax2.set_title("Running time vs n"); ax2.legend(); ax2.grid(alpha=.3)

plt.tight_layout()
plt.savefig("sorting.png", dpi=130)
print("\nsaved plot to sorting.png")
