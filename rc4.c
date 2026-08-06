/* RC4 stream cipher -- KSA and PRGA, with clock cycle measurements.
 * Algorithms from Boneh & Shoup, "A Graduate Course in Applied Cryptography".
 *
 * Build: gcc -O2 -o rc4 rc4.c
 */

#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>          /* __rdtsc() */

#define SWAP(a, b) do { uint8_t tmp_ = (a); (a) = (b); (b) = tmp_; } while (0)

static uint8_t S[256];
static uint8_t i, j;            /* PRGA counters */

/* Algorithm 1: Key Scheduling Algorithm */
void ksa(const uint8_t *key, int s)
{
    int t;
    uint8_t jj = 0;

    for (t = 0; t < 256; t++)
        S[t] = (uint8_t)t;

    for (t = 0; t < 256; t++) {
        uint8_t k = key[t % s];
        jj = jj + S[t] + k;             /* uint8_t wraps == mod 256 */
        SWAP(S[t], S[jj]);
    }
    i = j = 0;
}

/* Algorithm 2: Pseudo-Random Generation Algorithm */
void prga(uint8_t *out, long n)
{
    long t;

    for (t = 0; t < n; t++) {
        i = i + 1;                      /* mod 256 by wraparound */
        j = j + S[i];
        SWAP(S[i], S[j]);
        out[t] = S[(uint8_t)(S[i] + S[j])];
    }
}

int main(void)
{
    static uint8_t out[65536];
    static const uint8_t key[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    uint64_t start, ksa_cycles, prga_cycles;
    long n = 65536;
    int t;

    /* (3) total clock cycles for the KSA */
    start = __rdtsc();
    ksa(key, sizeof key);
    ksa_cycles = __rdtsc() - start;

    /* (4) clock cycles per output byte for the PRGA */
    start = __rdtsc();
    prga(out, n);
    prga_cycles = __rdtsc() - start;

    printf("KSA  : %llu cycles total (%.2f per iteration)\n",
           (unsigned long long)ksa_cycles, ksa_cycles / 256.0);
    printf("PRGA : %llu cycles for %ld bytes (%.2f cycles/byte)\n",
           (unsigned long long)prga_cycles, n, (double)prga_cycles / n);

    printf("\nFirst 16 keystream bytes: ");
    for (t = 0; t < 16; t++)
        printf("%02x", out[t]);
    printf("\n");

    return 0;
}
