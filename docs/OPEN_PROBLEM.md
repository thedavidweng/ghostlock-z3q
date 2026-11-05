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
| Per-boot KASLR slide | **solved**: EL0 prefetch oracle, seconds per boot |
| Write primitive | decoded: two arbitrary-target constrained-value qword writes per rb erase pass |
| Gadget targets | RELA-verified: `random_table[boot_id].data` slot, `&loggers[0][0]` |
| Overlay (stack stamp) | pselect route **impossible** on this build; setsockopt-MCAST route geometry **derived, full waiter coverage** |
| Readback channel | designed (boot_id sysctl serves the gadget target) |
| Remaining blocker | erase trigger timing + the exact erase-consumer field set (see below) |

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
| **setsockopt IPPROTO_IP MCAST_JOIN_SOURCE_GROUP** | **group_source_req @SP0-0x230 (sp+0x20 in do_ip_setsockopt), 264B copy** | **waiter = gsr+0x40: ALL fields inside the controlled copy** |

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
gsr+0x40 = tree_entry.rb_parent_color  (P: W1 value)
gsr+0x48 = tree_entry.rb_right         (0: simple-path erase)
gsr+0x50 = tree_entry.rb_left          (C: W1 target)
gsr+0x58 = pi_tree_entry.rb_parent_color
gsr+0x60 = pi_tree_entry.rb_right
gsr+0x68 = pi_tree_entry.rb_left
gsr+0x70 = waiter->task
gsr+0x78 = waiter->lock
gsr+0x80 = waiter->prio
gsr+0x88 = waiter->deadline
```

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

**Q1 — the erase trigger timing.** With correct slide, correct geometry,
and all planted values verified-mapped, run #10 (2026-11-05) still
panicked during the stamp phase. Two hypotheses remain:

1. Run #10 used the upstream *poc*'s `_exit` flow (stamp loop then exit);
   `do_exit`'s deep frames overwrite the stamped region before the
   exit-teardown walk reads it — a crash-demo flow, not an exploit flow.
   The committed build now parks the waiter syscall-free after stamping
   (the k40-exploit design), but this is **not yet device-verified**.
2. The erase (or its surrounding pi-chain walk) consumes a waiter field
   or a related structure beyond {tree_entry, pi_tree_entry, task, lock}
   that our window doesn't cover correctly — e.g. the wake path
   (`mark_wakeup_next_waiter` / `wake_up_q` on `waiter->task`), or the
   requeue-cleanup path's own locals.

What is needed: either a precise trace of which kernel path performs the
dangling-waiter erase on this build (futex_requeue cleanup vs
rt_mutex_finish_proxy_lock vs exit teardown), or empirical timing
variation of the stamp/consumer windows with the panic signature as the
only observable. The fsync'd log mirror survives every panic
(`log_*.txt`), and every panic so far has been a clean reboot — the
device is not at brick risk from this experiment class.

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
- Run: `adb shell 'cd /data/local/tmp && GHOSTLOCK_CONF=0xFFFFFFC0
  LD_PRELOAD=/data/local/tmp/preload.so id'` — the exlog mirror writes
  `log_*.txt` with fsync before every risky step.

## Non-goals / scope notes

- The three other lab devices (Pixel 3a, Tab A7 Lite, Mi 8 SE) are
  already rooted and out of scope here.
- The kernel source tree (kernel-z3q) does NOT match the shipped binary
  in `arch/arm64/include/asm/memory.h` or `kaslr.c`; the binary-derived
  constants in this document supersede any source reading.
