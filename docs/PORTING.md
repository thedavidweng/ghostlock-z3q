# Porting GhostLock to a Samsung 4.19 device (worked example: SM-G988U)

Every step below was executed against the real device/firmware. The order matters:
the target.h you produce is only as good as the provenance of each value.

## 0. Recon (on-device, read-only)

```sh
adb shell getprop ro.build.version.incremental   # G988USQSDHYG2 -> the exact firmware
adb shell uname -r                               # 4.19.113-27095354
adb shell zcat /proc/config.gz > s20u_kernel.config   # IKCONFIG=y on Samsung
adb shell getprop ro.boot.flash.locked            # 1 = locked BL, exploit is the only route
```

Record `CONFIG_FUTEX_PI=y`, `CONFIG_KALLSYMS_ALL=y`, `CONFIG_ARM64_VA_BITS_39=y`,
`CONFIG_SECURITY_SELINUX_DEVELOP=y`, `CONFIG_PANIC_ON_OOPS=y`, and whether
`CONFIG_DEBUG_RT_MUTEXES` is set (it changes `rt_mutex_waiter` layout).
`CONFIG_CFP*` will be set — Samsung's clang-only CFI; it must be disabled for an
OSS build (see §3) and it does not affect struct layout.

## 1. Firmware → boot.img → vmlinux

```sh
# FUS download (topjohnwu/samloader-rs)
samloader check-update -m SM-G988U -r CCT
samloader download -m SM-G988U -r CCT -d firmware
unzip AP_G988USQSDHYG2_*.tar.md5.zip        # only the AP tar matters
tar -xf AP_*.tar.md5 boot.img.lz4 && lz4 -d boot.img.lz4 boot.img
pip3 install vmlinux-to-elf
vmlinux-to-elf boot.img out/vmlinux
```

Verify the banner inside `out/vmlinux` matches `uname -r` byte for byte
(4.19.113-27095354 … KST 2025). All symbol offsets are `nm_addr - KIMAGE_TEXT_BASE`
with `KIMAGE_TEXT_BASE = _text = 0xffffff8008080000` (kallsyms-derived, unsild).

## 2. The RELA technique (Samsung KASLR zeroes relocated pointers)

On this kernel **every pointer in .data is zero in the raw image** and gets
filled from `.rela.dyn` (R_AARCH64_RELATIVE, 141,954 entries) during early boot.
Anything that scans the image for pointer values finds nothing — this is why
naive "find the slot that contains &sysctl_bootid" approaches fail on Samsung 4.19.

`tools/derive_slide_data.py` parses `.rela.dyn` directly:

- for each entry, `r_offset` is the slot, `r_addend` is the unsild target;
- the boot_id `ctl_table` entry is found by resolving `random_table` (kallsyms,
  4.19 `struct ctl_table`, 0x40 bytes/entry) and matching the entry whose
  procname RELA addend points at the string `"boot_id"`;
- cross-validate: the entry's `.data` addend must equal the kallsyms address of
  `sysctl_bootid` (the 16-byte .bss buffer).

Result for G988USQSDHYG2:

```
SLIDE_LOGGERS_0_1_OFF        = 0x2ba5dc8   # &loggers[0][0], == nfulnl_logger - 0xd8
SLIDE_NFULNL_LOGGER_OFF      = 0x2ba5ea0
SLIDE_RANDOM_BOOT_ID_DATA_OFF= 0x2c4d998   # random_table[4].data slot
```

The `loggers == nfulnl_logger - 0xd8` relation matches the oplus K40 build
exactly, so the gadget geometry from the 4.19 adaptation carries over.

## 3. Vendor source build (first pass — and why it was NOT enough)

Old kernels have no BTF, so struct layouts must come from compiling the exact
source with the exact config. Traps hit on the way (savox-326 mirror + Debian 13):

| Trap | Fix |
| --- | --- |
| mirror mixes new Kconfig files with old kconfig tools | replace `scripts/kconfig` with vanilla v4.19's (has the macro preprocessor); re-add `source "scripts/Kconfig.include"` as line 1 of `init/Kconfig` |
| `init/Kconfig` compiler-detection macros run broken `gcc-version.sh` | static-replace with `tools/patch_kconfig.py` (CC_IS_GCC=y etc. — these configs don't affect layout) |
| CRLF in Samsung Kconfigs/scripts | `find . -name "Kconfig*" -exec sed -i 's/\r$//' {} +` |
| `python`/`python2` missing on modern Debian | `python-is-python3` + `/usr/local/bin/python2 -> python3` |
| `YYLTYPE yylloc` multiple definition (new flex/bison) | delete the line in `scripts/dtc/dtc-lexer.l` (upstream e33a814e772d) |
| `extern inline` without body vs gcc-14 | `need_memory_boosting` → plain `extern` |
| `-Werror=strict-prototypes` on Samsung code | `KCFLAGS="-Wno-error -Wno-strict-prototypes"` |
| `CONFIG_CFP*` (Samsung clang-only CFI, internal clang unpublished) | disable; CFP is code instrumentation, does not change struct layout |
| build system hardcodes `toolchain/llvm-arm-toolchain-ship/10.0/bin/clang` | `make CC=aarch64-linux-gnu-gcc REAL_CC=aarch64-linux-gnu-gcc` |

**The critical lesson: the published OSS source is NOT the shipped kernel.**
Samsung publishes per-release source, but the release you can download may be
an older CL than your firmware. On this project the only G988U OSS release was
`G988USQSDHXA1` (Android 13 era, 2023-03) while the shipped firmware is
`G988USQSDHYG2` (final OneUI 6, 2024-08, same `4.19.113` uname). The pahole
layout from the mirror was *close but wrong*: task_struct drifted non-uniformly
(+8 before `usage`, +0x40 from `sched_task_group` onward, -0x28 in the
`thread_group` region from NR_CPUS-sized fields), and mm_struct grew 8 bytes.
Every exploit-relevant task_struct offset was different. A newer KSU tree
(AstroByteX-Code/android_kernel_samsung_sm8250, 4.19.325) failed anchor
validation too (thread_info 80 vs 88, usage 0x60 vs 0x68).

Running with plausible-but-wrong offsets under `CONFIG_PANIC_ON_OOPS=y` just
buys reboots. Don't trust any source layout on a locked device — **verify every
offset against the shipped binary itself** (§3.5), and use the source only to
fill the gaps with arithmetic anchored at verified points.

## 3.5 Binary-first offset derivation (RELA + init_task + disassembly)

The shipped `out/vmlinux` is the only ground truth you need. Three read-only
techniques, all cross-checkable:

**(a) RELA pointers.** `.rela.dyn` gives every static pointer in .data:
`r_offset` is the slot, `r_addend` the target. Pointers INTO `init_task`
identify fields unambiguously:

| anchor | RELA evidence |
| --- | --- |
| `stack@0x60` | addend `init_thread_union` (nm: `__start_init_task`) |
| `sched_task_group@0x3d8` | addend `root_task_group` |
| `tasks@0x540` | empty self-ref list; plist `prio_list@0x558`/`node_list@0x568`, rb `pushable_dl@0x578` follow, then `mm@0x590` (NULL) |
| `active_mm@0x598` | addend `init_mm` |
| `restart_block@0x610` | addend is a `.text` address (`.fn = do_no_restart`) |
| `real_parent@0x650 / parent@0x658` | addend pair `&init_task`; also the PPid reader in `proc_pid_status` passes `[task+0x650]` to `__task_pid_nr_ns` |
| `children@0x660 / sibling@0x670` | empty self-ref lists |
| `group_leader@0x680` | addend `&init_task` |
| `thread_group@0x688 / thread_node@0x698` | empty self-ref lists |
| `thread_pid@0x6a8` | addend `init_struct_pid` |
| `real_cred@0x7f0 / cred@0x7f8` | addend pair `init_cred` |
| `ptraced@0x7b8 / ptrace_entry@0x7c8` (+ Samsung 3rd list `@0x7d8`) | empty self-ref lists before the cred pair |

**(b) Raw init_task data.** Non-relocated scalars sit in the image as-is:
`usage@0x68 == 2`, `flags@0x6c == 0x200000` (PF_KTHREAD), the
`prio/static_prio/normal_prio` triple `120/120/120` at `0xac/0xb0/0xb4`
(rt_priority 0 follows), `comm@0x800 == "swapper"`. `thread_info` spans
[0, 0x58) = 88 bytes (not 80 like both public trees).

**(c) Disassembly.** `llvm-objdump -d --start-address/--stop-address` with
addresses from `nm`:

| field | evidence |
| --- | --- |
| `prio@0xac`, `normal_prio@0xb4`, `pi_top_task@0x8f0` | `rt_mutex_setprio` |
| `pi_blocked_on@0x8f8`, `pi_waiters@0x8e0`, `pi_lock@0x8c8` | `task_blocks_on_rt_mutex`, `mark_wakeup_next_waiter` (pi_lock: 3 independent hits) |
| `seccomp@0x8a0` | `__secure_computing` reads `[current+0x8a0]`, cmp mode 2 / 1 |
| `atomic_flags@0x608` | `prepare_binprm` `ldr x8,[current+0x608]; tbnz w8,#0` (PFA_NO_NEW_PRIVS) |
| `cred@0x7f8`, euid `cred+0x14` | `prepare_binprm`, `audit_log_task_info` |
| `mm->owner@0x378` | `mm_update_next_owner` |
| `MM_STRUCT_SZ = 0x3d0` | `proc_caches_init` passes 976 to `kmem_cache_create_usercopy` |
| pipe: `wait@0x40`, `nrbufs@0x60`, `curbuf@0x64`, `pipe_buffer=0x28` | `pipe_read` |
| `rt_mutex_waiter.lock@0x38` | `mark_wakeup_next_waiter` |

Fields with no static instance (pid/tgid) come from source arithmetic ANCHORED
at verified points: mirror-113 `restart_block` is 0x30 bytes, real
`atomic_flags@0x608` → `restart_block@0x610` (verified) → `pid@0x640`,
`tgid@0x644`, stack_canary `@0x648`, and `real_parent@0x650` (verified) closes
the chain with no gaps.

Everything that was NOT task_struct matched the 113-source pahole exactly
(cred, seccomp, pipe_inode_info, configfs_buffer, rt_mutex_waiter) — Samsung's
inter-CL drift was confined to task_struct (+8/+0x40) and mm_struct (+8). So:
source layouts remain useful for the peripheral structs; task_struct and mm
must be binary-verified per target. `tools/check_anchors.py` automates the
RELA-anchor comparison for any candidate layout.

## 4. target.h

Layout follows the K40 convention: every value tagged by provenance
([A] kallsyms-direct, [B] binary-verified via §3.5, [C] 4.19-upstream-stable,
[D] runtime-tunable). The [C] blocks (rt_mutex_waiter, configfs_buffer, fops,
struct page, cred, seccomp) matched the 113-source pahole and the shipped
binary's disassembly; Samsung's z3q `pipe_inode_info` is the legacy pre-4.9
layout exactly like oplus's. All task_struct/mm_struct values in the z3q
target.h are [B] — derived from the shipped vmlinux, not from any source tree.

## 5. Device run

- `CONFIG_PANIC_ON_OOPS=y`: a failed attempt is an instant reboot, not just an
  oops. Budget for retry loops; the failure logs are fsync'd by the exploit
  and survive at `/sdcard/Download` (or `/data/local/tmp` on storage-less
  lab devices — `root-z3q.sh` checks both).
- The configfs stage needs NO configfs mount: the UAF'd `configfs_buffer` is
  re-populated through an overlapping ashmem name slot (`/dev/ashmem`), and
  KASLR comes from the `ASHMEM_OPEN` fops pointer + the boot_id RELA gadget.
- First runs: watch `UNVERIFIED` slide-stage markers and the `ret=?` pselect
  markers; tune `PSELECT_WAITER_WORD_SHIFT` from the log, not by guessing.
- Root is memory-only: after reboot the device is stock (dm-verity intact,
  nothing written). Delivery layer (uid0 rootd / Shizuku / KSU late-load) is
  your choice — see the Index README section for reference implementations.

## 6. Samsung hardening stack and the first-leak problem (2026-11 findings)

Everything in this section was derived from the shipped `G988USQSDHYG2`
vmlinux, the device tree, the BL partition set of the AP tar, and four
on-device runs. It is the reason a straight K40-style port cannot work on
this device, and it maps out what a working z3q chain must look like.

### 6.1 The hardening inventory (config + binary evidence)

| Layer | Mechanism (measured, not assumed) | Consequence for the chain |
| --- | --- | --- |
| `CFP_JOPP` | every indirect call goes through a springboard gadget that loads the 4 bytes *before* the target and requires `0x00be7bad` (`deadc0de` otherwise) | physmap fake-fops tables are dead; calling any *real* function entry passes (verified: `commit_creds`, `configfs_read_bin_file` both carry the magic) |
| `UH_RKP` + `KDP_CRED` | cred pages protected at EL2; `commit_creds` has an inline RKP gate | direct cred writes fault; **`commit_creds(&init_cred)` is explicitly whitelisted** (the `rkp_init_data+0xd0` comparison resolves to `&init_cred`, verified in vmlinux) — this is the RKP-legal root path |
| `KDP_DMAP`, `KDP_NS`, `DEFEX`, `DSMS` | direct-map/namespace/userspace-escalation hardening | do not block the planned chain (read-window via real configfs fops + `commit_creds(&init_cred)`); never close the crossed fd (`configfs_release_bin_file` vfree's the fake fields) |
| `selinux` + Samsung log policy | kallsyms, dmesg, iomem, pstore, timer_list, sched_debug, DT property reads: all denied to `u:r:shell:s0` | no free address leak from userspace |

The Samsung `configfs_buffer` layout (from `configfs_read_bin_file` /
`configfs_release_bin_file` disassembly — differs from oplus): mutex `+0x20`,
`needs_read_fill` int `+0x60`, read/write_in_progress `+0x64/+0x65`,
`read_buffer` `+0x68`, `read_buffer_size` `+0x70`, `cb_max_size` `+0x74`,
`bin_buffer` `+0x78`, `bin_attr` `+0x88` (read `+0x38`, write `+0x40`).
With `needs_read_fill=0` the read path is a direct `simple_read_from_buffer`
from `read_buffer` — a ≤2 GB read window with no `i_private` involvement.

### 6.2 KernelSnitch is dead on this device (negative result)

The k40/6.x mm leak solves `hash(addr) == hash(pile)` offline over the direct
map. On z3q this is impossible. Strongest experiment (2026-11-05): fresh
on-device collision set (pile + 23 colliders, `futex_probe`), scanned the
**full 256 GB 39-bit linear region** on the 0x400 SLUB grid (268M candidates,
covers every possible `memstart_addr` randomization), across nine hashsize
values, with k-of-n noise-tolerant scoring (other processes' futex waiters
pollute pure threshold timing). Best candidate matched 4 of 21 colliders —
random water level; a true mm would match ~16. Earlier all-constraint scans
(13 GB window, full 2^32 salt sweep) also zero. Conclusion: the runtime
bucket assignment deviates from the upstream jhash2 key model in a way that
is invisible to static instruction-level verification. Do not burn time on
KernelSnitch for this target; the experiment design is reusable to test any
other Samsung kernel cheaply.

### 6.3 The address-space model (this is where naive ports die)

The linear map on arm64 is `VA = PAGE_OFFSET + (phys - memstart_addr)`, and
`P0_PHYS_OFFSET` in every exploit of this lineage is really the
**memstart_addr base** (see upstream tokay: `PL == PHYS_OFFSET == 0x80000000`,
delta 0). On z3q:

- Samsung aboot relocates the kernel into `reserved-memory/kaslr_region`
  (node name `kaslr_region@A0001000`, added at boot, **stable across
  reboots** — verified). The stale initial copy sits next to
  `hyp_region@80000000` and is fenced off by `removed_region@80b00000`.
- `chosen/kaslr-seed` exists; the seed is provisioned by the Knox
  `set_kaslr_flag` secapp (`bksecapp.mbn`, `[set_kaslr_flag]` strings;
  also XBL knows a kaslr dump region).
- The 4.19 `memstart_offset_seed = seed >> 48` path (kernel-z3q
  `arch/arm64/mm/init.c`) moves the entire linear map per boot in 1 GB
  quanta (`ARM64_MEMSTART_ALIGN = 1 << 30` here). Four device runs with
  three different fixed-alias assumptions all panicked on the first
  planted deref — consistent with the shift being nonzero every boot.
- The kernel stashes the virtual slide in IMEM
  (`qcom,msm-imem-kaslr_offset`, magic `0xdead4ead`, 64-bit offset split
  at +4/+8 — `store_kaslr_offset()`), but nothing in userspace can read
  that slot on a stock build.

Net effect: **there is no per-boot-stable kernel VA on this device** that a
shell process can compute or read, which kills fixed-address gadget
planting (the boot_id rb-gadget included) until a first leak exists.

### 6.4 Why the ecosystem has no S20U root

Every verified target in the lineage (upstream Pixel set, k40, duchamp,
rodin in the KernelSU generator, …) has `P0_KERNEL_PHYS_LOAD ==
P0_PHYS_OFFSET` — kernel at the DRAM base, memstart unrandomized, delta 0.
The generators even derive those two constants from `/proc/iomem` read as
*root* (`--detect-adb-profile`). Nobody in the public ecosystem has solved
"aboot kaslr_region relocation + per-boot memstart randomization"; that
combination is specific to late Samsung qcom boot chains and is precisely
where this port is stuck.

### 6.5 Roadmap: the vmemmap route

`VMEMMAP_START` is not randomized on 4.19, and the struct-page VA of any
physical page is `vmemmap_start + (phys >> 12) * 0x40` — pure arithmetic on
physical addresses, which z3q gives us in abundance (kaslr_region, the
whole reserved-memory table, all DTB-known regions). The GhostLock
constrained write can therefore target struct-page metadata with zero
address guessing:

```
GhostLock write → vmemmap struct page (known phys → known VA)
  → Dirty-Pagetable-class primitive (page-table page metadata corruption,
    page reclaimed into attacker-controlled content)
  → PTE control from userspace → map arbitrary phys (kernel @0xA0001000)
  → read the running kernel's .data: RELA-backfilled pointers hand over
    BOTH the virtual slide and the linear-map base in one step
  → then the mapped chain from §6.1 applies unchanged:
    real configfs fops swap (JOPP-legal) → read window → commit_creds(&init_cred)
```

Failure mode is also better: corrupting a wrong struct page is usually
retryable, not the instant reboot that fixed-alias planting costs. Design
work required: map the exact rb-erase write semantics onto a single
`struct page` field store (value + target), then pick the page-table-page
victim set from the early-memblock allocations whose physical addresses are
deterministic.
