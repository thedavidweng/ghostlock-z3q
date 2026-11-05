# ghostlock-z3q — GhostLock (CVE-2026-43499) on the Samsung Galaxy S20 Ultra (SM-G988U)

Permanent-root exploit port for the **Snapdragon S20 Ultra (z3q, locked bootloader,
kernel `4.19.113-27095354`, firmware `G988USQSDHYG2` — the final build, released
2025-07)**, delivered as a reproducible **port kit for non-BTF kernels** rather than
a single-device throwaway.

```
adb shell (uid 2000)
  └─ LD_PRELOAD=preload.so
       ├─ GhostLock UAF → constrained kernel write
       ├─ pipe physical R/W
       ├─ KASLR slide via boot_id rb-gadget (RELA-derived values)
       ├─ cred patch → uid 0 root + embedded su daemon
       └─ memory-only: no partition writes, dm-verity intact, gone on reboot
```

Everything below was derived from the device's own firmware (boot.img from the
exact `G988USQSDHYG2` AP tar) — see [tools/](tools/) and [docs/PORTING.md](docs/PORTING.md)
for the full chain of evidence.

## Status

| Stage | State |
| --- | --- |
| symbol offsets (22) from boot.img kallsyms | done, `src/targets/z3q-4.19.113/target.h` |
| KASLR gadget values via `.rela.dyn` | done (loggers `+0xd8` layout matches oplus) |
| struct offsets via pahole (z3q source + device `.config`) | see target.h confidence tags |
| GhostLock trigger + collision finder (on-device) | works — requeue race fires, 13-23 colliders per run |
| slide stage (boot_id rb-gadget) | **blocked** — per-boot randomized linear map (see below) |
| hardening map (JOPP / RKP / KDP) | done, all bypass-compatible — see docs/PORTING.md §6 |
| KernelSnitch mm leak | **dead on this device** — strongest-ever negative result, §6.2 |
| per-attempt failure mode | kernel panic → auto-reboot (CONFIG_PANIC_ON_OOPS=y), retry |

**Update 2026-11-05** — the blocker moved twice, and the address-space question is
now **solved** (details in [docs/OPEN_PROBLEM.md](docs/OPEN_PROBLEM.md) and
PORTING.md §7):

- The kernel is a **VA39** build (`PAGE_OFFSET = 0xffffffc000000000`); every early
  panic traced to a wrong VA48 base, not the randomization.
- The per-boot KASLR slide is measurable in seconds from unprivileged userspace via
  an **EL0 prefetch TLB-timing oracle** (`tools/prefetch_probe.c`, integrated into
  the slide stage) — no leak channel needed, no KernelSnitch.
- The pselect stack overlay is **geometrically impossible** on this build
  (disasm-derived); the replacement **setsockopt-MCAST stamp** covers the entire
  dangling waiter.

**Current blocker**: the erase-trigger timing — the write primitive, gadget
targets, geometry and readback are all in place; the remaining question is which
kernel path erases the dangling waiter and whether its consumer set fits the
planted fields. The precise open problem, full geometry tables and reproduction
package: **[docs/OPEN_PROBLEM.md](docs/OPEN_PROBLEM.md)**.

## Why this repo exists

The 2026 GhostLock ecosystem is a pile of per-device forks. The reusable pieces are
scattered across them: the bug research in one place, the 4.19 adaptation deltas in
another, Samsung porting discipline in a third, delivery layers in two more — and the
offset-extraction tooling for **old kernels without BTF** (4.9/4.19) is essentially
unpublished. This repo fills that last gap and records every step so the next
device takes an afternoon instead of a week:

- `tools/extract_symbols.sh` — boot.img → vmlinux → symbol offsets (kallsyms via vmlinux-to-elf).
- `tools/derive_slide_gadgets.py` + `derive_slide_data.py` — **the RELA technique**: Samsung
  4.19 zeroes every relocated pointer in the raw image and fills them from `.rela.dyn` at
  boot, so anything that scans the image for pointers finds nothing. These scripts recover
  the KASLR slide-gadget values (loggers slot, boot_id ctl_table `.data` field) from the
  relocation table instead, with cross-validation against kallsyms.
- `tools/futex_probe.c` + `tools/ks_shift_scan.c` + `tools/ks_repro.c` — the KernelSnitch
  negative-result experiment, reusable on any Samsung kernel: on-device collision-set
  collector, and a solver that scans the full 256 GB linear region on the SLUB grid across
  all hashsizes with noise-tolerant k-of-n scoring. Zero hits on z3q = the runtime bucket
  assignment deviates from the upstream model (PORTING.md §6.2).
- `tools/patch_kconfig.py` + `docs/PORTING.md` — building the vendor source with the exact
  device config on a modern gcc, including every trap (mirror-mixed kconfig, CRLF, python2,
  `yylloc`, `-Werror`, Samsung clang-only `CONFIG_CFP`).
- `src/targets/z3q-4.19.113/target.h` — every value tagged `[A]`/`[B]`/`[C]`/`[D]` by provenance.

## Build

```
make PROJECT=z3q-4.19.113 NDK_TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/darwin-x86_64
# -> build/z3q-4.19.113/bin/preload.so
```

Run (one-shot root from an unprivileged adb shell; expects panics — retry):

```
adb push build/z3q-4.19.113/bin/preload.so /data/local/tmp/preload.so
adb shell "LD_PRELOAD=/data/local/tmp/preload.so id"     # expect uid=0 on success
adb shell /data/local/tmp/su -c id                        # embedded su daemon survives the run
```

## Index — the CVE-2026-43499 (GhostLock) ecosystem

Collected so the next agent (or human) can start from the right layer instead of
re-surveying GitHub. Ordered by what each layer is *for*.

### The bug and the 6.x reference chain
- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) — original IonStack research
  and the upstream exploit (6.x kernels). Writeup: [IonStack part III](https://nebusec.ai/research/ionstack-part-3/).
  Everything below derives from this.
- [F-19-F/IonStackQuest3](https://github.com/F-19-F/IonStackQuest3) — first public port to 5.10.

### 4.19 adaptation layer (closest to this repo)
- [yijiacloud/ghostlock-cve-2026-43499-4.19-k40](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40) —
  Qualcomm 4.19 adaptation (Redmi K40 / SD870). `adaptation-4.19.patch` documents every
  4.19-vs-6.x delta (fops signatures, ashmem prefix, kmalloc geometry, no
  `selinux_blob_sizes`, legacy pipe). **This repo's exploit core derives from it.**
- [soralis0912/CVE-2026-43499-pmg110-root](https://github.com/soralis0912/CVE-2026-43499-pmg110-root) —
  exemplary single-device port (OPPO PMG110, GKI 6.6) with the best tooling conventions:
  `extract_device.py`, `preloader_memlayout.py`, **`qemu_verify.py`** (boot the target kernel
  under QEMU and measure the pselect stack overlay before touching hardware), `device_probe.sh`.

### Per-device ports (worked examples)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) — OnePlus, locked BL.
- [Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC](https://github.com/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC) —
  Redmi K50G / POCO F4 GT (SM8450, 5.10), KernelSU late-load delivery.
- [RetributionByRevenue/xperia1vi-root](https://github.com/RetributionByRevenue/xperia1vi-root) —
  Xperia 1 VI (6.1, locked BL), **14 devices' offsets in src**, profile derived from the kernel itself.
- [R0rt1z2/GhostLock](https://github.com/R0rt1z2/GhostLock) — Amazon Fire devices (5.10), clean
  reliability notes (Wi-Fi off during attempts, retry loops, bind shell).
- [yakidango-official/GhostLock-H80GT](https://github.com/yakidango-official/GhostLock-H80GT) — Honor H80GT.
- [Delta-Water/CVE-2026-43499-phq110-root](https://github.com/Delta-Water/CVE-2026-43499-phq110-root) —
  OPPO PHQ110 (5.4). **The best documentation discipline in the ecosystem**: per-shot rationale,
  every on-device failure with root cause, and the memory-only "uid0 rootd + Shizuku" delivery
  design (no partition writes, SELinux handled via a permissive-map trick instead of global disable).
- [soralis0912/CVE-2026-43499-pmg110-root](https://github.com/soralis0912/CVE-2026-43499-pmg110-root) — see above.

### Samsung-specific porting and productization
- [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy) + 
  [Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads) — one-click
  installer app + signed community payload feed (`support/targets-v3.json`, schema v3) is the
  natural upstream for a z3q payload PR. A Galaxy S20 Ultra Snapdragon support inquiry
  ([issue #743](https://github.com/BuSung-dev/Root-My-Galaxy/issues/743), 2026-10) is still
  open with no maintainer response — this device is genuinely unclaimed territory.
- [wxxsfxyzm/GhostLock-Galaxy](https://github.com/wxxsfxyzm/GhostLock-Galaxy) — Galaxy branch of
  the app lineage: Z Fold6 only (6.1), `extract_target.py` parses boot.img + **xbl_config.img**
  and auto-derives `pselect_waiter_shift` via llvm-objdump — the best generator-side
  route-feasibility check ("waiter start + 11 <= 14 or the route cannot work") in the ecosystem.
- [snothin/GhostSam](https://github.com/snothin/GhostSam) — the most productized Samsung toolkit:
  S22/S26/Z Fold8 (5.10-6.18) Ghostlock chains plus a **dirtyfrag** chain (CVE-2026-43284
  xfrm-ESP page-cache store, GKI KMIs only). Its write-carrier design (misc/simple_attr fd as
  the constrained-write target instead of a sprayed page) and KDP-free root stage
  (forged `work_struct` on `system_unbound_wq` → `call_usermodehelper_exec_work`, no cred
  writes) are both directly relevant to any later-stage redesign here.
- [k-o-n-t-o-r/ghostlock-sm-g990b](https://github.com/k-o-n-t-o-r/ghostlock-sm-g990b) — S21 FE 5G
  (5.4 qGKI, single firmware). The oldest Samsung kernel with a working public GhostLock root:
  5.4, not 4.19.
- [mobilehackinglab/ghostlock-a17](https://github.com/mobilehackinglab/ghostlock-a17) — Galaxy A17
  (6.12 GKI). Different endgame (workqueue forging to bypass Samsung KDP — irrelevant on 4.19,
  which has no KDP), but the best porting discipline and a **QEMU end-to-end validation harness**.
  Writeup: [mobilehackinglab.com](https://www.mobilehackinglab.com/blog/cve-2026-43499-ghostlock-a17-root-shell).
- [Wtrwx/smt878u-ionstack-poc](https://github.com/Wtrwx/smt878u-ionstack-poc) — Tab S7 (SM-T878U,
  4.19, same generation as this device). The only other public Samsung-4.19 GhostLock attempt
  found (2026-10): **WIP, no root** — stuck earlier than this repo (the requeue race never lands,
  ~470 runs). Useful companions: durable `write()+fsync()` log mirror under PANIC_ON_OOPS, and
  honest negative-status README discipline.
- [hmascs/KSuRoot](https://github.com/hmascs/KSuRoot) — Chinese one-click KSU tool: baselines
  6.1/6.6/6.12 + ~122 vendor payloads (Samsung list sourced from the RMG feed, i.e. S22-era and
  newer). No 4.19 baseline.
- [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) — app lineage; maintainer
  position on this device class: "not for Pre-GKI V2 devices (anything older than S22)"
  ([issue #694](https://github.com/YuKongA/ghostlock-app/issues/694), a Galaxy S20 FE request —
  same SM8250/4.19 generation as z3q).

### Target generators and adjacent tools
- [woshimaniubi8/CVE-2026-43499-root-KernelSU](https://github.com/woshimaniubi8/CVE-2026-43499-root-KernelSU) —
  `generate_target.py` (boot.img → target.h) with KernelSU late-load delivery; BTF-centric
  (falls back to templates without BTF — the gap this repo addresses).
- [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle) and
  [Linuxoid-cn/CVE-2026-43499-Poc-Analysis](https://github.com/Linuxoid-cn/CVE-2026-43499-Poc-Analysis) —
  analysis references cited by the generator above.
- [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) — app-wrapper lineage used
  by the Xperia port.

### Related 2026 kernel LPE (different bug, different scope)
- [EternalTimes/CVE-2026-98260-GhostKey](https://github.com/EternalTimes/CVE-2026-98260-GhostKey) —
  CVE-2026-98260 (exec POSIX-timers UAF, **introduced in kernel 5.7**; GKI 5.15/6.x only — 4.9/4.19
  devices are *not* affected). Included because its architecture is the best "universal by design"
  in the ecosystem: BTF struct-layout parsing + offline `mkprofile.py` + `uname -r` matching +
  runtime KASLR solving + Shizuku entry, all in one APK. Complementary to this repo's domain.

### Infrastructure
- [marin-m/vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) — kallsyms recovery from raw
  kernel/boot images; the first step of every port here.
- [topjohnwu/samloader-rs](https://github.com/topjohnwu/samloader-rs) — Samsung FUS firmware
  download/decrypt/extract (how the exact `G988USQSDHYG2` AP tar was obtained).
- [savox-326/G988U_android13_kernel](https://github.com/savox-326/G988U_android13_kernel) — z3q
  kernel source mirror used for the pahole struct-layout build (caveats documented in PORTING.md).

## License

Apache-2.0, inherited from the upstream IonStack exploit (NebuSec/CyberMeowfia) via the
K40 4.19 adaptation. All original research credit belongs to
[NebuSec](https://nebusec.ai/research/ionstack-part-3/); this repo is a device port and
tooling contribution on top.

**For authorized security research and devices you own only.**
