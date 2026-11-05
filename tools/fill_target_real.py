#!/usr/bin/env python3
"""Replace the mirror-derived [B] offsets with REAL G988USQSDHYG2 offsets.

Every value below is verified against the shipped binary (out/vmlinux) via
RELA relocation analysis of init_task, raw init_task data, or disassembly:
  usage 0x68   raw init_task data (refcount==2) + next_tgid ldxr
  prio/normal_prio 0xac/0xb4   init_task raw 120-triple + rt_mutex_setprio
  sched_task_group 0x3d8   RELA -> root_task_group
  tasks 0x540   RELA self-ref list (+ plist 0x550/0x558/0x568, dl 0x578)
  mm 0x590 / active_mm 0x598   RELA -> init_mm (nm-confirmed)
  atomic_flags 0x608   prepare_binprm tbnz bit0 (PFA_NO_NEW_PRIVS)
  pid 0x640 / tgid 0x644   restart_block@0x610 (fn->text) + mirror 113 delta,
                           canary 0x648 -> real_parent 0x650 (RELA)
  real_parent 0x650 / parent 0x658   RELA pair -> &init_task; PPid reader
  children 0x660 / sibling 0x670 / group_leader 0x680   RELA
  thread_group 0x688 / thread_node 0x698 / thread_pid 0x6a8   RELA
  real_cred 0x7f0 / cred 0x7f8 / comm 0x800   RELA -> init_cred; "swapper"
  seccomp 0x8a0   __secure_computing ldr + cmp mode 1/2
  pi_lock 0x8c8 / pi_waiters 0x8e0   mark_wakeup_next_waiter, 3rd confirmation
  pi_top_task 0x8f0 / pi_blocked_on 0x8f8   rt_mutex_setprio / task_blocks_on
  MM_STRUCT_SZ 0x3d0   proc_caches_init kmem_cache_create_usercopy size
  mm->owner 0x378, pipe_*, cred, rt_mutex_waiter, configfs_buffer unchanged
  (pipe_read / pipe_release / prepare_binprm / configfs_read_file verified).
"""
import sys

path = sys.argv[1]
src = open(path).read()

repl = [
    ("#define MM_STRUCT_SZ 0x3c8                              /* [B] pahole: 968 bytes */",
     "#define MM_STRUCT_SZ 0x3d0                              /* [B] real: proc_caches_init size=976 */"),
    ("#define FAKE_TASK_USAGE_OFF 0x60", "#define FAKE_TASK_USAGE_OFF 0x68"),
    ("#define FAKE_TASK_PRIO_OFF 0xa4", "#define FAKE_TASK_PRIO_OFF 0xac"),
    ("#define FAKE_TASK_NORMAL_PRIO_OFF 0xac", "#define FAKE_TASK_NORMAL_PRIO_OFF 0xb4"),
    ("#define FAKE_TASK_TASK_GROUP_OFF 0x398", "#define FAKE_TASK_TASK_GROUP_OFF 0x3d8"),
    ("#define FAKE_TASK_PI_LOCK_OFF 0x888", "#define FAKE_TASK_PI_LOCK_OFF 0x8c8"),
    ("#define FAKE_TASK_PI_WAITERS_OFF 0x8a0", "#define FAKE_TASK_PI_WAITERS_OFF 0x8e0"),
    ("#define FAKE_TASK_PI_TOP_TASK_OFF 0x8b0", "#define FAKE_TASK_PI_TOP_TASK_OFF 0x8f0"),
    ("#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8b8", "#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8f8"),
    ("#define TASK_PI_LOCK_OFF 0x888", "#define TASK_PI_LOCK_OFF 0x8c8"),
    ("#define TASK_PI_WAITERS_OFF 0x8a0", "#define TASK_PI_WAITERS_OFF 0x8e0"),
    ("#define TASK_PI_TOP_TASK_OFF 0x8b0", "#define TASK_PI_TOP_TASK_OFF 0x8f0"),
    ("#define TASK_PI_BLOCKED_ON_OFF 0x8b8", "#define TASK_PI_BLOCKED_ON_OFF 0x8f8"),
    ("#define TASK_PID_OFF 0x600", "#define TASK_PID_OFF 0x640"),
    ("#define TASK_TGID_OFF 0x604", "#define TASK_TGID_OFF 0x644"),
    ("#define TASK_REAL_PARENT_OFF 0x610", "#define TASK_REAL_PARENT_OFF 0x650"),
    ("#define TASK_ATOMIC_FLAGS_OFF 0x5c8", "#define TASK_ATOMIC_FLAGS_OFF 0x608"),
    ("#define TASK_REAL_CRED_OFF 0x7b0", "#define TASK_REAL_CRED_OFF 0x7f0"),
    ("#define TASK_CRED_OFF 0x7b8", "#define TASK_CRED_OFF 0x7f8"),
    ("#define TASK_COMM_OFF 0x7c0", "#define TASK_COMM_OFF 0x800"),
    ("#define TASK_TASKS_OFF 0x500", "#define TASK_TASKS_OFF 0x540"),
    ("#define TASK_THREAD_GROUP_OFF 0x6b0", "#define TASK_THREAD_GROUP_OFF 0x688"),
    ("#define TASK_SECCOMP_OFF 0x860", "#define TASK_SECCOMP_OFF 0x8a0"),
]

for old, new in repl:
    n = src.count(old)
    if n != 1:
        print(f"FATAL: pattern {old!r} matched {n} times")
        sys.exit(1)
    src = src.replace(old, new)

open(path, "w").write(src)
print(f"OK: {len(repl)} real-binary offsets applied to {path}")
