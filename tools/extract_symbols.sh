#!/bin/sh
# Extract the [A] symbol offsets for a target.h from a vmlinux ELF
# (produced by vmlinux-to-elf from the exact boot.img of the device).
#
# Usage: tools/extract_symbols.sh <vmlinux> <KIMAGE_TEXT_BASE>
#
# Prints off = sym - BASE for every symbol consumed by target.h.
set -e
VMLINUX=${1:?vmlinux path required}
BASE=${2:?image text base required, e.g. 0xffffff8008080000}

for s in ashmem_misc ashmem_fops ashmem_ioctl compat_ashmem_ioctl \
         ashmem_mmap ashmem_open ashmem_release ashmem_show_fdinfo \
         configfs_read_file configfs_write_bin_file \
         generic_file_splice_read noop_llseek \
         init_task init_uts_ns empty_zero_page root_task_group \
         selinux_enforcing selinux_state \
         security_hook_heads kmalloc_caches anon_pipe_buf_ops \
         nfulnl_logger loggers sysctl_bootid random_table \
         init_cred init_user_ns init_nsproxy; do
  ADDR=$(nm "$VMLINUX" 2>/dev/null | awk -v s="$s" '$3==s {print $1; exit}')
  if [ -n "$ADDR" ]; then
    python3 -c "print(f'$s 0x{0x$ADDR - 0x$BASE:x}')"
  else
    echo "$s NOT-FOUND" >&2
  fi
done
