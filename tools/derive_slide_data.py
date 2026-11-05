#!/usr/bin/env python3
"""Locate the boot_id ctl_table .data slot by scanning image data
segments for the relocated pointer value &sysctl_bootid.

On 4.19 the entry lives in random_table[] (extern, kallsyms-visible).
Its .data field holds the image-relative address of the sysctl_bootid
.bss buffer. The qword whose content equals that address IS the
SLIDE_RANDOM_BOOT_ID_DATA target used by slide.c's constrained write.
"""
import subprocess, sys, struct

VMLINUX = sys.argv[1] if len(sys.argv) > 1 else "out/vmlinux"
BASE = 0xffffff8008080000

out = subprocess.run(["nm", VMLINUX], capture_output=True, text=True).stdout
syms = {}
for line in out.splitlines():
    p = line.split()
    if len(p) == 3:
        syms.setdefault(p[2], int(p[0], 16))
bootid = syms["sysctl_bootid"]
tbl = syms["random_table"]
print(f"sysctl_bootid buffer : {bootid:#x} (off {bootid - BASE:#x})")
print(f"random_table         : {tbl:#x} (off {tbl - BASE:#x})")

with open(VMLINUX, "rb") as f:
    hdr = f.read(64)
    e_phoff = struct.unpack_from("<Q", hdr, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", hdr, 0x36)[0]
    e_phnum = struct.unpack_from("<H", hdr, 0x38)[0]
    f.seek(e_phoff)
    segs = []
    for _ in range(e_phnum):
        ph = f.read(e_phentsize)
        p_type = struct.unpack_from("<I", ph, 0)[0]
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", ph, 8)
        if p_type == 1:
            segs.append((p_vaddr, p_filesz, p_offset))
            print(f"PT_LOAD va={p_vaddr:#x} filesz={p_filesz:#x} off={p_offset:#x}")

needle = struct.pack("<Q", bootid)
hits = []
for vaddr, filesz, off in segs:
    with open(VMLINUX, "rb") as f:
        f.seek(off)
        data = f.read(filesz)
    i = 0
    while True:
        i = data.find(needle, i)
        if i < 0:
            break
        hits.append(vaddr + i)
        i += 8

print(f"\nhits for &sysctl_bootid: {[f'{h:#x} (off {h - BASE:#x})' for h in hits]}")
# keep hits inside random_table's vicinity
for h in hits:
    entry = h - 8
    if tbl <= entry < tbl + 0x400:
        print(f"\nboot_id entry          : {entry:#x} (off {entry - BASE:#x})")
        print(f"SLIDE_RANDOM_BOOT_ID_DATA_OFF = {h - BASE:#x}")
