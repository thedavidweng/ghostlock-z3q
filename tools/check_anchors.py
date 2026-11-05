#!/usr/bin/env python3
"""Validate a pahole task_struct dump against RELA-derived anchors from the
real G988USQSDHYG2 vmlinux. Any mismatch means the source tree does not
match the shipped kernel and its offsets must not be trusted."""

import re
import sys

# offset -> (field name, expected decimal offset from pahole output)
ANCHORS = {
    "usage": 0x68,
    "prio": 0xAC,
    "static_prio": 0xB0,
    "normal_prio": 0xB4,
    "sched_task_group": 0x3D8,
    "tasks": 0x540,
    "mm": 0x590,
    "active_mm": 0x598,
    "real_parent": 0x650,
    "parent": 0x658,
    "children": 0x660,
    "sibling": 0x670,
    "group_leader": 0x680,
    "thread_group": 0x688,
    "thread_node": 0x698,
    "thread_pid": 0x6A8,
    "real_cred": 0x7F0,
    "cred": 0x7F8,
    "comm": 0x800,
}

path = sys.argv[1]
text = open(path).read()
ok = fail = 0
for name, want in ANCHORS.items():
    m = re.search(rf"^\s*[^;]*?\b{name}\b[^;]*?;\s*/\*\s*(\d+)\s", text, re.M)
    if not m:
        print(f"MISSING  {name}")
        fail += 1
        continue
    got = int(m.group(1))
    status = "OK " if got == want else "MISMATCH"
    if got == want:
        ok += 1
    else:
        fail += 1
    print(f"{status} {name:18} pahole={got:#x} expected={want:#x}")
print(f"\n{ok} match, {fail} fail")
sys.exit(1 if fail else 0)
