#!/usr/bin/env python3
"""Static-replace the compiler-detection macros in init/Kconfig.

The savox-326 mirror mixes a newer Kconfig with an old kconfig toolchain and
a broken gcc-version.sh in the build environment. The detection configs
(CC_IS_GCC / GCC_VERSION / CLANG_VERSION / CC_HAS_ASM_GOTO / LD_IS_LLD) do
not influence struct layout, so static values are safe for pahole extraction.

We build with gcc, and gcc supports asm goto.
"""
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "init/Kconfig"
src = open(path).read()

replacements = [
    ("def_bool $(success,$(CC) --version | head -n 1 | grep -q gcc)", "def_bool y"),
    ("default $(shell,$(srctree)/scripts/gcc-version.sh -p $(CC) | sed 's/^0*//') if CC_IS_GCC", "default 0"),
    ("def_bool $(success,$(CC) --version | head -n 1 | grep -q clang)", "def_bool n"),
    ("def_bool $(success,$(LD) -v | head -n 1 | grep -q LLD)", "def_bool n"),
    ("default $(shell,$(srctree)/scripts/clang-version.sh $(CC))", "default 0"),
    ("def_bool $(success,$(srctree)/scripts/gcc-goto.sh $(CC))", "def_bool y"),
]

changed = 0
for old, new in replacements:
    if old in src:
        src = src.replace(old, new)
        changed += 1

open(path, "w").write(src)
print(f"replacements applied: {changed}/6")
if changed < 6:
    print("WARNING: some patterns not found")
