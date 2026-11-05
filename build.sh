#!/bin/bash
# Build preload.so for oplus-4.19.157-perf (qcom 4.19, aarch64-linux-android)
set -e
: "${NDK_ROOT:=$HOME/android-ndk-r27c}"
API=35
TC="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64"
CC="$TC/bin/aarch64-linux-android${API}-clang"
PROJECT="oplus-4.19.157-perf"

mkdir -p build/embed build/$PROJECT/bin

COMMON="-O2 -g0 -Wall -Wextra -Isrc -DTARGET_CONFIG_H=\"targets/$PROJECT/target.h\""

echo "== building embedded su_daemon =="
"$CC" $COMMON -fPIE -pie src/su_daemon.c -o build/embed/su_daemon_aarch64_pie

echo "== building preload.so =="
"$CC" $COMMON -fPIC -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
    -shared -o build/$PROJECT/bin/preload.so -pthread \
    src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c \
    src/preload.c src/su_blob.S src/wallpaper_blob.S

cp build/$PROJECT/bin/preload.so prebuilt/preload.so
cp build/embed/su_daemon_aarch64_pie prebuilt/su_daemon_aarch64_pie
sha256sum prebuilt/preload.so
echo "done: prebuilt/preload.so"
