#!/bin/sh
# Decide once per boot. No capture worker, hashing or diagnostic log in quiet mode.
DECIDED=/tmp/c10_usb_diagnostics.decided
ENABLED=/tmp/c10_usb_diagnostics.enabled
[ ! -e "$DECIDED" ] || exit 0
umask 077
mounted() { grep -q ' /mnt/UPAN ' /proc/mounts; }

# An already enumerated stick may need a short mount-settling window. Do not
# delay the normal no-stick path. A stick arriving after this decision needs reboot.
if ! mounted && { [ -b /dev/sda1 ] || [ -d /sys/block/sda ]; }; then
    attempts=0
    while ! mounted && [ "$attempts" -lt 30 ]; do
        sleep 0.1
        attempts=$((attempts + 1))
    done
fi
if mounted && [ -f /mnt/UPAN/AATestMode ]; then
    : > "$ENABLED" || exit 0
fi
: > "$DECIDED" || exit 0
[ -e "$ENABLED" ] || exit 0

exec >> /tmp/c10_capture_init.log 2>&1
echo 'C10 AutoKit Fix: USB+AATestMode enabled diagnostics for this boot'
date
cat /proc/uptime
/script/c10_usb_capture.sh >> /tmp/c10_usb_capture.log 2>&1 &
echo '[C10-AutoKit-Fix] persistent driver:'
md5sum /usr/sbin/ARMadb-driver
(
    sleep 12
    echo '[C10-AutoKit-Fix] executable hashes after startup:'
    for pid in $(pidof ARMadb-driver 2>/dev/null); do
        echo "PID $pid executable:"
        readlink /proc/$pid/exe
        md5sum /proc/$pid/exe
    done
) >> /tmp/c10_capture_init.log 2>&1 &
exit 0
