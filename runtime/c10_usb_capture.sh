#!/bin/sh
[ -e /tmp/c10_usb_diagnostics.enabled ] || exit 0
# Read-only sampling. Publish synced immutable snapshots; retain three completed ones.
duration=${1:-0}
case "$duration" in ''|*[!0-9]*) exit 2;; esac
[ "$duration" -ge 0 ] && [ "$duration" -le 86400 ] || exit 2
WORK=/tmp/c10_capture
umask 077
mkdir "$WORK" || exit 0
stamp() {
    printf 'wall='; date '+%Y-%m-%dT%H:%M:%S%z'
    printf 'uptime='; cat /proc/uptime
}
geometry() {
    for config in /etc/riddle.conf /etc/riddle_default.conf /etc/riddle_special.conf; do
        echo "FILE $config"
        if [ -r "$config" ]; then
            grep -E 'AndroidAutoWidth|AndroidAutoHeight|ScreenDPI|screenDPI|VideoResolution|VideoWidth|VideoHeight|DisplaySize|ScreenPhysical|OriginalResolution|AndroidWorkMode' "$config" || :
        else
            echo MISSING
        fi
    done
    for item in /tmp/screen_dpi /etc/VideoResolutionWidth /etc/VideoResolutionHeight /etc/RiddleBoxData/HU_SCREEN_INFO /etc/RiddleBoxData/HU_VIEWAREA_INFO /etc/RiddleBoxData/HU_SAFEAREA_INFO; do
        echo "FILE $item"
        if [ -r "$item" ]; then
            echo 'od-default (octal words):'; od "$item"
        else
            echo MISSING
        fi
    done
}
{
    echo 'C10 stage13 USB-armed boot capture: exact stage12 driver, V2 guard and AA220'
    if [ "$duration" -eq 0 ]; then
        echo 'Continuous capture/size bounding for this diagnostic boot'
    else
        echo "Capture samples: $duration (approximately one per second)"
    fi
    stamp
    uname -a
    printf 'firmware='; cat /etc/software_version
    printf '\nproduct='; cat /etc/box_product_type
    printf '\ncmdline='; cat /proc/cmdline
    printf '\n'
    ps
} > "$WORK/session.txt"

# Keep 2 MiB per active text log plus its first 512 KiB if it needs truncation.
# Truncate in place: the running process retains the same output descriptor.
bound_log() {
    source=$1
    [ -f "$source" ] || return 0
    size=$(wc -c < "$source")
    if [ "$size" -gt 2097152 ]; then
        name=${source##*/}
        if [ ! -e "$WORK/$name.boot" ]; then
            head -c 524288 "$source" > "$WORK/$name.boot"
        fi
        tail -c 1048576 "$source" > "$WORK/trim"
        cat "$WORK/trim" > "$source"
        echo "Bounded $name at uptime $(cat /proc/uptime); middle output may be omitted" >> "$WORK/limits.txt"
    fi
}
mounted() { grep -q ' /mnt/UPAN ' /proc/mounts && [ -e /mnt/UPAN/AATestMode ]; }
copy_snapshot() {
    src=$1
    name=$2
    [ -r "$src" ] || return 0
    tail -c 2097152 "$src" > "$stage/$name"
}
dest=
sequence=0
export_usb() {
    if ! mounted; then dest=; return; fi
    if [ -n "$dest" ] && [ ! -d "$dest" ]; then dest=; fi
    if [ -z "$dest" ]; then
        mkdir -p /mnt/UPAN/C10_LOGS || return
        number=1
        while [ -e "/mnt/UPAN/C10_LOGS/capture-$number" ]; do number=$((number + 1)); done
        dest=/mnt/UPAN/C10_LOGS/capture-$number
        mkdir "$dest" || { dest=; return; }
        cp "$WORK/session.txt" "$dest/SESSION.txt" || return
        echo 'Logging snapshots; keep the drive inserted during tests.' > "$dest/CAPTURE_ACTIVE.txt"
        sequence=0
    fi
    sequence=$((sequence + 1))
    stage=$dest/.snapshot-$sequence.pending
    completed=$dest/snapshot-$sequence
    mkdir "$stage" || return
    for source in /tmp/c10_driver.log /tmp/c10_androidauto.log /tmp/c10_capture_init.log /tmp/c10_usb_capture.log /tmp/userspace.log /tmp/ttyLog; do
        copy_snapshot "$source" "${source##*/}" || return
    done
    copy_snapshot "$WORK/geometry.log" geometry.log || return
    copy_snapshot "$WORK/limits.txt" limits.txt || return
    for source in "$WORK"/*.boot; do
        [ -f "$source" ] || continue
        copy_snapshot "$source" "${source##*/}" || return
    done
    dmesg | tail -n 500 > "$stage/kernel.log"
    ps > "$stage/processes.txt"
    # Derived convenience summary; retain the raw logs even if no keywords match.
    grep -iE 'androidauto|android auto|androidAutoSize|CmdOpen|ProcessCmdOpen|ProceessCmdOpen|screen|resolution|margin|density|dpi|sps|pps|[0-9]+[ xX]+[0-9]+|input|touch|focus' "$stage/c10_driver.log" "$stage/c10_androidauto.log" > "$stage/negotiation-summary.txt" 2>/dev/null
    stamp > "$stage/SNAPSHOT_READY.txt" || return
    # Order matters: data first, then directory publication, then the latest pointer.
    # Previously completed snapshots are never edited while writing the new one.
    sync || return
    mounted || { dest=; return; }
    mv "$stage" "$completed" || return
    sync || return
    echo "snapshot-$sequence" > "$dest/LATEST.txt.pending" || return
    sync || return
    mv "$dest/LATEST.txt.pending" "$dest/LATEST.txt" || return
    sync || return
    if [ "$sequence" -gt 3 ]; then
        obsolete=$dest/snapshot-$((sequence - 3))
        # Snapshot directories contain only flat files. Avoid recursive deletion.
        for item in "$obsolete"/*; do
            [ -f "$item" ] && rm -f "$item"
        done
        rmdir "$obsolete" 2>/dev/null
        sync || return
    fi
}
elapsed=0
while [ "$duration" -eq 0 ] || [ "$elapsed" -lt "$duration" ]; do
    geometry > "$WORK/current"
    if ! cmp -s "$WORK/current" "$WORK/previous"; then
        { echo '=== GEOMETRY CHANGE ==='; stamp; cat "$WORK/current"; } >> "$WORK/geometry.log"
        cp "$WORK/current" "$WORK/previous"
    fi
    for source in /tmp/c10_driver.log /tmp/c10_androidauto.log /tmp/c10_usb_capture.log "$WORK/geometry.log" "$WORK/limits.txt"; do bound_log "$source"; done
    if [ $((elapsed % 5)) -eq 0 ]; then export_usb; fi
    sleep 1
    elapsed=$((elapsed + 1))
done
if export_usb && [ -n "$dest" ] && mounted; then
    rm -f "$dest/CAPTURE_ACTIVE.txt"
    stamp > "$dest/CAPTURE_FINISHED.txt"
    sync
fi
exit 0
