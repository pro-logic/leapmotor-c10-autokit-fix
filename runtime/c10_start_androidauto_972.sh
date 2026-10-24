#!/bin/sh
# Keep the pair enforced throughout AA's delayed initialization and session.
read_pair() {
    width=$(sed -n 's/.*"AndroidAutoWidth"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' /etc/riddle.conf)
    height=$(sed -n 's/.*"AndroidAutoHeight"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' /etc/riddle.conf)
}
restore_dpi() {
    dpi_hash=$(md5sum /tmp/screen_dpi 2>/dev/null | awk '{print $1}')
    [ "$dpi_hash" = 12422b0f0b7564c7421d580a752d3c9a ] && return 0
    echo "[C10-972-dpi220] Applying AA-side DPI 220 at uptime $(cat /proc/uptime)"
    printf '\334\000\000\000' > /tmp/c10_screen_dpi.pending || return 1
    mv -f /tmp/c10_screen_dpi.pending /tmp/screen_dpi || return 1
    [ "$(md5sum /tmp/screen_dpi | awk '{print $1}')" = 12422b0f0b7564c7421d580a752d3c9a ]
}
restore_pair() {
    restore_dpi || return 1
    read_pair
    [ "$width" = 1920 ] && [ "$height" = 972 ] && return 0
    echo "[C10-972-dpi220] Observed ${width}x${height}; restoring 1920x972 at uptime $(cat /proc/uptime)"
    /usr/sbin/riddleBoxCfg -s AndroidAutoWidth 1920 && /usr/sbin/riddleBoxCfg -s AndroidAutoHeight 972 || return 1
    read_pair
    [ "$width" = 1920 ] && [ "$height" = 972 ]
}
echo '[C10-972-dpi220] Starting AA with session-scoped 1920x972 guard'
restore_pair || echo '[C10-972-dpi220] Initial write not verified; guard will retry during AA initialization'
child=
stop_child() {
    trap - TERM INT HUP
    if [ -n "$child" ]; then
        kill "$child" 2>/dev/null
        wait "$child" 2>/dev/null
    fi
    exit 143
}
trap stop_child TERM INT HUP
ARMAndroidAuto &
child=$!
echo "[C10-972-dpi220] AA child=$child; stock AA logs below establish consumed dimensions"
while kill -0 "$child" 2>/dev/null; do
    if restore_pair; then
        sleep 0.1
    else
        echo '[C10-972-dpi220] WARNING: restore not verified; backing off for one second'
        sleep 1
    fi
done
wait "$child"
result=$?
trap - TERM INT HUP
echo "[C10-972-dpi220] AA exited status=$result; session guard stopped"
exit "$result"
