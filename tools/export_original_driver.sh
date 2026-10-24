#!/bin/sh
# Manual export on a matching stock A15W; writes only RAM and a new USB directory.
set -eu
fail() { echo "Export failed: $*" >&2; exit 1; }
SOURCE=/usr/sbin/ARMadb-driver
TOOL=/mnt/UPAN/C10_TOOLS/c10_upx
WORK=/tmp/c10-v13-original-export
DEST=/mnt/UPAN/C10_ORIGINAL_DRIVER
[ "$(cat /etc/box_product_type)" = A15W ] || fail 'Requires A15W'
[ "$(cat /etc/software_version)" = 2025.10.15.1127 ] || fail 'Requires 2025.10.15.1127'
grep -q ' /mnt/UPAN ' /proc/mounts || fail 'USB is not mounted'
[ ! -e /mnt/UPAN/A15W_Update.img ] || fail 'Remove the update image first'
[ -e /dev/hwaes ] || fail 'Hardware AES device is missing'
[ ! -e "$DEST" ] || fail 'USB export directory already exists; preserve it'
[ "$(md5sum "$SOURCE" | awk '{print $1}')" = 039fe8dc4b4302fe2ce5dfe941dfc09d ] || fail 'Original packed driver required'
[ "$(md5sum "$TOOL" | awk '{print $1}')" = 88580a43f8356ecf915d119a4007f77d ] || fail 'Hardware UPX tool differs'
mkdir "$WORK" || fail 'RAM work directory already exists or cannot be created'
cp "$TOOL" "$WORK/upx"
[ "$(md5sum "$WORK/upx" | awk '{print $1}')" = 88580a43f8356ecf915d119a4007f77d ] || fail 'RAM tool copy differs'
chmod 755 "$WORK/upx"
"$WORK/upx" -d "$SOURCE" -o "$WORK/ARMadb-driver.unpacked"
[ -s "$WORK/ARMadb-driver.unpacked" ] || fail 'Unpacked output is empty'
[ "$(md5sum "$SOURCE" | awk '{print $1}')" = 039fe8dc4b4302fe2ce5dfe941dfc09d ] || fail 'Original driver changed'
mkdir "$DEST"
cp "$WORK/ARMadb-driver.unpacked" "$DEST/ARMadb-driver.unpacked.pending"
[ "$(md5sum "$DEST/ARMadb-driver.unpacked.pending" | awk '{print $1}')" = "$(md5sum "$WORK/ARMadb-driver.unpacked" | awk '{print $1}')" ] || fail 'USB copy differs'
sync
mv "$DEST/ARMadb-driver.unpacked.pending" "$DEST/ARMadb-driver.unpacked"
sync
echo 'Exported original driver. Verify its SHA-256 on the computer before building.'
