# Obtaining the exact original unpacked driver

Skip this if you already have the unpacked original with SHA-256
`0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee`.

The stock image contains a packed driver. Its first packed block uses the
dongle's `/dev/hwaes`; ordinary desktop UPX is insufficient. The builder therefore
requires an original unpacked export rather than silently substituting a
different driver. The packed stock driver's SHA-256 is
`614fa754065dcecd7465bfdc283d551abdc0c1d630c9c0c76b520a4272867cdb`.

This procedure requires existing shell access to a matching original A15W dongle.
Adding shell/SSH access is outside this repo's scope. It will refuse a driver
already replaced by a native patch; do not restore your working dongle merely to obtain
another copy if you already have a matching original export.

1. Obtain `Debug_Tools/upx` from
   [wireless-carplay-dongle-reverse-engineering at b437135](https://github.com/ludwig-v/wireless-carplay-dongle-reverse-engineering/tree/b437135316275a5d3c375bdd1ceac2a6bcf1315b/Debug_Tools).
   Keep its upstream licence/source information. Verify its SHA-256 on your
   computer matches `c41472232b5eb4b3ca5ffa0ea7a677be7fd832a8a10446bd4ba4077964ad4f42`.
2. Put that binary on USB as `C10_TOOLS/c10_upx`, and this repo's
   `tools/export_original_driver.sh` at USB root. Do not put an update image
   alongside this export operation. Start the matching dongle with USB attached.
3. From a shell **on the dongle**, run:

   ```sh
   sh /mnt/UPAN/export_original_driver.sh
   ```

   The script checks model/version, original driver and tool fingerprints, copies
   the tool to RAM, and unpacks to RAM. It never installs a replacement driver or
   changes startup files. It checks the original packed driver again and exports
   the result to `C10_ORIGINAL_DRIVER/ARMadb-driver.unpacked` on the USB stick.
   It refuses to overwrite an existing export directory.
4. Copy the unpacked result to this repository's ignored `inputs/` directory on
   your computer. The build's SHA-256 check must pass. An ELF magic check or a
   successful UPX exit code alone is insufficient.

The export helper's hardware execution has not been separately tested. It is a
simplified manual form of the hardware collector used during development. It
is not a stock update image, and will not run automatically just by inserting USB.
