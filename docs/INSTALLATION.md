# Installation, rollback and diagnostics

1. Obtain **both** matching patch and unpatch images from a published release,
   or [build them from source](BUILDING.md). Keep their manifests and rollback
   available. The paths below refer to the original builder's output directories;
   for downloads, select the corresponding patch or unpatch from the same release.
2. Copy **only** `dist/patch/A15W_Update.img` to the USB stick's root, keeping
   that filename. Use the dongle's normal USB update procedure. Do this parked
   with stable power. The installer requires at least 640 KiB of free root space.
3. Check `C10_LOGS/INSTALLED.txt` and `C10_LOGS/install.log` on the stick for the
   successful `C10 AutoKit Fix: install from stock` action. The ordinary updater
   screen alone does not prove the finish script succeeded. Reboot before testing.
4. For a normal run, boot without USB or without `AATestMode`. Test touch before
   pressing Show, including after another full cold boot.
5. For diagnostics, put an empty regular file named `AATestMode` at USB root
   before powering on. Keep the stick attached during capture. Already enumerated
   disks get up to three seconds to mount; a slow stick can miss boot selection.
   New captures appear in `C10_LOGS`. Keep these logs private or redact identifiers
   before sharing them.
6. To remove the fix, put **`dist/unpatch/A15W_Update.img`** at USB root instead
   and use the same update procedure. Verify the rollback receipt and reboot.

The patch does not create `AATestMode` automatically. Installation itself writes
a one-time receipt independently of runtime diagnostic mode. Completed installers
rename their USB input to `A15W_C10_AutoKit_Fix.used` or
`A15W_C10_AutoKit_Unpatch.used`.

Unpatch restores the original packed projection driver and startup/daemon files,
and removes this project's guard/capture helpers and provenance file it owns. It preserves
user settings, the USB marker, old logs and unrelated historical artifacts. It
does not factory-reset configuration: existing Android Auto resolution settings
are left for the stock host/driver to manage on the next boot. Neither image
replaces the kernel, boot partition, rootfs image or AutoKit APK; the displayed
firmware version remains unchanged.
