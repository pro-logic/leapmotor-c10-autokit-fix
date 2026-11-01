# Installation, rollback and diagnostics

## Prepare the USB stick

Obtain **both** matching patch and unpatch images from a published release,
or [build them from source](BUILDING.md). Keep their manifests and rollback
available. These instructions target matching stock CPC200-CCPA / A15W firmware
`2025.10.15.1127`, with the C10 in HD mode and Show Navigation Bar enabled.

Use a USB stick formatted as **FAT32**. Formatting erases the stick, so back up
anything you need first. Extract the selected ZIP on your computer and copy
**only its `A15W_Update.img`** to the root of the stick, keeping that filename.
Do not copy the ZIP itself or both update images. For a source build, the patch
is `dist/patch/A15W_Update.img`; the rollback is `dist/unpatch/A15W_Update.img`.
The installer requires at least 640 KiB of free space on the dongle's root filesystem.

## Install the patch in the car

1. Park the car and keep power stable. Connect the dongle and open the
   **AutoLinkKit / AutoKit app on the infotainment screen**.
2. Plug the prepared FAT32 USB stick into the **dongle's USB port** while
   viewing the app. The app should report **"dongle updating"**.
3. Wait for the update to finish. Do not remove the stick or interrupt power
   while the update is in progress.
4. Once the update has finished, **unplug the USB stick**. This restarts the
   dongle. Check `C10_LOGS/INSTALLED.txt` and `C10_LOGS/install.log` on the stick
   for the successful `C10 AutoKit Fix: install from stock` action. The updater
   screen alone does not prove the finish script succeeded.
5. You may need to press **Show Navigation Bar** (show bottom navigation) once
   more after installation. Then **restart the infotainment system** and
   reconnect Android Auto through the dongle. The picture should now have the
   correct aspect ratio above the bottom navigation bar.
6. Check picture and touch alignment after another full cold car/head-unit boot,
   before pressing Show again. For a normal run, boot without USB or without
   `AATestMode`.

## Remove the patch

Use the **matching unpatch** from the same release. Put its `A15W_Update.img`
at the root of a **FAT32** stick instead of the patch image. In the car, open
AutoLinkKit / AutoKit, insert the stick into the dongle and wait for updating to
finish. Then remove the stick to restart the dongle and verify the rollback
receipt in `C10_LOGS/INSTALLED.txt` and `C10_LOGS/install.log`.

## Optional diagnostics

Put an empty regular file named `AATestMode`, with no extension, at the FAT32
stick's root **before powering on**. Keep the stick attached during capture.
Already enumerated disks get up to three seconds to mount; a slow stick can miss
boot selection. New captures appear in `C10_LOGS`. Keep these logs private or
redact identifiers before sharing them.

Diagnostic mode is selected once per boot. Inserting a stick later does not
enable it. Removing the stick stops USB exports; local diagnostic logging
continues until reboot.

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
