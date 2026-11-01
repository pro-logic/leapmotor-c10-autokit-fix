# Leapmotor C10 AutoKit Fix

A cold-boot display fix for Leapmotor C10 owners using the **Carlinkit / MagicBox
CPC200-CCPA (A15W)** dongle to add Android Auto.

With **Show Navigation Bar** enabled in AutoKit, a cold car/head-unit boot can
leave the top and bottom of the Android Auto picture cropped. This patch adjusts
the picture to fit above the bottom navigation bar and corrects the touch offset
introduced by that resolution adjustment.

**This patch is intended for the C10 HD-mode setup with Show Navigation Bar
enabled.** It is not intended for setups with the bottom navigation bar hidden.

## Compatibility

The original patch targets **CPC200-CCPA / A15W firmware `2025.10.15.1127`**
with matching stock driver and startup files. The firmware version alone does
not establish compatibility. Other dongles and C10 software versions have not
been established as compatible. Previous development patches and other custom
firmware are not supported starting points.

## Download

Go to [Releases](https://github.com/pro-logic/leapmotor-c10-autokit-fix/releases) and download both the **patch**
and its matching **unpatch**. Keep the unpatch so you can restore the original
files later. Read the release notes for the required firmware and test status.

Prebuilt downloads are available only once a release has been published. If no
release is listed, you will need to [build from source](docs/BUILDING.md).

## Install or remove

1. Use **HD mode** with **Show Navigation Bar** enabled in AutoKit.
2. Prepare a USB stick formatted as **FAT32**. Formatting erases its contents,
   so back up anything you need first. Extract the patch ZIP on your computer
   and copy only **`A15W_Update.img`** to the stick's root.
3. **Do the update in the car**, parked with stable power. With the dongle
   connected and the **AutoLinkKit / AutoKit app open on the car screen**, plug
   the USB stick into the **dongle's USB port**. The app should report
   **"dongle updating"**. Wait for the update to finish; do not interrupt power.
4. Once the update has finished, **unplug the USB stick**. This restarts the
   dongle. Check **`C10_LOGS/INSTALLED.txt`** and **`C10_LOGS/install.log`** on the
   stick for success; the updater screen alone does not confirm installation.
5. You may need to press **Show Navigation Bar** (show bottom navigation) once
   more after installation. Then **restart the infotainment system** and
   reconnect Android Auto through the dongle. The picture should now have the
   correct aspect ratio above the bottom navigation bar.
6. Check picture and touch alignment after another full cold car/head-unit
   boot, before pressing Show again.

To remove the patch, repeat the update procedure using the matching **unpatch**
image as `A15W_Update.img` on a **FAT32** stick. Wait for the update to finish,
remove the stick to restart the dongle, and check the rollback receipt. It restores
replaced stock files and removes this project's helpers; it preserves settings
and existing logs. It is not a factory reset.

See [full installation and diagnostic instructions](docs/INSTALLATION.md).

## Status and risk

**Experimental. Use at your own risk.** The fix worked on the development dongle,
but the clean-stock installer and unpatch have not been separately tested on
hardware. Local checks cover native ARM emulation, encrypted update archives,
and simulated installation and rollback. See [validation and limits](docs/VALIDATION.md).

This project was developed with AI assistance. It is supplied as is, without
warranty, and is not supported by Leapmotor, Carlinkit or MagicBox. Firmware
modifications can leave the dongle unusable.

## Licence and credits

The project code is licensed under the **[MIT Licence](LICENSE)**. Vendor firmware
and components retain their own rights; MIT does not relicense them.

Based on work from
[lvalen91/CPC200-CCPA_resources](https://github.com/lvalen91/CPC200-CCPA_resources),
with subsequent C10-specific work. See [third-party credits](THIRD_PARTY.md).

For development, see [building and testing](docs/BUILDING.md),
[reverse engineering](docs/REVERSE_ENGINEERING.md) and [agent instructions](AGENTS.md).

`main` is the primary branch for this fix. The separate
[`feature/generic-firmware-patcher`](https://github.com/pro-logic/leapmotor-c10-autokit-fix/tree/feature/generic-firmware-patcher)
branch contains an experimental builder for
other recognized A15W firmware layouts. Its local test results do not establish
hardware compatibility; see its [generic patcher documentation](https://github.com/pro-logic/leapmotor-c10-autokit-fix/blob/feature/generic-firmware-patcher/docs/GENERIC_PATCHER.md).
