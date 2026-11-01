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

1. Enable **Show Navigation Bar** in AutoKit and use **HD mode**.
2. Put the patch image at the root of a USB stick as **`A15W_Update.img`**.
   Keep only the selected update image on the stick and use the dongle's normal
   USB update procedure, parked with stable power.
3. Check **`C10_LOGS/INSTALLED.txt`** and **`C10_LOGS/install.log`** for success.
   The updater screen alone does not confirm installation. Reboot the dongle.
4. Test the picture and touch alignment after a full cold car/head-unit boot,
   before pressing Show again.

To remove the patch, repeat the update procedure using the matching **unpatch**
image as `A15W_Update.img`, check the rollback receipt and reboot. It restores
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
