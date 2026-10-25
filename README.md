# C10 AutoKit Fix

Resolution and touch fix for the **Carlinkit / MagicBox CPC200-CCPA (A15W)**
dongle on a **Leapmotor C10**. Build one clean patch from matching **stock
firmware**, and a paired unpatch that restores the stock files it replaces.

This project was **vibe-coded with AI**. It is experimental, supplied **as is,
with no warranty**, and is not supported by Leapmotor, Carlinkit or MagicBox.
Installing firmware modifications can leave an adapter unusable. Use at your
own risk; the MIT licence contains the full warranty and liability disclaimer.

## The problem

With AutoKit set to **Show Navigation Bar**, the navigation bar appeared after a
cold car/head-unit boot, but Android Auto used the wrong resolution. The top and
bottom of the Android Auto image were cropped. This was the original stock issue.

For the tested **HD-mode** setup, the first part of the fix overrides the
car-requested AA resolution and holds the intended 1920×972 content size, so the
image fits the area above the navigation bar. That forced-resolution fix
introduced a touch offset: you had to touch above the visible controls.
Selecting Show again corrected that alignment for the session. The conditional
native touch correction compensates for this mismatch introduced by the
resolution override.

The screen reports 2560×1440, while the bottom navigation layout uses a
2560×1296 area. The investigation found different startup and post-Show geometry.
This patch targets that specific profile; it is not a universal touch calibration.

It grew out of work based on
[lvalen91/CPC200-CCPA_resources](https://github.com/lvalen91/CPC200-CCPA_resources).
The standalone implementation here includes subsequent local work; this does
not imply the upstream author wrote, reviewed or endorsed it. See
[THIRD_PARTY.md](THIRD_PARTY.md) for credits and input provenance.

## What the patch does

The two functional parts work together: first correct the cropped image by
overriding the requested resolution, then compensate for the resulting touch
offset.

- Keeps Android Auto content at 1920×972 and AA-side DPI at 220 using the existing
  session guard (100 ms polling while AA runs).
- Changes a valid raw host Open of exactly 2560×1440 to 2560×1296 in the native
  driver, and conditionally subtracts 500/10000 from AA's normalized touch Y,
  clamping at zero. A valid raw 2560×1296 Open disables the correction. Other
  valid Open profiles also disable it; malformed Open messages do not change state.
- Enables C10 diagnostics only if the dongle starts with a mounted USB stick and
  a regular file named **`AATestMode`**, with no extension. Otherwise C10 capture
  workers are absent and driver/AA output goes to `/dev/null`.

The mode is selected once per boot. Inserting USB later does not enable logging.
Removing it after a diagnostic boot stops USB exports; local diagnostic logging
continues until reboot. Quiet mode retains the functional geometry guard and
ordinary vendor/kernel logging. It does not make the adapter completely log-free.

## Compatibility and test status

Only **A15W / CPC200-CCPA, firmware `2025.10.15.1127`, with matching original
driver and startup files**, and the C10 geometry above. Matching a displayed
firmware version alone is insufficient. Other adapters and C10 software versions
have not been established as compatible. The observed AutoKit version was
`2024.08.06.1042`.

On the development dongle, the combined touch fix initially needed Show once;
two subsequent cold boots then had correct touch without Show. After the
boot-gated logging change, the owner reported a successful morning test on
25 October 2026. The USB/logging mode and cold-boot details for that report were
unspecified. **The clean-stock installer generated here has passed local tests but has not
been separately installed on hardware.** See [docs/VALIDATION.md](docs/VALIDATION.md).

**Stock firmware → C10 AutoKit Fix → optional unpatch to stock files.** No earlier
experimental patches are required or supported. Reinstall and recovery from a
partial installation of this same package are supported. Other modified firmware
and previous development installers are rejected; retain their own rollback.

## Inputs you supply

No vendor firmware, driver binaries, AutoKit APKs, device logs or compiled update
images are included in this Git repository. Builds use two local files:

| Input | Required SHA-256 |
| --- | --- |
| Original `A15W_Update_2025.10.15.1127.img` | `24589f1b71b95d87379ee2a10e130e939cd45c28bcd3ec328499f5bbd2bc477e` |
| Original, hardware-unpacked `ARMadb-driver.unpacked` (478664 bytes) | `0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee` |

Obtain matching originals you are entitled to use. The upstream repository's
`carlinkit/firmware_stock/` directory documents the stock firmware collection.
The builder checks the full hashes before patching; **do not edit the hashes to
force another firmware revision through**.

The unpacked driver is a real prerequisite. Desktop UPX cannot unpack this
hardware-encrypted variant. If you do not already have the exact file, follow
[docs/ORIGINAL_DRIVER.md](docs/ORIGINAL_DRIVER.md). That route requires existing
shell access to a matching stock dongle and a separately obtained hardware UPX
tool. This repo does not install SSH or automatically flash a collector.

## Build

Use Python **3.10 or newer** on Windows or Linux. The local reference build used
Python 3.14 on Windows, with Ubuntu WSL for additional shell tests. Python
packages are pinned in `requirements.txt`; no ARM compiler is required.

Put the two inputs in an `inputs` directory (ignored by Git). In PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe build.py --stock inputs/A15W_Update_2025.10.15.1127.img --driver inputs/ARMadb-driver.unpacked
```

On Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python build.py --stock inputs/A15W_Update_2025.10.15.1127.img --driver inputs/ARMadb-driver.unpacked
```

The builder verifies the ELF layout and executes the changed ARM paths in
Unicorn before emitting either image. Do not run Python with `-O`, which disables
the verification assertions.

Outputs:

| File | Purpose |
| --- | --- |
| `dist/patch/A15W_Update.img` | Complete C10 AutoKit Fix overlay for the matching stock baseline |
| `dist/unpatch/A15W_Update.img` | Paired rollback restoring the original packed driver and two startup scripts |
| `dist/patch/manifest.json`, `dist/unpatch/manifest.json` | Actual image and member hashes |
| `dist/validation.json` | ARM validation results and the input/output hashes |

The build writes files locally; it does not connect to or flash a dongle. No
earlier experimental images, log captures, absolute workspace paths or sibling
repositories are needed. Compression can vary with Python/zlib, so use your
generated manifests for your image hashes; the driver and runtime payloads are
pinned to the validated reference. The native touch driver and AA guard retain
their tested bytes; the public package uses the project name in its receipts,
diagnostic labels and provenance marker.

## Additional verification

Run the encrypted-archive checks and real Linux shell fixtures:

```powershell
.\.venv\Scripts\python.exe verify.py --stock inputs/A15W_Update_2025.10.15.1127.img --driver inputs/ARMadb-driver.unpacked --shell-tests
```

Windows needs an already configured WSL distribution with `python3` and ordinary
Linux command-line utilities. On Linux, run the same arguments with
`.venv/bin/python verify.py`. No ARM packages are needed inside WSL. Tests use
disposable directories and mocked projection programs; they do not flash or
contact the device. Without `--shell-tests`, archive and ARM checks still run.
Source-only unit tests need no firmware inputs:

```sh
python -m unittest discover -s tests -p "test_*.py"
```

## Install and unpatch

1. Build **both** images and keep their manifests and rollback available.
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

## Future firmware and agent instructions

[AGENTS.md](AGENTS.md) gives coding agents the scope, code map and validation
rules. [docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md) records the
investigation, rejected hypotheses, exact current hook locations, host-side
geometry clues and a procedure for investigating a new firmware revision.
The included read-only inspector helps locate code and strings in a new driver.
New firmware requires fresh analysis; changing a hash pin alone is not a port.

## Licence

Original tooling and these modifications are MIT-licensed; retain the notices
in [LICENSE](LICENSE). Vendor inputs and generated vendor-containing firmware
are separate third-party material. The project licence is not a grant of rights
to redistribute those inputs or generated binaries. See [THIRD_PARTY.md](THIRD_PARTY.md).
