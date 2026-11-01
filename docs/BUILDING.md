# Building from source

Run these commands from the repository root. These instructions cover the
original builder for stock A15W firmware `2025.10.15.1127` on `main`.
The experimental generic builder is maintained separately on
`feature/generic-firmware-patcher`; see its
[generic patcher documentation](https://github.com/pro-logic/leapmotor-c10-autokit-fix/blob/feature/generic-firmware-patcher/docs/GENERIC_PATCHER.md).

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
[docs/ORIGINAL_DRIVER.md](ORIGINAL_DRIVER.md). That route requires existing
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
