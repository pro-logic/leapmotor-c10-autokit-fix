# C10 AutoKit Fix: instructions for coding agents

## Experimental branch workflow

On `feature/generic-firmware-patcher`, read [docs/GENERIC_PATCHER.md](docs/GENERIC_PATCHER.md)
first. Stable `main` remains at `6f8cb63085c8e0d650f7f33776819b0b20645d5e`.
Keep `build.py` and its validated single-firmware path intact. The new `generic.py`
currently inventories inputs, partially decodes plaintext packed extents and
reports restricted native candidates/incomplete proof drafts; it cannot emit
installable images. Read [docs/PACKED_DRIVER_RESEARCH.md](docs/PACKED_DRIVER_RESEARCH.md)
for the February code-block dependency and decoder-prefix simulation limits.
Do not promote a candidate match, insertion proposal, edited draft or matching unpack
attestation into proof of compatibility. An exact February unpacked driver with
verified provenance is still missing.

For the generic path, replace fixed pins only with explicit input pairing,
semantic discovery, audited plans and independent validation. Hashes remain audit
identities. Two hard-coded version profiles are not completion of the experiment.
Preserve stable reference outputs under `dist/reference`; use separate ignored
`dist/generic/<embedded-version>-<image-hash-prefix>/` directories. Do not merge,
publish or flash as part of this local experiment. Work sequentially.

## Purpose and scope

Build a **clean stock-to-fixed patch and a paired stock-file unpatch** for the
Carlinkit / MagicBox **CPC200-CCPA (A15W)** used with a Leapmotor C10. This is
a resolution/geometry and Android Auto touch fix. Development experiment
numbers are not product versions or installation prerequisites.

Preserve the causal sequence: with **Show Navigation Bar** enabled, the original
stock cold-boot fault was cropped AA video (top and bottom). In the tested HD
setup, overriding the car-requested resolution fixed that picture but introduced
a touch offset. The native touch adjustment compensates for that introduced
mismatch. Do not rewrite the history as a stock touch-offset bug.

Read [README.md](README.md), [docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md),
[docs/VALIDATION.md](docs/VALIDATION.md) and [THIRD_PARTY.md](THIRD_PARTY.md)
before changing behavior or porting to another firmware. The research guide
distinguishes observed behavior, verified native code and host-side inference.

## Repository map

| File | Responsibility |
| --- | --- |
| `build.py` | Explicit input pins, patch generation and mandatory native validation |
| `driver_layout.py` | Original ELF validation, Open-only reference and RX insertion |
| `driver_patch.py` | Combined Open gate, AA-only Y correction and log hooks |
| `verify_driver.py`, `tests/arm_harness.py` | Independent ELF checks and real ARM/Thumb emulation |
| `runtime_scripts.py` | Derives vendor startup scripts from stock; pins custom runtime files |
| `runtime/` | AA resolution/DPI guard, one-time USB boot selector and durable collector |
| `firmware.py`, `templates/` | A15W encryption/archive format and updater scripts |
| `package_overlay.py` | Stock baseline checks, RAM driver payload, checked atomic commit and unpatch |
| `verify.py`, `tests/shell_runtime.py` | Actual archive and disposable Linux shell tests |
| `tools/inspect_driver.py` | Read-only ELF mapping, string locations and disassembly |
| `tools/export_original_driver.sh` | Optional manual hardware unpack/export; needs existing shell access |

## Non-negotiable compatibility boundaries

- A displayed firmware version is insufficient. The stable builder pins the
  original update image, packed driver, exact hardware-unpacked ELF and startup
  scripts. Generic analysis records identities and refuses unproved semantics.
- Never make a new firmware pass by changing only a hash or copying old addresses.
  Re-find plaintext Open and AA touch handlers, re-check data flow and ABI, then
  implement independently validated discovery and generation on the experimental
  branch. Keep existing supported behavior intact.
- The public installer starts from matching **stock** files. Reinstall and
  partial-copy recovery may accept this same package's known bytes. Do not add
  dependency chains through old development installers or unknown custom firmware.
- An unpatch restores the exact original packed driver and stock startup files
  from that same input. Remove only helpers/provenance owned by this project.
  Preserve settings, USB marker, logs and unrelated files; do not claim a factory reset.
- Keep source Git-only: no vendor images/executables, private logs, device IDs,
  APKs or dependency caches. `inputs/`, `dist/` and `.venv/` are ignored. The MIT
  licence does not relicense vendor components.

## Implementation invariants

- Only a validated raw Open matching the target profile enables the correction.
  A different valid profile disables it; malformed Open must not alter state.
  Never gate on already-rewritten height, or Show can be corrected twice.
- AA-only normalized Y correction; preserve X, pointer/action packing, other
  channels and out-of-range behavior. The current 500/10000 value is empirical,
  not a universally measured physical-pixel offset.
- Preserve ELF mappings, original virtual addresses, dynamic/GOT/unwind data,
  register/flag/stack/VFP behavior and original writable file bytes. Do not guess a
  code cave or make the data segment executable.
- Keep the functional AA session guard independent from diagnostics. Quiet
  startup must not create capture workers or an idle USB poller. Boot-mode
  selection is fixed until reboot. Preserve bounded, synced diagnostic exports.
- Stage the driver under `./tmp` in the archive. Verify, chmod, sync and rename
  a same-directory persistent pending file for next boot; do not replace or kill
  the running projection process. Check install receipts, not just updater UI.

## Validation workflow

Use the Python environment and explicit local inputs described in README. Do not
run Python with `-O`. Routine local builds and tests do not need another permission
question. Work sequentially unless the user requests delegation.

```sh
python -m unittest discover -s tests -p "test_*.py"
python verify.py --stock inputs/A15W_Update_2025.10.15.1127.img --driver inputs/ARMadb-driver.unpacked --shell-tests
```

Use `.venv/bin/python` on Linux or `.venv\Scripts\python.exe` on Windows in place
of `python`. The shell fixtures need Linux or an existing Windows WSL distribution.
They relocate paths and mock hardware; they are not a hardware flash test.

After relevant changes, inspect generated patch **and** unpatch archives and
manifests. Re-run affected emulation and installer/runtime checks; check Git's
staged contents and `git diff --check`. An updated runtime pin needs an explained
source change, not just a matching digest.

State whether a result is static analysis, emulation, shell simulation, a user
report or an independently verified hardware capture. Build a reviewable local
candidate before requesting any missing publishing/flashing authorization.
Never describe a new stock installer or firmware port as hardware-proven based
only on the previous development dongle's success.
