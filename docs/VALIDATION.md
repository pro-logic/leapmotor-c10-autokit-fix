# Validation and limits

Local standalone validation completed on **25 October 2026 (Australia/Sydney)**.

The documented virtual environment was created from requirements.txt and the
new repo was built using only its own source and two explicit, ignored input
files. No historical C10 image or private capture was required. Python 3.14 on
Windows executed the ARM checks; an existing Ubuntu WSL distribution executed
the real `/bin/sh` fixtures. Hardware and projection programs were mocked in
the shell fixtures.

## Results

- **PASS** four source-only tests: encrypted format round trips and unaligned
  tail behavior, in-memory archive reading, unknown input refusal before output,
  and exact/unique startup edit anchors.
- **PASS** independent pyelftools inspection of every ELF program/section
  header, segment mapping/alignment, existing virtual addresses and section data.
  The original writable data stays intact; the added state is 32 bytes of BSS.
- **PASS** 256 differential Open cases, 2240 direct touch cases and 108 complete
  normalization/gesture cases in Unicorn. Covers flags, integer/VFP registers,
  stack, payload preservation, AA-only gating, clamp boundaries, state transitions
  and the logging call's arguments/return behavior.
- **PASS** actual encrypted archive member, mode, scope and driver hashes.
- **PASS** real shell install/reinstall/rollback/reapply; unknown model, firmware,
  script, driver, provenance and low-space rejection; copy/corruption/chmod/sync/
  rename failures; preservation of configuration, marker and historical files.
- **PASS** no USB, USB without marker, unmounted marker, directory marker,
  diagnostic boot, mount settling and timeout; actual AA/driver redirection;
  AA guard exit status and TERM forwarding; fixed boot mode after USB changes.
- **PASS** durable USB snapshot publication, three-snapshot retention, failed
  flush withholding and log bounding beyond the former 1800-iteration limit.

The two generated reference images are byte-identical to the community
fresh-stock images prepared during v13 development:

| Output | Bytes | SHA-256 |
| --- | ---: | --- |
| Patch | 274257 | `68f06c469458931c6c63247acf6a92d0239da5d8368f480f56a3ac856cfd84eb` |
| Unpatch | 220914 | `ef340f9bbe381ebdb9106e2fc26d13dbfdbf5ef449eb346ae3abb18861f38609` |

Patched driver SHA-256:
`0bed061a46ab214b2fa4c3b57c548e01e1f9a814f56295962035153651114d95`.

Guard SHA-256:
`47e383b6f7601d64214e7d70fd515ee59e0f26fedf6e9b7fa71a9476f19baf14`.

The generated dist/validation.json records the current build's checks and hashes.
Compressed image bytes can vary with Python/zlib; the runtime/driver pins remain
fixed. No firmware input or output is committed here.

## Hardware evidence

One development dongle using the v12 native driver had two user-reported good
cold car boots after Show was used once following installation. A readable later
capture confirmed the expected running driver and active correction. This does
not explain the initially unsuccessful post-install session.

The same dongle was upgraded to v13's scripts-only diagnostic mode change on
24 October. On 25 October the owner reported that v13 worked fine that morning.
That report did not specify USB/marker status, Show use or cold-boot count, and
no v13 capture was supplied at the time of this document.

The community fresh-stock installer and rollback generated here **have not been
separately exercised on hardware**. The manual original-driver exporter is also
not newly hardware-tested. The test suite does not emulate the full OS, USB
timing, Android AutoKit Views, flash power loss or different vehicles. Previous
captures included unexplained USB filesystem anomalies; this project does not
claim to have diagnosed or fixed their cause.
