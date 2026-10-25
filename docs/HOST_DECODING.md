# Host decoding and two-input native experiments

25 October 2026. **The exact February native input is now reproducible on the
host.** This supersedes the decoding blocker recorded in the earlier packing
and semantic checkpoints. No device access or new hardware capture was needed.
Generic installable-image generation remains disabled pending the remaining
proof and packaging gates.

The subsequent [message-CFB checkpoint](MESSAGE_CRYPTO.md) establishes conditional
Open preprocessing/key/IV evidence and an inactive-state plaintext counterexample
under explicit import/diagnostic mocks. It does not change this packed-file CBC
decoding result or establish an unconditional plaintext hook boundary.

## Exact inputs and decoding result

| Object | Bytes | SHA-256 |
| --- | ---: | --- |
| February genuine image | 12585685 | `5c00b2e47aca6efc15625a1887ed857b1dceac691ff9dde96ac7de2f00adf8f8` |
| February exact packed member | 211424 | `baaa1ee60d43ee6a67264bb05dfcb7da9948c386c05a9e7c6be4568408e957cd` |
| February host-decoded ELF | 469516 | `a9fb4ed7aef64a5a7a9cbc221582bcb2716421fc19904a5eafba2e57c6d09eba` |
| October packed control | 216520 | `614fa754065dcecd7465bfdc283d551abdc0c1d630c9c0c76b520a4272867cdb` |
| October host-decoded/exported control | 478664 | `0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee` |

The decoder reproduces October's existing hardware-exported ELF **byte for
byte**, then applies the same transformation to February's own packed bytes.
Neither October's ELF nor the unverified research ELF was substituted for
February. All decoded binaries, partial probes and captures remain ignored.

## Method and independent evidence

An already-held kernel RAM snapshot at
`../CPC200-CCPA_resources/custom/kernel_dumps/kernel_ram_dump_0x80008000.bin`
contains the `/dev/hwaes` ioctl implementation and its software material.
Its SHA-256 is `8ab82dbbc95b2a5bb9d7dad26b100aa476a4496ab336f8930be98b660cc9965c`,
size 8388608, mapped from VA `0x80008000`. Its companion symbol file identifies
`dcp_ioctl` at `0x80294004`. This held snapshot is an analysis input, not evidence
of a new connection, a February kernel, or a hardware test in this run.

Disassembly identifies the `0xc00c6206` case at `0x8029424c`: it copies two
16-byte software values through literals at `0x802946bc` and `0x802946c0`, then
uses the CBC decrypt path on the first 8192 bytes. `generic_unpack.py` accepts
only this audited snapshot identity for that extraction recipe. Kernel bytes,
actual key/IV values and vendor tools are not bundled in source.

The referenced key and IV have SHA-256 identities
`b09cde62355f38a48878177721971d21b768f8ac7dd4cc93574692e5a1b1acb3` and
`fdeb9f8c199580cd98a0015a637dc3c2e24c7756da28ae4dbce35726382dfae2`.
The earlier notes about hardware-bound OTP kernel-image encryption concern a
different operation; they do not describe this packed-executable ioctl case.

The host pipeline is:

1. Inventory the genuine image and obtain its exact packed archive member.
2. AES-128-CBC decrypt the first 8192 compressed bytes, retaining the remainder.
3. Decode UPX's size-delimited LZMA1 stream and reverse ARM filter 50 per block.
4. Reconstruct every original file byte from nonoverlapping, complete extents.
5. Enforce the pack-header checksum, compressed Adler32, uncompressed Adler32,
   original lengths, footer/overlay bounds, ELF entry and section mappings.

Both stored Adler32 values pass for both inputs. February's uncompressed checksum
is calculated in UPX block order (headers/code/RW/gaps), not final file order;
its inter-LOAD file gap makes those orders different. The compressed checksum
covers original ciphertext bytes, not the transformed plaintext stream. The
legacy tool's checksum-warning behavior is not copied or used as a bypass.

`verify_host_unpack.py` additionally emulates each packed file's actual ARM
LZMA routine to completion. It supplies host CBC at the mocked ioctl boundary,
intercepts mmap/open/close/munmap/cacheflush and compares the ARM decompressor's
entire output with Python liblzma. Both agree exactly. This is independent
decompressor evidence; AES is still provided by host crypto, not hardware.

Format sources consulted and saved as ignored research inputs are UPX v3.96
[filter implementation](https://github.com/upx/upx/blob/v3.96/src/filter/ct.h),
[Unix extent decoding](https://github.com/upx/upx/blob/v3.96/src/p_unix.cpp) and
[pack headers](https://github.com/upx/upx/blob/v3.96/src/packhead.cpp).
Their SHA-256 identities are respectively
`c2c177abda7f45d8fd0cf33e503418aa0b3419c74b68f8184ae805f0c01910fa`,
`52b5af3fdad74b3d17e403e8bc1d1598c8589a5ac212c8035273ce245cb5a7ac` and
`dc25386d4ce293183b3dc10889d9bc3c513df2ea9168f2f000cea9f9aadffec5`.
The Python filter expresses the operand arithmetic independently; upstream
source and the separately held hardware UPX executable are not vendored.

## Genuine February layout differences

The same discovery path now recognizes both real native inputs. It derives
header-length/type registers and action packing roles rather than fixing
October's allocation. It accepts the checked independent integer load scheduled
between February's VFP conversions and handles a stack-based HU record. Changed
header order, clobbered data flow, unsupported schedules and ambiguous sites
remain refusals.

| Finding | February | October |
| --- | --- | --- |
| Open hook | `0x1d442` | `0x1df00` |
| Y hook | `0x1ebea` | `0x1fae2` |
| Header size/type registers | r0/r2 | r2/lr |
| Action register | r7 | sl |
| Divisor literal | `0x1ed50` | `0x1fc60` |
| Channel/output-pointer stack offsets | `0x88`/`0x90` | `0x88`/`0x90` |
| Touch routes | 3→6, 5→9, 6→11, 7→13, 20→161 | adds 8→15 |
| Type1 sender arguments | two | third argument explicitly zero |
| HU record destination | `sp+0x28` | r4 |

These addresses are independent verifier annotations, not discovery selectors.
Both inputs pass seven original Open cases, sixteen geometry cases and three
RemoteCxCy guard cases. February passes 360 native dispatch cases, October 432,
including signed extremes, action/pointer packing and source/RW preservation.

## In-memory native experiments

`tests/native_experiment.py` derives RX insertion, aligned file shifts, BSS state,
hook branches/returns and saved-stack offsets from each source ELF/analysis.
It assembles only inside a test fixture and exposes no file-writing or update
image API. The generic CLI still has no build/apply command or override.

The experimental Open hook replays the original load, saves integer temporaries
and flags, checks length/type again, records raw geometry and gates exactly
2560×1440 before rewriting height to 1296. Other valid profiles disable the gate;
malformed messages preserve state. The AA Y hook derives its channel from the
AAP link evidence, preserves integer/flag/VFP state and corrects only eligible
Y with `max(0,Y-500)`. It leaves payload coordinates and X untouched. Diagnostic
logger hooks are omitted; no guessed logger ABI is introduced.

For each real layout, independent checks cover all program/section headers,
original writable/dynamic/GOT/unwind bytes and declared hook edits, 160 direct
Open cases, 1920 direct Y cases, and full native dispatch (120 February / 144
October). All NZCVQ combinations, GE patterns, integer registers, 32 VFP registers,
SP/LR and bounded saved-stack scratch are checked. Seven repeated Open/Show/
malformed transitions verify cold-state disabling and no accumulated/double shift.

These are **new code generated only in memory for emulation**. They establish
pending ABI/insertion evidence; they are not audited generation plans, released
drivers, generic installers or hardware evidence. No experimental ELF is exported.
The decoded original ELFs above are saved separately as prerequisites.

## Commands and saved evidence

```powershell
.\.venv\Scripts\python.exe generic.py unpack-driver --stock ../CPC200-CCPA_resources/carlinkit/firmware_stock/A15W_Update_2025.02.25.1521.img --kernel ../CPC200-CCPA_resources/custom/kernel_dumps/kernel_ram_dump_0x80008000.bin
.\.venv\Scripts\python.exe generic.py analyze --stock ../CPC200-CCPA_resources/carlinkit/firmware_stock/A15W_Update_2025.02.25.1521.img --driver dist/generic/2025.02.25.1521-5c00b2e47aca/host-unpack/ARMadb-driver.unpacked --kernel ../CPC200-CCPA_resources/custom/kernel_dumps/kernel_ram_dump_0x80008000.bin --output dist/generic/2025.02.25.1521-5c00b2e47aca/analysis-host.json
.\.venv\Scripts\python.exe verify_semantics.py --driver dist/generic/2025.02.25.1521-5c00b2e47aca/host-unpack/ARMadb-driver.unpacked --fixture february --output dist/generic/host-decode-20261025/february-native.json
.\.venv\Scripts\python.exe verify_native_experiment.py --driver dist/generic/2025.02.25.1521-5c00b2e47aca/host-unpack/ARMadb-driver.unpacked --fixture february --output dist/generic/host-decode-20261025/february-hook-final.json
```

Outputs refuse overwrite. The equivalent commands accept October's image and
fixture. `--kernel` replays the decode and checks supplied native bytes; a matching
JSON receipt alone still grants no verified pairing. The status is
`reproduced-host-decode`, independent of stock version/full-file whitelists.
Unknown kernel recipes, changed ciphertext/checksums or wrong native pairs fail.

Canonical originals and per-input evidence live under each version's ignored
`host-unpack/`. `dist/generic/host-decode-20261025/` contains independent decode,
both original-path/native-hook reports, source tests and the commit-bound run
summary. Earlier reports and stable reference outputs are retained.

Remaining work is complete outside-entry, crypto-condition and interprocedural
proof; audited plan acceptance; production native generation; stock-derived
paired script/installers and archive/Linux shell validation. No hardware
dependency blocks these two native inputs now. Unknown future packing/key/code/
script layouts must still be rejected. Two native fixtures do not establish
support for all firmware or that another firmware/car needs this C10 profile.
