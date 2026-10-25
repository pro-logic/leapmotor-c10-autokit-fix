# Exact February packed-driver investigation

25 October 2026. Evidence is host partial decoding and bounded decoder-prefix
emulation. No hardware was contacted, no AES plaintext was fabricated, and no
complete February unpacked ELF or installable generic image was produced.

## Input binding and result

The previously extracted February member was re-read from the genuine hashed
stock archive and compared byte for byte. The extraction request and original
analysis reports remain untouched in ignored `dist/generic/` output.

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| February stock image | 12585685 | `5c00b2e47aca6efc15625a1887ed857b1dceac691ff9dde96ac7de2f00adf8f8` |
| February packed member | 211424 | `baaa1ee60d43ee6a67264bb05dfcb7da9948c386c05a9e7c6be4568408e957cd` |
| February complete unpacked ELF | unknown | **Not obtained or verified** |
| October packed control | 216520 | `614fa754065dcecd7465bfdc283d551abdc0c1d630c9c0c76b520a4272867cdb` |
| October existing hardware-exported control | 478664 | `0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee` |

February has an ELF32 ARM executable container, three program headers, no
section table, and the obfuscated UPX magic `0x22552255` at file `0x98`.
Its metadata reports UPX format 23/version 13 and original size 469516. A literal
`UPX!` search finds nothing; absence of that string does not mean it is unpacked.

`generic_packing.py` reads this restricted container grammar using UPX v3.96's
`PackLinuxElf32::unpack` order: ELF/program headers, two LOAD extents, aligned
embedded loader, file gaps, and terminal marker. It validates extents and bounds,
then decodes only supported plaintext size-delimited LZMA1 blocks with Python
liblzma. It does not reverse the code filter, verify UPX checksums, decrypt AES,
reconstruct an executable, or treat any of these findings as patch authority.

February partial results:

| Extent | Packed header offset | Decoded bytes | Decoded SHA-256 |
| --- | --- | ---: | --- |
| Original ELF/program headers | `0xac` | 308 | `feabea6a9d6de999657bc2642dccc253166a9ce6c3c558eec917fe87fb6ee2e8` |
| Executable LOAD remainder | `0x149` | **Unresolved** | unknown |
| Writable LOAD data | `0x31eca` | 5184 | `578135d72fefb8d577b3c6b8485b545fbf9f2a84d1a5fe06e35b0300722bdf46` |
| Inter-LOAD file gap | `0x33748` | 1784 | `161e5073a0bdc6cd6a4842aae8e537e13998336cc3545fe0572174b8ae0160cd` |
| File tail / section metadata | `0x33767` | 1484 | `41e752ee8d47e46625ec4e4567061b641ca6ebce0d3aa043c34d92d64706ae48` |

The decoded headers describe RX file `0..0x70908` at VA `0x10000`, RW file
`0x71000..0x72440` at VA `0x91000`, RW memsz `0x8cec0`, entry `0x1599c`,
29 sections and a section table at file `0x72584`. This differs from October.
These headers describe the claimed original layout; they do not supply its
missing code or establish its functional semantics.

The executable block's compressed payload is at file `0x155`, length 204149,
SHA-256 `8bded7ef4b75a30057eed906566436de7edf12ebe74dde1dcca675e7e5a18576`.
Its prefix `45c1` fails UPX's LZMA property checks (`pb=5`, `lp=12` and an
inconsistent `lc+lp` encoding). It meets the published hardware-aware unpacker's
decrypt condition. Property failure alone would only establish an unsupported
stream; the actual loader supplies separate evidence of hardware AES use.

## Tool/source provenance and independent checks

The separately held tool was hashed, **not executed**: 1891214 bytes,
SHA-256 `c41472232b5eb4b3ca5ffa0ea7a677be7fd832a8a10446bd4ba4077964ad4f42`.
Its upstream identity remains `Debug_Tools/upx` at Ludwig commit
`b437135316275a5d3c375bdd1ceac2a6bcf1315b`.

Read sources, retained as ignored research inputs:

- [Pinned hardware-aware source patch](https://github.com/ludwig-v/wireless-carplay-dongle-reverse-engineering/blob/b437135316275a5d3c375bdd1ceac2a6bcf1315b/Debug_Tools/Source/upx-3.96/patchUPX.diff), SHA-256 `4a736766c1d514c715e9326bddf7e2aa6f29f3ac07779024abe1f4cc1cf8ad18`.
- [UPX v3.96 ELF format source](https://github.com/upx/upx/blob/v3.96/src/p_lx_elf.cpp), SHA-256 `506634e05ec9b15c6be14de2fbbc281c985a208d6328eadde04c85214e449590`.
- [UPX v3.96 LZMA source](https://github.com/upx/upx/blob/v3.96/src/compress_lzma.cpp), SHA-256 `616a9a47d414b0dd45b5de24085af61072051a98cee2d1509e83a40c9252b4a0`.

The source patch decrypts up to 8192 bytes through `/dev/hwaes` ioctl
`0xc00c6206`, then runs LZMA. It also changes checksum errors into warnings;
a successful exit would therefore require independent validation. The original
unmodified desktop UPX path cannot decode this invalid-properties stream.
No desktop-UPX binary was run or represented as the hardware-aware tool.

Independent ARM disassembly of February's loader at VA `0x4230c` shows it
constructing `/dev/hwaes` byte by byte. At `0x42410` it issues the same ioctl.
The 5192-byte loader at file `0x32300` has SHA-256
`879366f1e5e2c14e118a90fe2ab85343de26dfd26505dbf1ff2c2b6aa0b85342`.

`verify_packing.py` separately pins the two real inputs and annotated decoder
entry points. It emulates only the decoder prefix at entry+20, supplying the
compressed-block arguments directly. mmap and open are simulated; it stops at
the ioctl before providing any result. February requests the exact 204149-byte
input at file `0x155`. The embedded loader passes the whole compressed length;
the published host unpacker patch instead caps its request at 8192. These are
different paths and have not been assumed interchangeable without hardware.
Bootstrap, AES, subsequent decompression, and driver functionality are outside
this simulation. The report records Unicorn/Python versions, decoder extension,
implementation/source/tool hashes and the intercepted arguments.

As an independent positive control, every host-decoded October extent is
compared byte for byte with the existing exact hardware-exported October ELF:
308-byte headers, 5404 writable bytes and the 1484-byte file tail all match.
This validates those extent mappings and plaintext decoding on the control. It
does not validate the unresolved February code or grant cross-firmware pairing.

Initial failed research steps were a sandbox-denied source download, followed
by a successful approved download of the same public sources, and a manual
probe initially starting a block four bytes late. Reading UPX's actual metadata
layout corrected that probe to `0xac`; it is not used as decoding evidence.
An initial host probe requested one byte beyond UPX's explicit output size,
which interpreted size-delimited padding as extra data. The implementation now
requests exactly the declared size and independently matches October's export.
No complete February unpack was attempted against a device.

## Host-side proof and insertion work

`generic_plan.py` provides a deterministic **proof draft**, not an audited or
accepted generation plan. It binds image/packed/native/script and implementation
identities, the separate C10 profile, candidate original bytes/VA/file offset/
Thumb mode/return target, and mandatory functional proof slots. Incoming edges,
liveness, stack facts and logger ABI remain explicitly unknown. All required
proof slots remain unproved; matching source hashes or a receipt cannot fill them.
Recomputation rejects edits and stale inputs/sources. There is no apply API.

The insertion analyzer derives a conservative RX file insertion and aligned
file-offset shift, writable BSS extension, preserved section/interpreter hashes
and original RW hash from a supplied complete ELF. It rejects page collisions,
mapping inconsistencies, sections/segments crossing the insertion, unsupported
permissions, bounds and alignment. On October it independently recovers file
`0x732e0`, RX VA `0x832e0`, a 65536-byte shifted file gap, and state VA `0x120320`.
The default 4096-byte code and 32-byte state budgets are reservations for analysis,
not generated code. Hook slot assignment, branch reachability, instruction
relocation, generated-ELF preservation and independent native tests remain open.
February has no native insertion proposal because its exact complete ELF is absent.

## Reproduction and retained local evidence

From the repository, using the existing Windows virtual environment:

```powershell
.\.venv\Scripts\python.exe verify_packing.py --february-stock ../CPC200-CCPA_resources/carlinkit/firmware_stock/A15W_Update_2025.02.25.1521.img --october-stock inputs/A15W_Update_2025.10.15.1127.img --october-driver inputs/ARMadb-driver.unpacked --february-extracted dist/generic/2025.02.25.1521-5c00b2e47aca/unpack-input/ARMadb-driver.packed --hardware-upx ../CPC200-CCPA_resources/custom/tools/c10_driver_collector/upx --research-sources dist/generic/research-20261025 --output dist/generic/research-20261025/packing-validation-final.json
.\.venv\Scripts\python.exe generic.py draft-plan --stock inputs/A15W_Update_2025.10.15.1127.img --driver inputs/ARMadb-driver.unpacked --output dist/generic/2025.10.15.1127-24589f1b71b9/proof-draft-20261025.json
.\.venv\Scripts\python.exe generic.py draft-plan --stock ../CPC200-CCPA_resources/carlinkit/firmware_stock/A15W_Update_2025.02.25.1521.img --output dist/generic/2025.02.25.1521-5c00b2e47aca/proof-draft-20261025.json
```

These outputs refuse overwrite. Use a new filename when repeating a run.
Fresh `analysis-20261025-packing.json` files accompany both drafts. Private
partial bytes and downloaded sources stay ignored; this document contains only
methods, identities and results. Earlier `dist/reference` outputs were preserved.

Validation: 22 source tests pass, including malformed/oversized packed extents,
changed metadata/terminator, relocated layouts, virtual gap collisions, mapping
errors, edited capability status, stale source/input identities and missing native
input. The existing two-image generic verifier passes, including stable reference
image and member hashes and refusal of October's ELF as verified February input.
Windows temp-directory tests required the existing approved execution route
outside the restricted sandbox; assertions were retained.

## Precise dependencies and evidence limits

The known route now has an exact dependency: a compatible authorized kernel
`/dev/hwaes` service capable of ioctl `0xc00c6206` on a RAM copy of February's
exact packed input, plus independent validation of the resulting complete ELF.
No hardware endpoint/access was established. A verified host implementation of
that transformation could replace hardware, but none was established here.
This investigation does not prove that no host-only solution exists.

A later decode must preserve packed/tool identities, capture output size/hash,
check complete ELF mappings and meaningful code/data, compare the plaintext
extents above, and independently establish decoding of the encrypted/filtered
code. The existing exporter is still installed-October-specific and must not be
used as a generic February exporter. Do not flash, install or run February's driver
to get an export. No October or unverified research ELF was substituted.

Static candidate discovery and insertion arithmetic have advanced. New native
generation/emulation, full functional control/data-flow/channel/ABI proofs,
stock-derived installer pairs, and their shell fixtures remain incomplete.
The decoder-prefix emulation is separate from the previously passing stable
functional emulation. No new installer shell simulation or hardware test was
performed in this continuation; prior stable shell evidence remains unchanged.
Milestones C/D/E and the two-firmware experiment remain incomplete.
