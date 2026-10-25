# Experimental generic A15W patcher

Local checkpoint: 26 October 2026, Australia/Sydney.

The current continuation is documented in
[CHANNEL_ENTRY_CONTRACTS.md](CHANNEL_ENTRY_CONTRACTS.md) and
[ADMISSION.md](ADMISSION.md). It integrates bounded native channel/storage
relationships, actual-span hook/unwind/entry audits, stock-derived runtime and
paired installer components. Source identities now cover all 59 files in the
implementation/test tree. The plaintext-safe three-hook experiment corrects
explicit plaintext Open or encrypted Open after the actual CFB return; it never
uses inactive crypto state as plaintext proof. Production audited generation
and installable generic pairs remain unavailable. The earlier checkpoints below
describe their historical scope and test counts.

Latest continuation: [MESSAGE_CRYPTO.md](MESSAGE_CRYPTO.md) checks both layouts'
conditional Open CFB behavior and key/IV construction. Encrypted Open with
inactive crypto state can reach the hook unchanged under explicit callee mocks;
unconditional plaintext remains unproved. This concrete blocker is now exposed
in analysis and non-authorizing proof drafts. No generic installer exists.

The branch is `feature/generic-firmware-patcher`, based on stable `main` at
`6f8cb63085c8e0d650f7f33776819b0b20645d5e`. The stable builder, native patch,
runtime scripts and packaging are unchanged. No generic installer exists yet.

The target is semantic discovery for compatible A15W ARM firmware, with the
tested C10 vehicle profile kept separate. It is not support for arbitrary
vehicles, architectures or firmware. The original fault was cropped AA video;
the resolution override introduced a touch mismatch, and the native correction
compensated for that introduced mismatch.

## Commands

Use the existing `.venv` described in the main README. From the repository:

```powershell
.\.venv\Scripts\python.exe generic.py analyze --stock inputs/A15W_Update_2025.10.15.1127.img --driver inputs/ARMadb-driver.unpacked
.\.venv\Scripts\python.exe generic.py analyze --stock ../CPC200-CCPA_resources/carlinkit/firmware_stock/A15W_Update_2025.02.25.1521.img
.\.venv\Scripts\python.exe generic.py extract-driver --stock ../CPC200-CCPA_resources/carlinkit/firmware_stock/A15W_Update_2025.02.25.1521.img
.\.venv\Scripts\python.exe generic.py unpack-driver --stock ../CPC200-CCPA_resources/carlinkit/firmware_stock/A15W_Update_2025.02.25.1521.img --kernel ../CPC200-CCPA_resources/custom/kernel_dumps/kernel_ram_dump_0x80008000.bin
.\.venv\Scripts\python.exe generic.py draft-plan --stock inputs/A15W_Update_2025.10.15.1127.img --driver inputs/ARMadb-driver.unpacked
```

Sibling workspace paths above describe these local samples, not a required
repository structure. Any supplied stock path is accepted for inventory if its
actual contents meet the archive/product rules. Default outputs are ignored:

```text
dist/generic/<embedded-version>-<image-sha256-first-12>/analysis.json
dist/generic/<embedded-version>-<image-sha256-first-12>/unpack-input/ARMadb-driver.packed
dist/generic/<embedded-version>-<image-sha256-first-12>/unpack-input/request.json
```

Reports and extraction directories refuse overwrite. Use another `--output`
to retain repeated analyses. `analyze` exits successfully when it creates a
report, including an incomplete/refusal report; inspect `patchable`, which is
always false in this checkpoint. Invalid archives fail before output creation.
`extract-driver` extracts packed bytes only. Analysis now inspects the observed
packed format and partially decodes plaintext blocks on the host; it cannot
decode the encrypted executable block without the explicit audited `--kernel`
input. That host route now reproduces both exact native ELFs; see below.
`draft-plan` writes a source/input-bound incomplete proof draft. None of these
commands connects to a device, executes vendor code, or installs firmware.

## Current host decoding and native experiments

[HOST_DECODING.md](HOST_DECODING.md) records the resolved February input and
supersedes the earlier decoding blocker. A software CBC recipe recovered from
an already-held kernel snapshot reproduces October's entire hardware export and
decodes February's own exact packed member with both UPX checksums enforced.
An independent emulated ARM LZMA backend agrees on both code blocks.

The decoded February ELF is 469516 bytes, SHA-256
`a9fb4ed7aef64a5a7a9cbc221582bcb2716421fc19904a5eafba2e57c6d09eba`.
Use `unpack-driver --kernel ...` to save a new ignored `host-unpack/` directory,
or `analyze/draft-plan --kernel ...` to reproduce and verify the native pairing.
A supplied `--driver` must match the reconstruction exactly. No kernel bytes,
key values or vendor executables are bundled in source. No hardware was accessed.

Recognition now handles observed register/scheduling differences, two/three
argument sender shapes and checked register/stack HU field stores. Both inputs
have independently checked Open, touch and all four geometry consumers.
Original-path dispatch emulation passes 432 October and 360 February cases.
In-memory native hook fixtures also pass preservation and Open/Show sequence
checks; they expose no experimental ELF/update export command. Production
generation remains disabled until full proof and audited-plan gates are met.

## Earlier partial decoding investigation and proof drafts

The following paragraphs describe the earlier checkpoint; the encrypted-block
and missing-February-ELF limits were resolved by the host route above.

The continuation reverified February's extracted packed member byte for byte
against the hashed genuine image. It identified the actual obfuscated UPX
container and host-decoded the original headers, writable bytes and file gaps.
The 204149-byte code block remains unresolved. Independent disassembly and
bounded ARM decoder-prefix simulation observe a `/dev/hwaes` ioctl request for
that exact input; no syscall was sent to hardware or invented plaintext returned.
See [PACKED_DRIVER_RESEARCH.md](PACKED_DRIVER_RESEARCH.md) for all identities,
source/tool provenance, commands, evidence and precise missing dependency.

`generic_plan.py` now derives a conservative two-LOAD insertion proposal from
complete ELF mappings. Relocated fixtures and independent October annotations
check the arithmetic. Drafts bind original image/packed/native/script and
implementation hashes, candidate hook bytes/sites and required proof slots.
Mandatory proofs remain unproved; drafts are not audited generation plans.
`validate_draft` recomputes the whole draft and rejects edits/stale sources or
inputs. It always returns `generation_allowed=False`. No apply/build API exists.

`verify_packing.py` pins real fixture annotations independently, compares all
plaintext October extents with the existing exact hardware export and simulates
only the decoder-prefix mmap/open/ioctl path. It records Python/Unicorn/decoder,
implementation, unpacker and downloaded source hashes. This is distinct from
full native functional emulation, shell simulation and hardware evidence.

The continuation's 22 source tests and both real-input verifiers pass. Fresh
packing analyses and proof drafts are retained beside the earlier reports; the
packing verifier is under ignored `dist/generic/research-20261025/`. Stable
source and reference artifacts remain unchanged. Full functional proofs,
new generation and paired generic installers remain incomplete.

## Bounded semantic evidence

The next continuation adds recursive Thumb traversal within ELF unwind ranges,
ELF-backed ARM PLT/import resolution, bounded dominance and incoming-edge checks,
derived touch channel/stack routing and four separate geometry consumer checks.
See [SEMANTIC_ANALYSIS.md](SEMANTIC_ANALYSIS.md) for proof scope, annotations,
adversarial fixtures and reproduction commands.

The independent original-path verifier passes seven Open cases, sixteen geometry
cases, three RemoteCxCy guard cases and 432 native touch-dispatch cases. Native
packet object code runs; allocator/diagnostic I/O boundaries are mocked and IPC
stops before external I/O. These are new **unmodified-path** emulation checks,
not new hook generation, installer shell simulation or hardware evidence.
All 33 source tests pass. Mandatory full proof slots remain unproved and both
`patchable` and `generation_allowed` remain false.

## Inventory and candidate boundaries

`generic_inventory.py` reads the encrypted archive in memory with input,
decompression and member-count limits. It validates normalized paths, duplicate
members, non-directory ancestors, mode bits and member types before using
required regular files. It allows only the two specific vendor OpenSSL library
aliases observed in these samples, requires their regular targets, and never
follows links. Other links, devices, FIFOs and contiguous/sparse types are
unsupported. Reports record every member's identity/mode/type and the real
embedded product/version. Only embedded A15W is accepted.

`generic_analysis.py` validates file-backed ELF mappings and searches `.text`
for a restricted Thumb compiler shape. Candidate selection uses no firmware
version, full-image/driver hash or October address. The Open candidate requires
a 28-byte length check, payload-pointer load, structure-copy data flow, distinct
writable original/effective structures and a nearby literal xref to the geometry
format. The touch candidate requires separate X/Y loads, signed conversions,
double division by a file-backed `10000.0` literal, size/type fields and gesture
packing. Candidate reports include actual addresses, file offsets, original
bytes, instruction mode and local evidence. Zero and multiple candidates remain
unsupported; no first-match selection occurs.

This grammar still restricts registers and compiler layout. It is a first
candidate detector, **not completed version-independent semantic recognition**.
Its newer bounded supporting evidence does not complete proof of decryption, all
incoming edges, downstream geometry consumers, AA channel selection, stack/ABI
facts, register liveness, logger ABI or a safe insertion layout. These missing
facts appear as blockers; no candidate is an audited patch plan.

The previously documented October image/packed/unpacked hash tuple is labeled
`documented-reference`. Other tuples remain `unverified`. Optional `--provenance`
accepts a JSON `c10-unpack-attestation-v1` containing `image_sha256`,
`packed_driver_sha256`, `unpacked_driver_sha256` and a nonempty `method`.
Mismatches fail. A matching new attestation remains
`matching-attestation-unverified`: a hash-bound claim does not independently
prove decoding. No arbitrary receipt grants native support.

## Local evidence

Milestone A passed. The unchanged October builder's native, archive and real
Linux shell fixtures reproduced all four reference identities:

| Object | SHA-256 |
| --- | --- |
| Native ELF | `0bed061a46ab214b2fa4c3b57c548e01e1f9a814f56295962035153651114d95` |
| AA guard | `47e383b6f7601d64214e7d70fd515ee59e0f26fedf6e9b7fa71a9476f19baf14` |
| Patch image | `fbfa6226cf8e364f2bda352cd9ef255f2e0ecfd5b61a7e2ee532ad3b82d354fb` |
| Unpatch image | `6de11c46e740945c4e0cc93f340409cc358ba84380914bdf71893dd034cad0cf` |

Reference output and validation are retained at `dist/reference/`. Validation
includes 256 differential Open cases, 2240 direct touch cases, 108 complete
normalization/gesture cases, decrypted archives and disposable WSL install,
rollback, failure and runtime fixtures. These are stable October checks, not
validation of new native generation. Commands:

```powershell
.\.venv\Scripts\python.exe verify.py --stock inputs/A15W_Update_2025.10.15.1127.img --driver inputs/ARMadb-driver.unpacked --output dist/reference --shell-tests
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
.\.venv\Scripts\python.exe verify_generic.py --october-stock inputs/A15W_Update_2025.10.15.1127.img --february-stock ../CPC200-CCPA_resources/carlinkit/firmware_stock/A15W_Update_2025.02.25.1521.img --october-driver inputs/ARMadb-driver.unpacked
```

Milestone B is partial. Both genuine images pass inventory; independent October
annotations confirm candidate Open `0x1df00`, touch `0x1fae2`, structures
`0x11f40c`/`0x11f3d4`, format `0x6e67f` and divisor `0x1fc60`. Source-only tests
use newly assembled synthetic ELF fixtures at different base addresses and a
different file layout, duplicated plausible Open blocks, changed length/divisor,
unsupported permissions, hostile archives, mismatched attestations and output
overwrite attempts. Passing these tests demonstrates the limited detector's
behavior, not compatibility with a second native firmware layout.

| Input | Image SHA-256 | Packed driver SHA-256 | Native status |
| --- | --- | --- | --- |
| February `2025.02.25.1521` | `5c00b2e47aca6efc15625a1887ed857b1dceac691ff9dde96ac7de2f00adf8f8` | `baaa1ee60d43ee6a67264bb05dfcb7da9948c386c05a9e7c6be4568408e957cd` | Exact ELF reproduced by checked host decode; see later host checkpoint |
| October `2025.10.15.1127` | `24589f1b71b95d87379ee2a10e130e939cd45c28bcd3ec328499f5bbd2bc477e` | `614fa754065dcecd7465bfdc283d551abdc0c1d630c9c0c76b520a4272867cdb` | Stable reference reproduced; static candidates found |

The local research ELF with SHA-256
`b86533cad6096311874f26281871d258ca289b23ebc36148a6a1d5e543d5ef46`
has no established February pairing. Static analysis found one Open candidate
and zero supported touch candidates. It is retained only as an unverified
research input outside the repository. It must not replace February's exact
host-decoded export. No hardware access or hardware decoding was attempted.

## Remaining work

1. Preserve/reproduce both host-decoded inputs and provenance when changing the
   decoder or kernel recipe. Exact February decoding is now complete; do not
   substitute the unverified research ELF or use the installed-October exporter
   as a generic exporter. See [HOST_DECODING.md](HOST_DECODING.md).
2. Complete functional semantic proofs, including downstream consumers and AA
   channel/ABI facts. Independently verify each real native layout. Add broader
   compiler shapes deliberately; one familiar format or instruction is not proof.
3. Emit explicit audited plans and derive insertion/state mappings; parameterize
   native generation and independent emulation. Keep source-byte and stale-plan
   checks and retain the separate C10 profile. Do not loosen the stable pins.
4. Derive scripts from each supplied stock image, generate exact paired rollback
   payloads, parameterize model/version/provenance checks and exercise both
   stock-specific package pairs with native/archive/shell tests.
5. Report experimental per-input results with their evidence level and limits.
   Hardware success on either new installer remains unestablished. Do not merge
   into stable, publish vendor files, push or flash without separate scope.

Milestones C, D and E are incomplete. This checkpoint is a reviewable analysis
foundation, not completion of the two-firmware experiment.
