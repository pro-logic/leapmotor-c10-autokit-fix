# Channel, storage and incoming-entry continuation

Historical research checkpoint: the later recognized-layout builder is described
in [GENERIC_PATCHER.md](GENERIC_PATCHER.md). It now generates validated local
experimental pairs under explicit native ownership/ABI/control-flow contracts.
The exhaustive proof gaps and earlier refusal statuses below remain research
limits; they are not claims that the current builder is unavailable.

26 October 2026, Australia/Sydney. Production generation is still refused.
The current work composes the three-hook plaintext-boundary experiment with
bounded channel/storage evidence and checks the actual emitted ELF spans.

## Native relationships

`generic_analysis.analyze_driver` now includes `channel_storage_evidence`.
`generic_channel.py` derives the AAP string-gated link channel's correspondence
with the touch packet channel and keeps the touch-selector and AAP link-state
globals distinct. It checks the dominating 16-byte touch source guard, payload
pointer definition and intervening register definitions.

Both the type1 response and touch paths call a type-preserving resize wrapper.
The wrapper moves length to r2, loads the existing packet type to r1 and tail
branches to the storage routine. The storage target must be derived from that
branch. Treating the wrapper itself as the allocator body caused both real
inputs to fail the earlier unfinished recognizer. The composition now refuses
to report conditional nonaliasing when either wrapper or storage checks fail.
Unsupported channel/source child contracts and incomplete touch control flow
also prevent the composite ownership conclusion.

The bounded storage grammar checks allocation, reuse, zero length, allocation
failure, mapping cleanup and imported function identities. For a nonzero length
without unsigned allocation overflow, successful storage yields a payload at
owner+96 with allocation overhead 192. This requires valid prior owner/capacity/
mapping state and the normal allocator/OS/callee ABI contracts. A local output
descriptor above SP is disjoint from newly saved hook scratch. These facts do
not prove all incoming descriptors, borrowed payloads or override callers have
that provenance.

Independent verifier landmarks, never production discovery selectors:

| Role | February | October |
| --- | --- | --- |
| Type-preserving resize wrapper | `0x62e9e` | `0x646fa` |
| Packet storage routine | `0x62e14` | `0x64670` |
| AAP/touch channel and selector | 9 / 5 | 9 / 5 |

## Incoming references and actual ELF checks

`generic_global_flow.static_entry_inventory` retains three separate inventories:

- Direct branches/calls at every Thumb halfword and ARM word of every file-backed
  executable LOAD. This includes executable bytes outside `.text` and conditional
  ARM calls. Capstone instruction IDs avoid missing condition-suffixed mnemonics.
- Absolute pointer candidates at every byte alignment of every file-backed LOAD,
  including unaligned data and potential readonly pointer runs.
- Supported ADR/PC arithmetic and adjacent MOVW/MOVT constructors throughout
  executable LOADs, including the last narrow Thumb halfword and conditional ARM
  constructors. Unresolved MOVT high halves remain explicit candidates.

An inventory is conservative. Numeric coincidences, wrong-ISA interpretations
and literal-pool decodes remain visible. A clean direct-branch inventory does
not establish the absence of computed or register-indirect targets. No firmware
source address is whitelisted to suppress a finding.

The real-input verifier protects all three displaced-instruction interiors and
the actual extended RX byte range, including its unwind prefix and alignment.
It does not use the larger 4096-byte planning budget as if all of it were mapped
new executable code. It independently checks ELF mappings, original byte
recovery, each hook transfer, the authoritative exception-index extension and
the observer's registered synchronous unwind frame. Empty `.eh_frame` handling
continues to preserve its four terminator bytes; nonempty overlaps are refused.

The broader scan retains a February ARM `bpl` candidate at `0x72114` into the
actual RX extension. Its bytes belong to `.rodata` without SHF_EXECINSTR, inside
an executable LOAD. The report records that section metadata without assuming
the candidate is a live instruction or discarding it as a numeric coincidence.
The earlier `.text`-only scan could not see it. This remains a conservative
candidate, not an established executed branch or a hardware fault.

## Verification and source identities

`verify_generic_contracts.py` runs 48 actual native storage scenarios per input:
three prior storage states, eight lengths and successful/failing allocation
contracts. It checks mapping cleanup arguments/order, ownership/capacity,
callee-saved registers/SP, bounded stack writes and unchanged unrelated globals.
Allocator and OS primitives are explicit host contracts. This is emulation,
not execution of vendor libraries or device hardware.

Source tests relocate storage/wrapper/channel fixtures and exercise changed
imports, guard/type/capacity mutations, clobbered payload registers, duplicate
routes, conflated globals, unaligned pointers, conditional ARM instructions,
scan-tail boundaries and exhausted audit budgets.

`generic_plan.SOURCES` now deterministically includes all root, test and tool
Python sources, runtime shell files, templates and requirements: 59 files at
this checkpoint. It excludes ignored inputs/output/dependency trees. Analysis,
drafts, native verifiers and runtime/package component reports use that same
complete identity set. Newly added source files invalidate older drafts too.
Reports produced before this expansion cannot establish complete current-source
coverage, even if their listed hashes still match.

Reproduce from the repository with its existing environment:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_*.py'
.\.venv\Scripts\python.exe verify_generic_contracts.py --driver <exact-native-ELF> --fixture february --output <NEW-report.json>
.\.venv\Scripts\python.exe verify_plaintext_experiment.py --driver <exact-native-ELF> --fixture february --output <NEW-plaintext-report.json>
```

Repeat for October. `--fixture` is an independent verifier oracle; generic
discovery does not use it. Reports refuse overwrite. Native experiments remain
in memory; neither command exports a modified vendor ELF or updater archive.
The contracts verifier saves bounded check results and the full entry inventory,
reports `component_checks=PASS` with overall `status=INCOMPLETE`, and exits 2 while
the entry/ownership gate remains refused. A refusal must not erase the evidence
or be counted as a completed generation proof.

## Remaining generation boundary

The checks establish bounded relationships and synchronous frame behavior.
All-caller ownership, complete indirect target/entry resolution, stack bounds
and asynchronous unwind scope remain unresolved. The ordinary Open hook's
fresh crypto-state read is still insufficient plaintext proof; the separate
three-hook experiment instead corrects only an explicit plaintext marker or
after the actual CFB call returns. That design has not been promoted into a
production audited-plan consumer.

Production native generation, paired archive emission and matrices using an
approved generated driver remain pending. Runtime/package component checks use
source-generated ELF stand-ins and must not be described as validating an
installable generic firmware pair. The separate C10 vehicle calibration and
all stable-path behavior remain unchanged.

## Source-bound local results

The final continuation run is retained under ignored
`dist/generic/continuation-20261026/source-bound-final/`. All 78 source tests
passed. Every analysis/native/runtime/package report binds the same 59 source
identities; the runner detected no source or source-file inventory drift.

| Check | February | October |
| --- | ---: | ---: |
| CFB relay/control preservation cases | 256 | 256 |
| Native helper cases | 588 | 588 |
| Guarded Open dispatch cases | 96 | 96 |
| Direct Open / direct touch cases | 160 / 1920 | 160 / 1920 |
| Full touch dispatch cases | 120 | 144 |
| Open/Show state sequences | 7 | 7 |
| Header / stream callback / seed writer cases | 60 / 6 / 20 | 60 / 6 / 20 |
| Native packet-storage scenarios | 48 | 48 |
| Linux runtime checks | 16 | 16 |
| Installer component matrix entries | 9 | 9 |
| Retained direct / absolute reference candidates | 1 / 33 | 0 / 3 |
| Retained partial MOVT constructors | 3 | 3 |

The native, admission/storage and Linux component checks passed; both entry
audits remain `INCOMPLETE` and refuse generation. Installer matrices used
source-generated ELF stand-ins. No approved generated-driver archive pair or
hardware installation is established by these results.

`run-summary.json` records commands, tools, source identities and report hashes.
`commit-bound-summary.json` additionally checks those report hashes, matches all
59 source files against the local Git commit, records preserved handover files
and binds recomputed non-authorizing proof drafts. Earlier interrupted or
development reports are retained and are not the final current-source evidence.
