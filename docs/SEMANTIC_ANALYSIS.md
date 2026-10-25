# Bounded semantic analysis and original-path emulation

Later result: [HOST_DECODING.md](HOST_DECODING.md) establishes the exact February
ELF, both native-layout checks and in-memory new-hook experiments. The missing-input
and no-new-hook statements below describe this earlier checkpoint.

25 October 2026. This advances the experimental generic patcher beyond local
instruction matches. Generation remains disabled. The complete verified February
ELF is still unavailable; no substitute has been used.

## Implementation and proof scope

`generic_flow.py` reads ELF-backed ARM unwind ranges and traverses Thumb code
from the enclosing range's entry. It follows direct branches and call returns,
records instruction boundaries, IT regions, predecessors, calls and dominance,
and keeps literal pools out of fallthrough traversal. It resolves the observed
ARM PLT veneers through their actual GOT relocations and dynamic symbol names.
Fixture addresses, firmware versions and whole-driver hashes do not select sites.

Only adjacent unsigned CMP/BHI-bounded TBB/TBH tables are supported. Table data
and ordered targets are part of the report/digest. Unknown indirect transfers,
outside edges, unsupported calls, instruction overlaps, entries inside IT/table
data, and bypasses around a table bound prevent a closed-range result. Unsupported
transfers do not silently become returns. Only BX LR and stack-based PC restores
qualify as bounded returns.

An unwind range is an analysis boundary, not a full function or ABI proof.
Direct calls are conservatively assumed able to return; their contracts remain
separate. Indirect/outside callers and arbitrary entries into an interior site
are not exhaustively enumerated. A closed bounded graph is not complete global
control-flow proof. Guard/routing conclusions are withheld if that graph has
unresolved transfers. Mandatory proof-draft capabilities remain unproved.

`generic_semantics.py` checks these narrower facts:

- Open length validation dominates the candidate hook within the bounded graph;
  the malformed-message branch cannot reach it. Every bounded incoming edge to
  the hook is recorded.
- A dominating preprocessing call receives the same message descriptor before
  dispatch. Its helper resolves to AES key setup and an in-place
  `AES_cfb128_encrypt` import, with the incoming zero direction reaching the
  conditional zero-direction stack store. Bypass conditions, key derivation,
  primitive correctness and external caller contracts remain unproved.
- Old r0-r3 values are overwritten before any read in the Open continuation.
  This is a straight-line integer-register result; it does not prove full
  flag/VFP/stack or interprocedural liveness.
- The touch channel stack store dominates normalization. Channel assignments,
  selector edges and selector storage are derived from control/data flow.
  Explicit SP writes on store-to-hook paths invalidate the derived offset.
- Displaced instructions report actual register reads/writes, flags, predicate
  status and PC dependence. No trampoline or relocation is generated.

`generic_geometry.py` starts from effective-Open pointer references reached in
the graphs, then checks restricted compiler shapes for four separate consumers:
the 28-byte type1 response, inner240/outer30 RemoteCxCy broadcast, AAP-gated link
parameters and the named 24-byte HU_SCREEN_INFO record. The box-info/type25 path
is not used as the RemoteCxCy evidence. Zero/multiple consumers stay visible;
the independent verifier requires a unique match for each expected role.

These grammars still constrain registers, object layout and compiler shape.
Relocation tests show address independence, not support for every compiler.
Interprocedural packet/IPC/OS contracts remain incomplete even where native
object construction executes successfully in the verifier.

## Independently checked October annotations

The following are verifier oracles for the exact October export, not discovery
constants. `verify_semantics.py` requires its SHA-256
`0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee`.

| Finding | Independent annotation |
| --- | --- |
| Shared dispatch range | `0x1dd98..0x1fc78`, 2555 reached instructions |
| Open hook / copy end | `0x1df00` / `0x1df38` |
| Dominating preprocessing call / helper | `0x1ddbe` / `0x17b74` |
| Helper's CFB import call | `0x17ee4`, resolves `AES_cfb128_encrypt` |
| Open old integer scratch values | r0-r3 overwritten before read |
| Touch hook / channel store | `0x1fae2` / `0x1faae` |
| Channel / output pointer stack offsets | `0x88` / `0x90` before any future hook prologue |
| Touch selector word | `0x11f460` |
| Selector to channel routing | 3→6, 5→9, 6→11, 7→13, 8→15; 20→161 |
| Type1 response function / copy | `0x1984c` / `0x19868` |
| RemoteCxCy function / inner build | `0x1b574` / `0x1b5c2` |
| AAP link geometry / channel | `0x1b8c0`, channel 9 |
| Link-state word | `0x11f4d0`; **distinct from touch selector storage** |
| HU geometry copy / named write call | `0x21d04` / `0x21e30` |

The link-state and touch-selector words both participate in familiar value 5
paths, but their storage is different. No shared-global claim is made. The
string-gated AAP link channel and the independently annotated touch route are
corroborating October evidence; further state-definition and IPC proof is needed
before automatically assigning AA meaning on another firmware.

## New emulation evidence

`tests/generic_arm.py` maps supplied ELF LOADs and derives scratch/stack/heap
space outside those mappings. Execution locations come from discovery, while
independent constants and behavioral expectations in `verify_semantics.py`
provide the oracle. It imports no stable patcher's October layout constants.
Actual packet initializer/resize/reference-object code runs in Unicorn.
Imported malloc/free/realloc are mocked with bounded allocations and pointer
checks; RemoteCxCy's diagnostic logger is mocked. These mocks clobber caller-saved
integer registers and flags. Unknown imports fail instead of becoming no-ops.

Validated on the unmodified October export:

- Seven Open-copy cases: matching/nonmatching/zero geometry and malformed
  lengths 0/27/29. Original/effective stores, untouched fields, source payload
  and the entire original writable mapping are independently checked.
- Four profiles through each of the type1, RemoteCxCy, AAP link and HU consumers
  (16 cases). Checks cover exact source geometry/payload, headers, destination
  arguments and preservation of original writable bytes.
- Three real RemoteCxCy function cases bypass inner240/outer30 when width or
  height is zero or Open state is closed.
- 432 native touch-dispatch cases: six selectors/channels, raw actions 14/15/16,
  pointers 0/7/255, signed X/Y extremes and normalization boundaries. These start
  at the selector's literal load, execute native routing, action translation,
  object construction and signed double normalization. Input coordinates and
  original writable bytes remain unchanged.

All IPC and named file-write calls stop before external I/O. HU copy and write
setup are separate slices, and AAP link emulation starts after the string gate
(the gate is checked statically). These checks validate original-path semantics;
they do not generate or emulate new hook code, prove a patched ABI, test the
OS/USB/flash, or establish hardware success. Stable patched emulation and shell
evidence remain separate and unchanged.

## Reproduction and evidence

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_*.py'
.\.venv\Scripts\python.exe verify_semantics.py --october-driver inputs/ARMadb-driver.unpacked --output dist/generic/semantics-20261025/native-validation.json
.\.venv\Scripts\python.exe verify_generic.py --october-stock inputs/A15W_Update_2025.10.15.1127.img --february-stock ../CPC200-CCPA_resources/carlinkit/firmware_stock/A15W_Update_2025.02.25.1521.img --october-driver inputs/ARMadb-driver.unpacked
```

Outputs refuse overwrite; choose new paths when repeating. The native report
records Python/Unicorn versions, implementation hashes, graph evidence and exact
limits. Fresh per-input `analysis-20261025-semantics.json` and
`proof-draft-20261025-semantics.json` accompany it; earlier reports are preserved.
The ignored `dist/generic/semantics-20261025/run-summary.json` binds the final
source commit and evidence hashes.

All 33 source tests pass. New fixtures cover relocated CFGs and channel stack
positions, a live bypass around an otherwise valid Open signature, skipped
literal pools, overlapping/outside edges, indirect transfers, IT-interior entry,
bounded tables and their bypass/data-target failures, invalid unwind indexes
and an SP change between channel store and touch hook.

Remaining generation gates are full outside-entry and interprocedural proof,
preprocessing conditions/key semantics, complete flag/stack/VFP alias liveness
and displaced-code relocation/branch checks, followed by new-hook emulation.
February's exact native decoding, stock-derived paired installers and their
archive/Linux shell checks remain necessary. No installable generic pair,
new installer shell simulation or hardware test exists at this checkpoint.
