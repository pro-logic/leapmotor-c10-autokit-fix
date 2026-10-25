# Bounded native callback admission and crypto-state writer evidence

25 October 2026. `generic_admission.py` derives a readonly virtual-method table,
the matching callback/reader grammar, the reader's header predicate and a
positive type240 crypto-state writer from each exact native input. The evidence
is read-only and non-authorizing. No firmware hash, version or oracle address
selects a discovery result.

## What the transport actually admits

The reader's small header leaf accepts either its plaintext marker or its
encrypted marker, provided the fourth word is the bitwise inverse of the third
(message type). It does not authenticate payload contents, bound payload length
to Open's 28 bytes, or test crypto readiness. Open's later length check remains
separate. Marker values are derived from the leaf's literal and addition and
cross-checked against the independently discovered message-CFB marker.

On both exact fixtures, the discovered dispatch pointer occurs in a readonly
Itanium-style vtable for `CAccessory_fd`, at slot24 from the address point. A
native callback invokes that slot after its embedded packet reader returns
nonzero, unless an explicit callback override is installed. The reader has
stream and recvmsg/ancillary-FD routes to the same checked header leaf.

The independent verifier executes the actual callback, stream reader, packet
object allocation and indirect virtual transfer. A valid encrypted header and
28 supplied payload bytes reach dispatch unchanged with crypto state -1, 0 or 1.
Only getsockname/read and allocator boundaries are mocked for this path. Thus
transport header validation cannot supply the missing positive crypto-state
invariant. This does not establish all real session ordering or caller contracts.

## Crypto state installation and initial value

The dispatch type240 arm requires length4 and a signed positive first payload
word. It constructs/sends an acknowledgement, then reloads the payload pointer
and stores its first word through the unchanged literal-backed r4 state pointer.
The source type load, compare, guard branches, pointer definition and store are
checked. Native helper calls are assumed to preserve r4/r6 and the supplied
descriptor/payload; their external effects remain separate contracts.

Both state words lie in the writable LOAD's zero-filled memory tail. Standard
ELF loading therefore starts them at zero. This is not an exhaustive proof of
all aliases/writers, subsequent initialization or concurrency. It provides no
permission to infer that a fresh positive state read proves an earlier decrypt.

Independent fixture landmarks, never discovery selectors:

| Role | February | October |
| --- | --- | --- |
| Vtable address point | `0x6afd8` | `0x6cae8` |
| Virtual callback instruction | `0x62b38` | `0x64394` |
| Callback function entry | `0x62b10` | `0x6436c` |
| Native packet reader | `0x62fd0` | `0x6482c` |
| Header predicate leaf | `0x62d90` | `0x645ec` |
| Crypto state word | `0x11d03c` | `0x11f408` |
| Type240 positive-payload guard | `0x1e8b4` | `0x1f798` |
| State store | `0x1e8e4` | `0x1f7ca` |

## Verification and limits

`tests/test_generic_admission.py` has four source-only tests using relocated
source-generated fixtures. They reject changed marker/inverse predicates,
crypto-marker disagreement, invalid RTTI/member pointers, changed callback
arguments/reader gates, changed length/sign guards, a wrong type source and a
clobbered state pointer. Ambiguous vtable members remain candidates; no first
match is selected.

`verify_admission.py` independently pins each exact native fixture and runs:

- 60 actual header-leaf cases spanning both markers, invalid marker neighbors,
  five message types and valid/invalid inverse fields.
- Six complete stream-reader/virtual-callback cases spanning both markers and
  negative/zero/positive crypto state, preserving the supplied payload and
  original writable mapping.
- Twenty native state-writer cases spanning malformed lengths and signed
  positive/nonpositive payloads, preserving unrelated writable state.

Both inputs pass. Development evidence is retained under ignored
`dist/generic/admission-20261025/`. Later integrated final reports should bind all
current source identities; development reports predate ongoing root changes.

The recvmsg/ancillary-FD route is identified statically rather than newly
emulated. All indirect entries, object/vtable ownership, runtime callback
replacement, transport/library contracts, aliases/writers and session ordering
remain unproved. The module explicitly returns false for unconditional
plaintext proof, complete indirect-entry proof and generation authority.

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_generic_admission -v
.\.venv\Scripts\python.exe verify_admission.py --driver inputs/ARMadb-driver.unpacked --fixture october --output dist/generic/admission-20261025/october-next.json
.\.venv\Scripts\python.exe verify_admission.py --driver dist/generic/2025.02.25.1521-5c00b2e47aca/host-unpack/ARMadb-driver.unpacked --fixture february --output dist/generic/admission-20261025/february-next.json
```

Outputs refuse overwrite. These tests execute no device/OS I/O and emit no
patched executable or update image.
