# Open message decryption contract

Continuation, 26 October 2026: the native in-memory experiment now offers a
plaintext-safe three-hook design, described in
[CHANNEL_ENTRY_CONTRACTS.md](CHANNEL_ENTRY_CONTRACTS.md). It corrects an explicit
plaintext marker in the ordinary Open hook and observes the actual CFB call's
return for encrypted Open. This avoids assuming decryption from a later crypto
state read. It does not change the conditional stock contract below or grant
production generation authority.

25 October 2026. Both exact February and October drivers now have a checked,
entry-relative contract for their Open message-CFB preprocessing. This is
separate from the completed packed-file CBC decoder in [HOST_DECODING.md](HOST_DECODING.md).
It establishes conditional native behavior, **not an unconditional plaintext
postcondition or permission to generate an installer**.

## Finding that prevents plaintext proof

For an incoming direction-zero, type-one descriptor, the native helper has four
paths. The marker is derived from its directly called equality helper; the
crypto state is a literal-backed writable signed word.

| Descriptor/state | Native behavior |
| --- | --- |
| Marker differs from encrypted marker | No CFB call |
| Encrypted marker, crypto state <= 0 | Diagnostic call, then return without CFB |
| Encrypted marker, crypto state > 0, length zero | Return without CFB |
| Encrypted marker, crypto state > 0, length nonzero | In-place AES-CFB with direction zero |

With an explicit diagnostic-return mock, an encrypted 28-byte Open and inactive
crypto state traverse the actual helper and dispatch and reach the original
Open hook with unchanged ciphertext. This happens for negative and zero state
in both fixtures. Therefore a dominating preprocessing call and a 28-byte length
check alone cannot prove plaintext. These are supplied-input emulation
counterexamples; they do not establish that the full real caller accepts such
messages during ordinary operation.

The source of the caller's seed is the same word as the helper's crypto state in
both samples. The detector derives that alias through a dominating unmodified
literal-backed r4 definition, modulo intervening callees preserving r4. The seed
load and helper state loads occur at different times. Runtime initialization,
writers, concurrency, full caller validation and diagnostic side effects remain
unproved. Do not infer a stable positive-state invariant from these reads.

## Recognition and key/IV evidence

`generic_crypto.py` checks actual connected instruction blocks and branch
destinations specialized to direction zero and Open type one. It validates the
marker leaf from its direct-call target; that 12-byte leaf has no separate unwind
entry in these inputs. It checks bypass/return paths, the selected diagnostic
arm, two imported memset calls, signed key-table indexing, the 16-iteration loop,
128-bit key setup, CFB register/stack arguments and balanced helper return.
The other direction and other message-type logging arms are outside this scope.

For byte i, key construction indexes the supplied image's read-only table using
the signed, truncating remainder of `int32(seed + i)` by 16. Arithmetic wraps at
32 bits before signed interpretation. Indices can be -15..15, so recognition
requires a file-backed immutable 31-byte window around the table. This includes
overflow from a positive seed near INT32_MAX. Treating indexing as unsigned
`& 15` would be incorrect for those cases. Only the window's hash is reported;
table/key bytes are never bundled or printed.

The IV starts as sixteen zero bytes; seed bytes from least to most significant
are stored at offsets 1, 4, 9 and 12. CFB num starts at zero. Input and output are
the same descriptor payload pointer, length is descriptor offset 4, and the
expanded key/IV/num are local to the helper stack. The marker and helper/state/
table/import addresses are discovered from code, without firmware versions,
fixture hashes or verifier landmarks selecting them.

Independent verifier landmarks, not discovery selectors:

| Role | February | October |
| --- | --- | --- |
| Helper entry | `0x18244` | `0x17b74` |
| Marker helper | `0x62dc4` | `0x64620` |
| Caller seed / crypto-state word | `0x11d03c` | `0x11f408` |
| Key-table pointer | `0x6b5d1` | `0x6d0d4` |
| Diagnostic target | `0x66e64` | `0x688d4` |

## Independent emulation and source tests

`verify_message_crypto.py` pins each real fixture independently. Actual marker,
condition, key/IV and return instructions execute in Unicorn. The verifier uses
a separately expressed signed-remainder oracle and host cryptography to prepare
ciphertext and check primitive arguments. Imported memset, key schedule/CFB and
diagnostic logging have explicit host contracts. Vendor OpenSSL and diagnostic
implementations are not executed. Other unrecognized imports still fail.

Each fixture passes:

- 1,155 direct helper cases: eleven seeds including negative/wrap boundaries,
  five signed crypto states, three marker values and seven lengths (0/1/15/16/
  17/28/29). These include 132 decrypt paths and 231 diagnostic bypasses.
- 18 actual argument-setup/helper/Open-dispatch cases. Three encrypted inactive
  cases reach the hook unchanged. Actual dispatch reads its seed from the same
  state word; direct helper cases vary the two inputs independently.
- Exact descriptor, payload boundaries, original writable mapping,
  callee-saved integer registers and SP preservation across preprocessing.

There are 42 source tests. New source-generated fixtures relocate both helper
and state/table data and reject changed gates, payload arguments, seed data flow,
IV offsets, signed mask/IT/loop conditions, key width, direction stack argument,
marker helper and imported primitive. An explicit r4 clobber invalidates caller
seed-source evidence. No fixture includes vendor key material.

Analysis exposes the concrete plaintext blocker. Proof drafts retain this
conditional supporting evidence in `plaintext-open-after-decryption`, whose
status stays `unproved`. All mandatory slots remain unproved, edited/stale drafts
are rejected, and generation stays disabled. Stable code and reference outputs
are unchanged. No generated ELF, installer shell test or hardware action belongs
to this milestone.

## Reproduction and saved evidence

From the repository, using the existing environment:

```powershell
.\.venv\Scripts\python.exe verify_message_crypto.py --driver inputs/ARMadb-driver.unpacked --fixture october --output dist/generic/message-cfb-20261025/final-october-crypto.json
.\.venv\Scripts\python.exe verify_message_crypto.py --driver dist/generic/2025.02.25.1521-5c00b2e47aca/host-unpack/ARMadb-driver.unpacked --fixture february --output dist/generic/message-cfb-20261025/final-february-crypto.json
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_*.py'
```

Evidence refuses overwrite. Choose a new path for repeated runs. Final reports,
original-path regression reports, per-image analyses/drafts and the commit/source/
artifact-bound run summary are retained under ignored `dist/generic/`. Earlier
development reports are preserved; use the final names recorded in the new run
summary for current source identities.

Next work is to establish the complete caller/runtime-state contract or derive
a hook boundary that independently establishes plaintext on every admitted path.
Do not turn a fresh read of the crypto-state word into proof of the earlier CFB
call. Outside entries, full ABI/control/unwind and geometry/channel contracts,
audited generation, stock-script derivation and paired installer validation also
remain outstanding.
