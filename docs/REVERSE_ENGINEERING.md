# How the fix was found, and how to investigate another firmware

This is the maintenance handover for **C10 AutoKit Fix**. The public workflow is
one patch built from stock, with one paired unpatch. The development work below
explains the implementation; none of its intermediate installers is required.

## 1. Start with the observed failure

Tested combination: Leapmotor C10, CPC200-CCPA / A15W dongle, dongle firmware
`2025.10.15.1127`, installed AutoKit `2024.08.06.1042`.

The original stock failure was **image cropping**, not the later touch offset.
With AutoKit set to **Show Navigation Bar**, a cold car/head-unit boot showed the
navigation bar, but Android Auto used an incorrect resolution. The top and
bottom of its image were cropped.

In the tested **HD-mode** setup, the resolution fix overrides what the car asks
the dongle to use and holds AA content at 1920×972. This corrected the cropped
picture, but introduced a touch-coordinate mismatch: touching above an Android
Auto icon selected it. Selecting Show again corrected touch for that session;
the offset could return on a later cold boot with the resolution fix in place.
The conditional native touch adjustment was added as a workaround for that
introduced mismatch. Do not describe it as the original stock symptom.

Keep these coordinate spaces distinct:

| Space / value | Observed or inferred meaning |
| --- | --- |
| Host raw Open `2560×1440` | Cold-boot fullscreen profile; still advertised on a later successful patched boot |
| Host usable area `2560×1296` | Bottom-navigation layout and the corrected Show profile |
| AA content `1920×972` | Desired active content, held by the session guard |
| AA input `1920×1080` | Native input/full-frame tier; distinct from active content |
| AA margin `108` | Total vertical difference between 1080 and 972 |
| AA DPI `220` | Forced AA-side DPI; native HU state was sometimes still 232 |
| SPS `1920×1088` | Observed encoded video allocation; do not equate it to active content |

No single reported height proves that host Views, decoded video, native AA
input and touch coordinates agree. Record which layer is under test: stock
cropping, the resolution-only fix's introduced touch error, or the combined fix.
Compare cold boot and a corrected Show session on the **same firmware and
process**, including raw Open, effective Open, HU info, AA configuration, process
hashes and user picture/touch observations.

## 2. What the earlier approaches established

| Approach | Result and lesson retained in this project |
| --- | --- |
| Force smaller AA settings / pre-launch settings only | Host writes after AA exec could overwrite them; a launch-time write alone raced initialization. |
| Session-scoped `1920×972` guard | Corrected the cropped picture and held the intended resolution through delayed initialization, but introduced the touch offset. The native touch workaround was needed to complete the fix. |
| AA DPI220 with that guard | Density settings alone did not remove the touch offset introduced by forcing the resolution. |
| Native Open `1440→1296` only | Corrected stored and downstream native dimensions, but the user still reported wrong touch until Show. Native metadata feedback does not prove a host View was remeasured. |
| Conditional normalized AA Y shift plus Open correction | Two later cold boots were reported good without Show; a readable later capture confirmed the expected running driver and an ACTIVE correction. The initial post-install session had still needed Show. |
| Boot-only USB diagnostics | Preserved the same native driver and guard while removing C10 capture workers and output files in quiet mode. A subsequent morning use was reported successful. |

These were diagnostic hypotheses and retained improvements, not a sequence the
community should install. Read [VALIDATION.md](VALIDATION.md) before making a
hardware-success claim. The first installation's failure/Show transition remains
unexplained; do not invent a mandatory first-Show step or promise it is never needed.

## 3. Obtain the exact executable, not a similar reference

Work began from [CPC200-CCPA_resources](https://github.com/lvalen91/CPC200-CCPA_resources).
Useful upstream areas are `carlinkit/firmware_stock/`, the AutoKit research under
`carlinkit/autokit/`, and firmware/protocol analysis under `documentation/`.
The later local C10 work is consolidated in this repository's code and this guide;
do not assume the linked upstream commit contains it all.

The original `ARMadb-driver` is packed. A desktop-unpacked reference from another
version was insufficient: the installed firmware needed an exact hardware export.
The hardware-aware UPX uses `/dev/hwaes` for an encrypted packed block. See
[ORIGINAL_DRIVER.md](ORIGINAL_DRIVER.md) and [THIRD_PARTY.md](../THIRD_PARTY.md)
for the separately obtained tool, its pinned source location and manual export.

Current baseline identities:

| Object | SHA-256 |
| --- | --- |
| Original update image | `24589f1b71b95d87379ee2a10e130e939cd45c28bcd3ec328499f5bbd2bc477e` |
| Packed stock driver | `614fa754065dcecd7465bfdc283d551abdc0c1d630c9c0c76b520a4272867cdb` |
| Hardware-unpacked stock ELF, 478664 bytes | `0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee` |
| Patched native ELF, 544200 bytes | `0bed061a46ab214b2fa4c3b57c548e01e1f9a814f56295962035153651114d95` |

Hash the update image, persistent executable, unpacked export and actually running
`/proc/<pid>/exe` separately. The launcher uses a RAM copy under `/tmp/bin`; a
persistent-file hash alone does not prove which bytes ran in the failed session.
Early startup may precede that RAM path's creation, hence the delayed process
hash sample in `runtime/c10_capture_init.sh`.

## 4. Where to look in the native driver

**All addresses below belong only to the pinned original ELF above. They are
navigation landmarks, not signatures to paste into another firmware.**

| Original virtual address / path | Verified role |
| --- | --- |
| `0x1def8` onward | Validates Open length as 28 bytes. The post-decrypt payload pointer is loaded at `0x1df00` from `[r6+0x10]`. |
| `0x1df00` | Open hook; displaced four bytes `d6f810e0` (`ldr.w lr, [r6,#0x10]`). Return `0x1df04`. |
| `0x11f40c`, `0x11f3d4` | Original/effective Open structures populated by the handler after the hook. |
| `0x21d04..0x21d1c`, then `0x21e2a..0x21e30` | Uses effective width/height/fps to construct and write the 24-byte HU_SCREEN_INFO record. |
| `0x1b8c0..0x1b8d0` | Copies effective width/height/fps into AA link parameters. |
| `0x2208a → 0x1984c` | Builds a type-1 Open response using the effective 28-byte Open; sends through `0x18598`. |
| `0x22098 → 0x1b574` | Actual BroadCastRemoteCxCy routine: inner type240 from effective Open, outer type30 via `0x17328`. Requires open/nonzero-dimension state. |
| `0x22084 → 0x1bc24` | Box-info JSON / outbound type25. An early analysis misidentified this as RemoteCxCy; do not repeat that attribution. |
| `0x1fad2..0x1fb04` | AA touch conversion: integer coordinates become doubles divided by `10000.0`; literal at `0x1fc60`. |
| `0x1fae2` | Y-load hook, displaced `94ed027a` (`vldr s14,[r4,#8]`), return `0x1fae6`. X resides separately; AA IPC channel is 9. |
| `0x1df82 → 0x688d4` | Existing Open logging call, redirected to select ACTIVE/BYPASS formats while preserving its arguments and return behavior. |

Use the included read-only tool, with the Python dependencies installed:

```sh
python tools/inspect_driver.py --driver inputs/ARMadb-driver.unpacked --strings
python tools/inspect_driver.py --driver inputs/ARMadb-driver.unpacked --start 0x1def8 --end 0x1df38
python tools/inspect_driver.py --driver inputs/ARMadb-driver.unpacked --start 0x1fad2 --end 0x1fb08
```

It maps virtual addresses through file-backed PT_LOAD segments. Do not assume
`file_offset = VA - 0x10000` outside the current first segment. Thumb is the
default; inspect ARM code such as PLT entries with `--arm`. For a new firmware,
find string references, imports, call sites, field copies and bounds checks first;
similar strings or one matching instruction are not enough to identify a hook.

The boundary must be after host-control decryption and before dimensions are
copied/forwarded. Older protocol notes mention other framing and brokers such as
`/var/run/phonemirror`, `/var/run/adb-driver` and MiddleMan. Those are leads, not
proof that a generic stream proxy or old message layout fits a new executable.

## 5. Why the host View remained relevant

Nearby decompiled AutoKit source used in development was an **August 1** build,
whereas the installed app reported **August 6**. It is corroborating source,
not an exact reconstruction of the installed APK.

In decompiled package `cn.manstep.phonemirrorBox`, look for:

- `AutoBoxMirrorView.java` and its TextureView counterpart: touch normalization
  using `scaled_top` and `scaled_height`.
- `i.java`: the shared geometry object's log/string contains `scaled_width`,
  `scaled_height`, `scaled_left`, `scaled_top`, `video_width`, `video_height`.
- `resizeAndroidAutoView` and cached maximum/AA dimensions (`c0.k()` / `c0.a()`
  in that reference); the Show path's window measurement/cache updates.
- The Open-response handler in `m/f.java` (older reference: `BoxInterface/f.java`):
  stores parsed dimensions, but this alone did not establish a View remeasurement.

The nearby resize code supports this **inference**: stale max `2560×1440` and
cached AA `1920×1080` select a zero-top branch; max `2560×1296` with AA `1920×972`
can produce scaled height `2560*1080/1920 = 1440`, top correction
`(1440-1296)/2 = 72`, and View top `-72`. Show refreshes local geometry.

This motivated the tested `500/10000` normalized shift: it is 54 units of an
AA 1080-high tier, or 72 pixels only under the hypothesized 1440 scaling. Actual
View implementation/cropping and physical touch error were not fully measured.
**Do not hard-code a universal “72-pixel fix” for new firmware or app versions.**

## 6. Current patch mechanics and invariants

`driver_layout.py` checks the exact ELF32 little-endian ARM executable. Its
Open-only reference is also the differential control used by the combined
patch's validator; it is not an extra installer users must apply.

`driver_patch.py` changes Open only when a valid raw payload is exactly
`2560×1440`. It stores the latest raw profile and enables the touch state before
rewriting height to 1296. Every other valid Open disables the state; malformed
Open leaves it alone. A new process starts disabled. Gate on **raw** Open, so
Show's already-correct `2560×1296` profile does not get the shift again.

The AA Y hook checks channel9 and normalized integer range `0..10000`, applies
`max(0,y-500)` only when enabled, and otherwise replays the original load. It
does not rewrite the input payload, X coordinate, other channels or gesture
action/pointer packing. The saved-stack channel offset must account for the
hook's pushed registers; verify this afresh if surrounding code changes.

The original RX LOAD ends at file `0x732e0`. Insert a 65536-byte file gap there,
map only the added RX content at VA `0x832e0`, and move subsequent file offsets
without moving existing VAs. Combined code slots are Open `0x832e0`, touch
`0x83380`, log `0x83480`, strings `0x83500`. Original RW LOAD is VA `0x932e0`,
filesz5404/memsz577600; its BSS ends at `0x120320`, where 32 zero-initialized state
bytes are added. Program/section offsets and `e_shoff` are adjusted explicitly.

Keep original permissions/alignment, entry point, interpreter, dynamic/GOT data,
sections and unwind data intact except the documented hooks/metadata. Added code
has no named section; its executable PT_LOAD mapping is what matters. Undoing
the insertion, hook edits and metadata edits reconstructs the original exactly.
Assembly/disassembly, branch reachability and independent ELF checks guard this.

## 7. Porting a new stock firmware: ordered work

1. **Reproduce and capture.** Identify actual dongle/SoC, firmware, AutoKit and car
   software. Compare cold boot and Show without flashing between observations.
   Preserve originals and raw logs; redact identifiers before publishing.
2. **Export and fingerprint.** Keep each new revision's input files distinct.
   Verify packed/unpacked/running executable identities. Do not replace a working
   dongle's firmware just to substitute a convenient reference binary.
3. **Inspect the new ELF and handlers.** Use segment mappings, string xrefs,
   imports and actual instruction flow to re-find validated plaintext Open,
   original/effective structures, all outbound geometry consumers, and AA touch
   normalization. Confirm lengths, integer types, channel IDs and action packing.
4. **Check the host side again.** Find the exact installed APK if possible;
   trace window/cache/View updates on startup and Show. Ask whether the old bug,
   gate profile and shift still exist before retaining them.
5. **Choose the smallest coherent change.** Re-establish register liveness,
   flags, VFP, stack alignment and branch ranges. Derive a valid mapped insertion
   and zero state allocation. Do not paste old addresses or patch ciphertext.
6. **Add explicit compatibility.** Add a separately pinned stock profile if
   supporting another version. Derive its startup edits from that stock image.
   Keep the public workflow stock→fixed→stock-files, never a chain of experiments.
7. **Validate before packaging.** Rebuild independent ELF and emulation fixtures
   around the new original instructions. Test invalid lengths/profiles, all
   flags, AA/non-AA paths, boundaries, repeated gestures, Show transitions, pointer
   actions, original writable bytes and logger ABI. Do not merely change expected
   hashes until an old test passes.
8. **Build paired overlays.** Generate the matching stock-file unpatch at the
   same time. Keep model/version/file/provenance/space checks; stage the driver in
   RAM and commit a checked persistent pending copy for the next reboot. Do not
   replace a live RAM process or add a full rootfs/APK/SSH change by default.
9. **Run shell tests.** Exercise fresh install, reinstall, partial-copy failures,
   rollback/reapply, unknown baselines and failed sync/rename; preserve settings
   and evidence. Test both boot logging modes and fixed decisions after hotplug.
10. **Then test hardware and report limits.** Verify the install receipt and
    running `/proc/<pid>/exe`, cold boots before Show, behavior after Show, quiet
    and diagnostic boots, and rollback. Emulation is not proof of USB timing,
    host View behavior or flash power-loss safety. Publish only claims supported
    by the new firmware's evidence.

Diagnostic publication stages and syncs immutable snapshots, retaining three.
Some development captures had regular files where directories were expected;
their cause was not established. Do not silently repair/delete those captures
or attribute them to a specific media/power fault without evidence. Installation
success also needs its receipt/log: the stock updater UI can overlook finish
script failure.
