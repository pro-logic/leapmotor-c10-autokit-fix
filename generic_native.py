"""Recognized-layout A15W native patch generation.

Generation is limited to checked compiler/data-flow layouts and valid native
packet ownership, allocator and AAPCS contracts. It does not promise exhaustive
computed-entry proofs, arbitrary invalid-pointer safety or asynchronous unwind.
Image pairing, native emulation and paired installer checks are builder gates.
"""
import copy
import json
from functools import lru_cache
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from driver_layout import assemble
from firmware import sha256
from generic_analysis import Driver, analyze_driver
from generic_plan import insertion_layout
from generic_crypto import plain_packet_marker
from generic_abi import (unwind_tail_extension, hook_transfer_contract,
                         observer_frame_contract, verify_unwind_tail_extension)
from generic_global_flow import static_entry_inventory

DEFAULT_PROFILE = dict(
    raw_open=[2560, 1440], effective_open=[2560, 1296], aa_content=[1920, 972], aa_dpi=220,
    aa_touch=dict(integer_range=[0, 10000], subtract_y=500, clamp_min=0),
    calibration='empirical C10 HD setup; need on another firmware has not been established')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def checked_profile(profile=None):
    candidate = copy.deepcopy(DEFAULT_PROFILE if profile is None else profile)
    if (not isinstance(candidate, dict) or set(candidate) != set(DEFAULT_PROFILE)
            or not isinstance(candidate.get('calibration'), str) or not candidate['calibration'].strip()
            or any(_canonical(candidate[key]) != _canonical(value) for key, value in DEFAULT_PROFILE.items()
                   if key != 'calibration')):
        raise ValueError('Unsupported vehicle profile; this native generator implements the explicit C10 profile only')
    return candidate


@lru_cache(maxsize=4)
def _discovery_json(original):
    # Cache an immutable serialization, not a caller-mutable analysis dictionary.
    return _canonical(analyze_driver(original))


def recognized_native(original, native=None):
    if not isinstance(original, bytes) or not 0 < len(original) <= 16 * 1024 * 1024:
        raise ValueError('Unsupported original native driver bounds')
    discovered = json.loads(_discovery_json(original))
    if native is not None and _canonical(native) != _canonical(discovered):
        raise ValueError('Supplied native analysis is stale, edited or belongs to another input')
    if not discovered.get('unique_candidates'):
        raise ValueError('Need exactly one recognized Open and touch layout')
    try:
        evidence = discovered['semantic_evidence']
        opened, touch = evidence['open'][0], evidence['touch'][0]
        channel = discovered['channel_storage_evidence']
        if (not opened['graph']['closed_within_range']
                or not touch['graph']['closed_within_range']
                or not opened['length_check_dominates_hook'] or opened['failure_path_can_reach_hook']
                or touch['routing']['status'] != 'checked bounded routing'
                or channel['status'] != 'checked bounded channel and conditional storage relationships'
                or any(len(items) != 1 for items in evidence['geometry_consumers'].values())):
            raise ValueError('Unsupported Open/touch/channel/geometry control or storage layout')
        pre = opened['preprocessing']
        if len(pre) != 1 or pre[0]['open_cfb_contract']['status'] != 'checked entry-relative Open CFB contract':
            raise ValueError('Need unique checked message-CFB and explicit plaintext-marker contracts')
        crypto = pre[0]['open_cfb_contract']
        if crypto['caller_seed_source'].get('source_va') != crypto['active_state_va']:
            raise ValueError('Message-CFB caller/helper state alias differs')
    except (KeyError, IndexError, TypeError) as error:
        raise ValueError('Incomplete recognized native compatibility evidence') from error
    return discovered


@lru_cache(maxsize=4)
def _entry_inventory_json(original, spans):
    return _canonical(static_entry_inventory(Driver(original), list(spans)))


def _entry_contract(original, manifest):
    spans = [(f'hook-{index}-interior', hook['va'] + 2, 2)
             for index, hook in enumerate(manifest['hooks'])]
    spans.append(('new-rx', manifest['layout']['rx_va'], manifest['code_bytes']))
    audit = json.loads(_entry_inventory_json(original, tuple(spans)))
    # A potential entry into a displaced instruction is always a refusal. For
    # new RX, executable-section direct/complete constructor targets also refuse.
    # Numeric readonly data and wrong-ISA candidates remain recorded assumptions,
    # rather than being silently treated as proven runtime branches.
    def interior(hit):
        return any(name.startswith('hook-') for name in hit['protected_spans'])
    for hit in audit['direct']['hits']:
        if interior(hit) or any(section['declared_code'] for section in hit['source_sections']):
            raise ValueError('Incoming direct reference enters a protected native patch span')
    if any(interior(hit) for hit in audit['absolute']['hits']):
        raise ValueError('Absolute reference enters a displaced instruction interior')
    if audit['constructors']['hits']:
        raise ValueError('Complete address constructor enters a protected native patch span')
    return dict(status='accepted under recognized-layout execution contract', inventory=audit,
                assumptions=['ELF declared code and discovered native entry/dispatch structure are respected',
                             'Code/data are not modified and arbitrary computed mid-instruction entries are absent',
                             'Unresolved readonly numeric/MOVT-high candidates are inventory, not exhaustive target proof'],
                complete_indirect_target_proof=False)


def compatibility_contract():
    return dict(schema='c10-recognized-native-contract-v1',
        scope='recognized A15W ELF32 ARM/Thumb compiler layouts with explicit marker-safe C10 correction',
        assumptions=['Native descriptors, pointers, prior owner/capacity/mapping fields are valid under their constructor/storage APIs',
                     'Heap/mapped packet storage is disjoint from active saved-stack scratch; stack has at least56 bytes available',
                     'Imported allocator/OS/CFB routines and intermediate callees obey their AAPCS/API contracts',
                     'Stock dispatch/session ordering and ordinary non-self-modifying native control flow apply'],
        limits=['No exhaustive arbitrary computed-entry, invalid-pointer, concurrency or ownership proof',
                'Synchronous CFB callsite unwind is registered; arbitrary asynchronous stack walking is unproved',
                'The C10 calibration is empirical and not a universal vehicle calibration',
                'Host native validation and per-input paired archive/installer verification are required before output publication'],
        hardware_tested=False)


def pointer(register, value):
    return f'movw {register}, #{value & 65535}\nmovt {register}, #{value >> 16}\n'


def branch(source, destination):
    code = assemble(f'b.w {destination:#x}', source)
    ins = list(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(code, source))
    if len(code) != 4 or len(ins) != 1 or ins[0].mnemonic != 'b.w' or int(ins[0].op_str[1:], 0) != destination:
        raise ValueError('Native branch is out of range or misassembled')
    return code


def call_branch(source, destination):
    code = assemble(f'bl {destination:#x}', source)
    ins = list(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(code, source))
    if len(code) != 4 or len(ins) != 1 or ins[0].mnemonic != 'bl' or int(ins[0].op_str[1:], 0) != destination:
        raise ValueError('Native call branch is out of range or misassembled')
    return code


def profile_source(descriptor, state, suffix):
    return f'ldr.w ip,[{descriptor},#0x10]\n' + pointer('r3', state) + f'''ldr.w r0,[ip]
str r0,[r3,#4]
ldr.w r1,[ip,#4]
str r1,[r3,#8]
movw r1,#2560
cmp r0,r1
bne disable_{suffix}
ldr.w r0,[ip,#4]
movw r1,#1440
cmp r0,r1
bne disable_{suffix}
movw r0,#1296
str.w r0,[ip,#4]
movs r0,#1
b store_{suffix}
disable_{suffix}:
movs r0,#0
store_{suffix}:
str r0,[r3]
'''


def _materialize(original, native, plaintext_safe=False):
    if sha256(original) != native['sha256'] or not native['unique_candidates']:
        raise ValueError('Native source/analysis mismatch or ambiguous sites')
    op, touch = native['open_candidates'][0], native['touch_candidates'][0]
    evidence = native['semantic_evidence']
    if (not evidence['open'][0].get('length_check_dominates_hook')
            or evidence['open'][0]['failure_path_can_reach_hook']
            or evidence['touch'][0]['routing']['status'] != 'checked bounded routing'
            or any(len(v) != 1 for v in evidence['geometry_consumers'].values())):
        raise ValueError('Native semantic preconditions not established')
    d = Driver(original)
    if (op['hook']['instruction'] != 'ldr.w lr, [r6, #0x10]'
            or touch['hook']['instruction'] != 'vldr s14, [r4, #8]'):
        raise ValueError('Native displaced instruction contract unsupported')
    for site in (op['hook'], touch['hook']):
        if (site['mode'] != 'Thumb' or site['return_va'] != site['va'] + 4
                or site['file_offset'] != d.offset(site['va'],4,True)
                or len(bytes.fromhex(site['original_bytes'])) != 4 or d.read(site['va'], 4).hex() != site['original_bytes']):
            raise ValueError('Native displaced bytes differ')
    layout = insertion_layout(original)
    state, insertion_va = layout['state_va'], layout['rx_va']
    open_slot = insertion_va
    crypto, plain = None, None
    if plaintext_safe:
        pre = evidence['open'][0].get('preprocessing', [])
        if len(pre) != 1 or pre[0]['open_cfb_contract']['status'] != 'checked entry-relative Open CFB contract':
            raise ValueError('Plaintext-safe experiment needs checked CFB contract')
        crypto = pre[0]['open_cfb_contract']
        initializer = evidence['geometry_consumers']['type1_response'][0]['initializer_target']
        plain = plain_packet_marker(d, initializer)
        if plain['marker'] == crypto['encrypted_flag']['encrypted_marker']:
            raise ValueError('Plaintext/encrypted markers must differ')
        exidx = d.elf.get_section_by_name('.ARM.exidx')
        open_slot = max(insertion_va, (exidx['sh_addr'] + exidx['sh_size'] + 24 + 3) & ~3)
    routing = evidence['touch'][0]['routing']
    channel = evidence['geometry_consumers']['aa_link'][0]['channel']
    if channel not in [r['channel'] for r in routing['routes']]:
        raise ValueError('AAP link channel absent from native touch routes')
    open_source = '''ldr.w lr, [r6, #0x10]
push.w {r0,r1,r2,r3,ip}
mrs r2, apsr
push {r2}
ldr r0,[r6,#4]
cmp r0,#28
bne exit_open
ldr r0,[r6,#8]
cmp r0,#1
bne exit_open
'''
    if plaintext_safe:
        open_source += 'ldr r0,[r6]\n' + pointer('r1', plain['marker']) + '''cmp r0,r1
bne exit_open
''' + profile_source('r6', state, 'plain')
    else:
        open_source += pointer('r3', state) + '''ldr.w r0,[lr]
str r0,[r3,#4]
ldr.w r1,[lr,#4]
str r1,[r3,#8]
movw r1,#2560
cmp r0,r1
bne disable
ldr.w r0,[lr,#4]
movw r1,#1440
cmp r0,r1
bne disable
movw r0,#1296
str.w r0,[lr,#4]
movs r0,#1
b store
disable:
movs r0,#0
store:
str r0,[r3]
'''
    open_source += '''exit_open:
pop {r2}
msr apsr_nzcvq,r2
pop.w {r0,r1,r2,r3,ip}
''' + f'b.w {op["hook"]["return_va"]:#x}'
    opened = assemble(open_source, open_slot)
    touch_slot = (open_slot + len(opened) + 31) & ~31
    touch_source = '''push.w {r0,r1,r2,r3,ip}
mrs r2,apsr
''' + pointer('r3', state) + f'''ldr r0,[sp,#{routing['channel_stack_offset'] + 20}]
cmp r0,#{channel}
bne bypass
ldr r0,[r3]
cmp r0,#1
bne bypass
ldr r0,[r4,#8]
movw r1,#10000
cmp r0,r1
bhi bypass
subs.w r0,r0,#500
bcs nonnegative
movs r0,#0
nonnegative:
vmov s14,r0
b done
bypass:
vldr s14,[r4,#8]
done:
msr apsr_nzcvq,r2
pop.w {{r0,r1,r2,r3,ip}}
b.w {touch['hook']['return_va']:#x}
'''
    touched = assemble(touch_source, touch_slot)
    length = touch_slot + len(touched) - insertion_va
    observer_slot, observed, cfb_site, unwind = None, b'', None, None
    if plaintext_safe:
        observer_slot = (insertion_va + length + 31) & ~31
        cfb_call = crypto['cfb_call']
        ins = next(d.cs.disasm(d.read(cfb_call['va'], 4), cfb_call['va'], count=1))
        cfb_site = d.site(ins)
        if ins.size != 4 or ins.mnemonic != 'blx' or int(ins.op_str[1:], 0) != cfb_call['target']:
            raise ValueError('Unsupported native CFB call instruction')
        observer_source = '''push.w {r4,r5,r6,lr}
sub sp,#16
ldr.w ip,[sp,#32]
str.w ip,[sp]
ldr.w ip,[sp,#36]
str.w ip,[sp,#4]
ldr.w ip,[sp,#40]
str.w ip,[sp,#8]
''' + f'blx {cfb_call["target"]:#x}\n' + '''push.w {r0,r1,r2,r3,ip}
mrs r2,apsr
push {r2}
ldr r0,[sp,#32]
cmp r0,#0
bne exit_cfb
ldr r0,[r4,#4]
cmp r0,#28
bne exit_cfb
ldr r0,[r4,#8]
cmp r0,#1
bne exit_cfb
ldr r0,[r4]
''' + pointer('r1', crypto['encrypted_flag']['encrypted_marker']) + '''cmp r0,r1
bne exit_cfb
''' + profile_source('r4', state, 'decrypted') + '''exit_cfb:
pop {r2}
msr apsr_nzcvq,r2
pop.w {r0,r1,r2,r3,ip}
add sp,#16
pop.w {r4,r5,r6,lr}
bx lr
'''
        observed = assemble(observer_source, observer_slot)
        observer_end = observer_slot + len(observed)
        length = (observer_end - insertion_va + 2 + 3) & ~3
        terminator = d.elf.get_section_by_name('.eh_frame')['sh_addr']
        unwind = unwind_tail_extension(d, [(terminator,1),(observer_slot,0x8003aab0),(observer_end,1)],
                                       empty_eh_frame=True)
        if unwind['minimum_code_start_va'] > open_slot:
            raise ValueError('Native unwind prefix overlaps new code')
    if length > layout['code_reservation_bytes']:
        raise ValueError('Native code reservation exceeded')
    blob = bytearray(length)
    blob[open_slot - insertion_va:open_slot - insertion_va + len(opened)] = opened
    blob[touch_slot - insertion_va:touch_slot - insertion_va + len(touched)] = touched
    if plaintext_safe:
        prefix = bytes.fromhex(unwind['insertion_prefix_bytes'])
        blob[:len(prefix)] = prefix
        blob[observer_slot - insertion_va:observer_slot - insertion_va + len(observed)] = observed
    cut, gap = layout['insertion_file_offset'], layout['inserted_file_gap_bytes']
    result = bytearray(original[:cut] + blob + bytes(gap - length) + original[cut:])
    if unwind is not None:
        edit = unwind['original_padding_edit']
        replacement = bytes.fromhex(edit['replacement'])
        result[edit['file_offset']:edit['file_offset'] + len(replacement)] = replacement
    header = struct.unpack_from('<16sHHIIIIIHHHHHH', original)
    if header[9] != 32 or header[11] != 40:
        raise ValueError('Native ELF table entry size unsupported')
    for index, segment in enumerate(d.elf.iter_segments()):
        p = list(struct.unpack_from('<8I', original, header[5] + index * 32))
        if segment['p_type'] == 'PT_LOAD' and segment['p_flags'] == 5:
            p[4] += length
            p[5] += length
        if segment['p_type'] == 'PT_LOAD' and segment['p_flags'] == 6:
            p[5] += layout['rw_memsz_extension']
        if unwind is not None and index == unwind['original_index']['segment_index']:
            p[4] = p[5] = unwind['new_index_bytes']
        if p[1] >= cut:
            p[1] += gap
        struct.pack_into('<8I', result, header[5] + index * 32, *p)
    table = header[6] + (gap if header[6] >= cut else 0)
    struct.pack_into('<I', result, 32, table)
    for index in range(header[12]):
        s = list(struct.unpack_from('<10I', original, header[6] + index * 40))
        if s[4] >= cut:
            s[4] += gap
        if unwind is not None and d.elf.get_section(index).name == '.ARM.exidx':
            s[5] = unwind['new_index_bytes']
        if unwind is not None and d.elf.get_section(index).name == '.eh_frame':
            s[5] = unwind['empty_eh_frame_section']['replacement_size']
        struct.pack_into('<10I', result, table + index * 40, *s)
    hooks = []
    assignments = [(op['hook'], open_slot, False), (touch['hook'], touch_slot, False)]
    if plaintext_safe:
        assignments.append((cfb_site, observer_slot, True))
    for site, slot, is_call in assignments:
        off = d.offset(site['va'], 4, executable=True)
        if off >= cut:
            raise ValueError('Native hook lies beyond insertion')
        after = call_branch(site['va'], slot) if is_call else branch(site['va'], slot)
        result[off:off + 4] = after
        hooks.append(dict(**site, replacement=after.hex(), target_va=slot, transfer='call' if is_call else 'branch'))
    restored = bytearray(result[:cut] + result[cut + gap:])
    for hook in hooks:
        off = hook['file_offset']
        restored[off:off + 4] = bytes.fromhex(hook['original_bytes'])
    if unwind is not None:
        edit = unwind['original_padding_edit']
        body = bytes.fromhex(edit['original'])
        restored[edit['file_offset']:edit['file_offset']+len(body)] = body
    restored[32:36] = original[32:36]
    restored[header[5]:header[5] + header[9] * header[10]] = original[header[5]:header[5] + header[9] * header[10]]
    restored[header[6]:header[6] + header[11] * header[12]] = original[header[6]:header[6] + header[11] * header[12]]
    if restored != original:
        raise ValueError('Native ELF mutated undeclared original bytes')
    return bytes(result), dict(mode='in-memory ABI experiment only', source_sha256=sha256(original),
                               experimental_sha256=sha256(result), layout=layout, code_bytes=length,
                               state_va=state, hooks=hooks, aa_channel=channel,
                               open_stack_scratch_bytes=24, touch_stack_scratch_bytes=20,
                               plaintext_safe=plaintext_safe, plain_packet_marker=plain,
                               cfb_observer_va=observer_slot, cfb_observer_frame_bytes=32 if plaintext_safe else None,
                               cfb_observer_peak_scratch_bytes=56 if plaintext_safe else None,
                               cfb_observer_unwind=unwind,
                               generation_allowed=False, installable_image=False)


def _production_materialize(original, native, profile):
    changed, manifest = _materialize(original, native, plaintext_safe=True)
    manifest.update(schema='c10-recognized-native-patch-v1',
                    mode='recognized-layout C10 native generation',
                    generated_sha256=sha256(changed), profile=copy.deepcopy(profile),
                    compatibility_contract=compatibility_contract(),
                    incoming_entry_contract=_entry_contract(original, manifest),
                    generation_allowed=True, installable_image=False,
                    native_validation='independent supplied-byte validation required before packaging')
    return changed, manifest


def generate_native(original, native=None, profile=None):
    """Generate checked recognized-layout bytes, without writing or packaging.

    Supplied analysis is a convenience only: it must equal fresh byte-derived
    discovery. Image pairing is the builder's independent mandatory input gate.
    """
    selected_profile = checked_profile(profile)
    discovered = recognized_native(original, native)
    changed, manifest = _production_materialize(original, discovered, selected_profile)
    validate_native(original, changed, manifest, discovered)
    return changed, manifest


def validate_native(original, changed, manifest, native=None):
    """Recompute the patch contract and inspect the actual supplied ELF bytes."""
    if not isinstance(changed, bytes) or not isinstance(manifest, dict):
        raise ValueError('Need generated bytes and native manifest')
    discovered = recognized_native(original, native)
    selected_profile = checked_profile(manifest.get('profile'))
    expected_bytes, expected_manifest = _production_materialize(original, discovered, selected_profile)
    if changed != expected_bytes or _canonical(manifest) != _canonical(expected_manifest):
        raise ValueError('Generated native bytes or manifest differ from recomputed recognized-layout contract')
    # This checker independently walks every ELF header, mapping and original
    # section's actual bytes instead of trusting generator size/mapping claims.
    from verify_native_experiment import elf_check
    checked = elf_check(original, changed, manifest)
    old, output = Driver(original), Driver(changed)
    transfers = [hook_transfer_contract(old, output, hook, hook['target_va'], hook['transfer'] == 'call')
                 for hook in manifest['hooks']]
    unwind = verify_unwind_tail_extension(old, output, manifest['cfb_observer_unwind'])
    end = manifest['cfb_observer_unwind']['appended_entries'][-1]['function_va']
    frame = observer_frame_contract(output, manifest['cfb_observer_va'], end)
    if not frame['synchronous_unwind_registered']:
        raise ValueError('Generated CFB observer lacks synchronous unwind coverage')
    return dict(status='PASS', generated_sha256=sha256(changed), source_sha256=sha256(original),
                elf_check=checked, hook_transfers=transfers, unwind=unwind, observer_frame=frame,
                compatibility_contract=compatibility_contract(),
                evidence_level='recomputed native contract and independent actual-ELF/transfer/frame inspection',
                independent_emulation_required=True, hardware_tested=False)


def verify_generated_native(original, changed, manifest, native=None):
    """Run independent behavioral expectations against supplied generated bytes.

    Execution locations are derived from checked code relationships. Optional
    fixture verification remains a separate independent control for real samples.
    No fixture/version/hash selector grants generation or chooses a location.
    """
    discovered = recognized_native(original, native)
    structural = validate_native(original, changed, manifest, discovered)
    from verify_message_crypto import case
    from verify_native_experiment import verify_generated_hooks
    from verify_plaintext_experiment import relay_checks
    opened = discovered['semantic_evidence']['open'][0]
    preprocessing = opened['preprocessing'][0]
    crypto = preprocessing['open_cfb_contract']
    marker = crypto['encrypted_flag']['encrypted_marker']
    plain = manifest['plain_packet_marker']['marker']
    oracle = dict(helper=crypto['helper_entry'], marker_helper=crypto['encrypted_flag']['function_entry'],
                  active=crypto['active_state_va'], table=crypto['key_derivation']['table_va'],
                  logger=crypto['logger_target'], call=preprocessing['call']['va'],
                  hook=discovered['open_candidates'][0]['hook']['va'])
    relay = relay_checks(original, changed, discovered, manifest['state_va'])
    print(f'native: {relay} actual generated CFB relay/preservation cases PASS', flush=True)
    helpers = dispatches = 0
    for seed in (0, 1, 15, 0x01020304, 0x7fffffff, 0x80000000, 0xffffffff):
        for active in (-1, 0, 1, 2147483647):
            for value in (marker, plain, marker ^ 1):
                for length in (0, 1, 15, 16, 17, 28, 29):
                    case(original, oracle, seed, active, value, length, machine_data=changed,
                         patch_state=(manifest['state_va'], helpers & 1),
                         encrypted_marker=marker, plain_marker=plain)
                    helpers += 1
    for width, height in ((2560, 1440), (2560, 1296), (1920, 1080), (0, 0)):
        for active in (-1, 0, 1, 2147483647):
            for value in (marker, plain, marker ^ 1):
                for initial in (0, 1):
                    case(original, oracle, active & 0xffffffff, active, value, 28, dispatch=True,
                         machine_data=changed, patch_state=(manifest['state_va'], initial),
                         fields=(width, height, 30, 5, 0x4000, 11, 5),
                         encrypted_marker=marker, plain_marker=plain)
                    dispatches += 1
    print(f'native: {helpers} helper and {dispatches} guarded Open-dispatch cases PASS', flush=True)
    hooks = verify_generated_hooks(original, changed, manifest, discovered)
    return dict(status='PASS', source_sha256=sha256(original), generated_sha256=sha256(changed),
                structural=structural, cfb_relay_cases=relay, helper_cases=helpers,
                guarded_open_dispatch_cases=dispatches, hook_checks=hooks,
                evidence_level='independent actual supplied ELF, native helper/dispatch/hook emulation',
                compatibility_contract=compatibility_contract(),
                mocks=['host CFB/key/memset and diagnostic return contracts',
                       'native allocator API contract; external IPC is withheld'], hardware_tested=False)
