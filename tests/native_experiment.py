"""In-memory hook experiments used to establish pending ABI/insertion evidence.

This test fixture has no file-writing API and never constructs an update image.
It is not an audited plan consumer. Generic CLI generation stays disabled.
"""
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from driver_layout import assemble
from firmware import sha256
from generic_analysis import Driver
from generic_plan import insertion_layout
from generic_crypto import plain_packet_marker
from generic_abi import unwind_tail_extension


def pointer(register, value):
    return f'movw {register}, #{value & 65535}\nmovt {register}, #{value >> 16}\n'


def branch(source, destination):
    code = assemble(f'b.w {destination:#x}', source)
    ins = list(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(code, source))
    if len(code) != 4 or len(ins) != 1 or ins[0].mnemonic != 'b.w' or int(ins[0].op_str[1:], 0) != destination:
        raise ValueError('Experimental branch is out of range or misassembled')
    return code


def call_branch(source, destination):
    code = assemble(f'bl {destination:#x}', source)
    ins = list(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(code, source))
    if len(code) != 4 or len(ins) != 1 or ins[0].mnemonic != 'bl' or int(ins[0].op_str[1:], 0) != destination:
        raise ValueError('Experimental call branch is out of range or misassembled')
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


def experiment(original, native, plaintext_safe=False):
    if sha256(original) != native['sha256'] or not native['unique_candidates']:
        raise ValueError('Experimental source/analysis mismatch or ambiguous sites')
    op, touch = native['open_candidates'][0], native['touch_candidates'][0]
    evidence = native['semantic_evidence']
    if (not evidence['open'][0].get('length_check_dominates_hook')
            or evidence['open'][0]['failure_path_can_reach_hook']
            or evidence['touch'][0]['routing']['status'] != 'checked bounded routing'
            or any(len(v) != 1 for v in evidence['geometry_consumers'].values())):
        raise ValueError('Experimental semantic preconditions not established')
    d = Driver(original)
    if (op['hook']['instruction'] != 'ldr.w lr, [r6, #0x10]'
            or touch['hook']['instruction'] != 'vldr s14, [r4, #8]'):
        raise ValueError('Experimental displaced instruction contract unsupported')
    for site in (op['hook'], touch['hook']):
        if (site['mode'] != 'Thumb' or site['return_va'] != site['va'] + 4
                or site['file_offset'] != d.offset(site['va'],4,True)
                or len(bytes.fromhex(site['original_bytes'])) != 4 or d.read(site['va'], 4).hex() != site['original_bytes']):
            raise ValueError('Experimental displaced bytes differ')
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
            raise ValueError('Unsupported experimental CFB call instruction')
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
            raise ValueError('Experimental unwind prefix overlaps new code')
    if length > layout['code_reservation_bytes']:
        raise ValueError('Experimental code reservation exceeded')
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
        raise ValueError('Experimental ELF table entry size unsupported')
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
            raise ValueError('Experimental hook lies beyond insertion')
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
        raise ValueError('Experimental ELF mutated undeclared original bytes')
    return bytes(result), dict(mode='in-memory ABI experiment only', source_sha256=sha256(original),
                               experimental_sha256=sha256(result), layout=layout, code_bytes=length,
                               state_va=state, hooks=hooks, aa_channel=channel,
                               open_stack_scratch_bytes=24, touch_stack_scratch_bytes=20,
                               plaintext_safe=plaintext_safe, plain_packet_marker=plain,
                               cfb_observer_va=observer_slot, cfb_observer_frame_bytes=32 if plaintext_safe else None,
                               cfb_observer_peak_scratch_bytes=56 if plaintext_safe else None,
                               cfb_observer_unwind=unwind,
                               generation_allowed=False, installable_image=False)
