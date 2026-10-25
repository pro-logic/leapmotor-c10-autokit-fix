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


def pointer(register, value):
    return f'movw {register}, #{value & 65535}\nmovt {register}, #{value >> 16}\n'


def branch(source, destination):
    code = assemble(f'b.w {destination:#x}', source)
    ins = list(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(code, source))
    if len(code) != 4 or len(ins) != 1 or ins[0].mnemonic != 'b.w' or int(ins[0].op_str[1:], 0) != destination:
        raise ValueError('Experimental branch is out of range or misassembled')
    return code


def experiment(original, native):
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
    state, open_slot = layout['state_va'], layout['rx_va']
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
''' + pointer('r3', state) + '''ldr.w r0,[lr]
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
exit_open:
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
    length = touch_slot + len(touched) - open_slot
    if length > layout['code_reservation_bytes']:
        raise ValueError('Experimental code reservation exceeded')
    blob = bytearray(length)
    blob[:len(opened)] = opened
    blob[touch_slot - open_slot:] = touched
    cut, gap = layout['insertion_file_offset'], layout['inserted_file_gap_bytes']
    result = bytearray(original[:cut] + blob + bytes(gap - length) + original[cut:])
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
        if p[1] >= cut:
            p[1] += gap
        struct.pack_into('<8I', result, header[5] + index * 32, *p)
    table = header[6] + (gap if header[6] >= cut else 0)
    struct.pack_into('<I', result, 32, table)
    for index in range(header[12]):
        s = list(struct.unpack_from('<10I', original, header[6] + index * 40))
        if s[4] >= cut:
            s[4] += gap
        struct.pack_into('<10I', result, table + index * 40, *s)
    hooks = []
    for site, slot in ((op['hook'], open_slot), (touch['hook'], touch_slot)):
        off = d.offset(site['va'], 4, executable=True)
        if off >= cut:
            raise ValueError('Experimental hook lies beyond insertion')
        after = branch(site['va'], slot)
        result[off:off + 4] = after
        hooks.append(dict(**site, replacement=after.hex(), target_va=slot))
    restored = bytearray(result[:cut] + result[cut + gap:])
    for hook in hooks:
        off = hook['file_offset']
        restored[off:off + 4] = bytes.fromhex(hook['original_bytes'])
    restored[32:36] = original[32:36]
    restored[header[5]:header[5] + header[9] * header[10]] = original[header[5]:header[5] + header[9] * header[10]]
    restored[header[6]:header[6] + header[11] * header[12]] = original[header[6]:header[6] + header[11] * header[12]]
    if restored != original:
        raise ValueError('Experimental ELF mutated undeclared original bytes')
    return bytes(result), dict(mode='in-memory ABI experiment only', source_sha256=sha256(original),
                               experimental_sha256=sha256(result), layout=layout, code_bytes=length,
                               state_va=state, hooks=hooks, aa_channel=channel,
                               open_stack_scratch_bytes=24, touch_stack_scratch_bytes=20,
                               generation_allowed=False, installable_image=False)
