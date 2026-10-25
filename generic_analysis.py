"""Conservative Thumb candidate discovery, deliberately unable to emit patches.

Candidates are compiler-shape evidence, not full control-flow/ABI proof. No
source hash or October hook address participates in candidate selection.
"""
from __future__ import annotations

import io
import struct
import re

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

from firmware import sha256

OPEN_FORMAT = b'%s : w(%d) h(%d) frameRate(%d) iBoxversion(%02x) iPhoneWorkMode(%s) VideoType(%s)\n\0'


class Driver:
    def __init__(self, data):
        self.data = data
        try:
            self.elf = ELFFile(io.BytesIO(data))
            if (self.elf.elfclass != 32 or not self.elf.little_endian
                    or self.elf['e_machine'] != 'EM_ARM' or self.elf['e_type'] != 'ET_EXEC'):
                raise ValueError('Expected unpacked ELF32 little-endian ARM ET_EXEC')
            if not (1 <= self.elf.num_segments() <= 64 and 1 <= self.elf.num_sections() <= 4096):
                raise ValueError('Unsupported ELF header table counts')
            self.loads = [dict(s.header) for s in self.elf.iter_segments() if s['p_type'] == 'PT_LOAD']
            if not self.loads:
                raise ValueError('ELF has no loadable segments')
            for s in self.loads:
                if (s['p_filesz'] > s['p_memsz'] or s['p_offset'] + s['p_filesz'] > len(data)
                        or s['p_vaddr'] + s['p_memsz'] > 2**32
                        or s['p_align'] < 1 or s['p_align'] & (s['p_align'] - 1)
                        or s['p_offset'] % s['p_align'] != s['p_vaddr'] % s['p_align']
                        or s['p_flags'] not in (4, 5, 6)):
                    raise ValueError('Unsupported ELF LOAD bounds, alignment or permissions')
            for i, a in enumerate(self.loads):
                for b in self.loads[i + 1:]:
                    if max(a['p_vaddr'], b['p_vaddr']) < min(a['p_vaddr'] + a['p_memsz'], b['p_vaddr'] + b['p_memsz']):
                        raise ValueError('Overlapping ELF LOAD virtual mappings')
            self.text = self.elf.get_section_by_name('.text')
            if self.text is None or self.text['sh_flags'] & 6 != 6 or self.text['sh_addr'] & 1:
                raise ValueError('Missing aligned executable .text section')
            off = self.offset(self.text['sh_addr'], self.text['sh_size'], executable=True)
            if off != self.text['sh_offset']:
                raise ValueError('Text section does not match LOAD mapping')
        except (ELFError, struct.error, IndexError) as error:
            raise ValueError(f'Invalid ELF: {error}') from error
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    def offset(self, va, size=1, executable=False):
        mappings = [s for s in self.loads if s['p_vaddr'] <= va
                    and va + size <= s['p_vaddr'] + s['p_filesz']
                    and (not executable or s['p_flags'] & 1)]
        if len(mappings) != 1 or size <= 0:
            raise ValueError(f'VA range is not uniquely file-backed: {va:#x}+{size}')
        s = mappings[0]
        return s['p_offset'] + va - s['p_vaddr']

    def read(self, va, size):
        offset = self.offset(va, size)
        return self.data[offset:offset + size]

    def writable(self, va, size):
        return any(s['p_flags'] == 6 and s['p_vaddr'] <= va
                   and va + size <= s['p_vaddr'] + s['p_memsz'] for s in self.loads)

    def literal(self, ins):
        # This restricted grammar accepts only positive PC-relative literals.
        if '[pc, #' not in ins.op_str or '#-' in ins.op_str:
            raise ValueError('Unsupported literal addressing')
        displacement = int(ins.op_str.split('[pc, #')[1].split(']')[0], 0)
        return ((ins.address + 4) & ~3) + displacement

    def site(self, ins):
        return dict(va=ins.address, file_offset=self.offset(ins.address, ins.size, True),
                    mode='Thumb', original_bytes=ins.bytes.hex(),
                    instruction=f'{ins.mnemonic} {ins.op_str}', return_va=ins.address + ins.size)


def matches(instructions, expected):
    return len(instructions) >= len(expected) and all(
        ins.mnemonic == mnemonic and ins.op_str == operands
        for ins, (mnemonic, operands) in zip(instructions, expected))


def open_candidates(driver):
    results = []
    text, start = driver.text.data(), driver.text['sh_addr']
    # A Thumb ldr-immediate seed; validate the full following data flow below.
    for offset in range(0, len(text) - 64, 2):
        if struct.unpack_from('<H', text, offset)[0] & 0xF800 != 0x6800:
            continue
        ins = list(driver.cs.disasm(text[offset:offset + 64], start + offset))
        if not matches(ins, [('ldr', 'r3, [r6, #4]'), ('cmp', 'r3, #0x1c')]):
            continue
        if len(ins) < 23 or ins[2].mnemonic not in ('bne', 'bne.w'):
            continue
        expected = [
            ('ldr.w', 'lr, [r6, #0x10]'),
            (ins[4].mnemonic, ins[4].op_str),
            ('ldm.w', 'lr!, {r0, r1, r2, r3}'), ('mov', 'r5, r4'),
            ('stm', 'r5!, {r0, r1, r2, r3}'), ('ldm.w', 'lr, {r0, r1, r2}'),
            ('ldr.w', 'lr, [r4]'), ('stm.w', 'r5, {r0, r1, r2}'),
            (ins[11].mnemonic, ins[11].op_str),
            ('ldr', 'r3, [r4, #0x10]'), ('ldr', 'r0, [r4, #4]'),
            ('ldr', 'r1, [r4, #8]'), ('mov', 'r5, r2'),
            ('str', 'r3, [r2, #0x10]'), ('movs', 'r3, #5'),
            ('str', 'r3, [r4, #0xc]'), ('str', 'r3, [r2, #0xc]'),
            ('ldr', 'r3, [r4, #0x18]'), ('str.w', 'lr, [r2]'),
            ('str', 'r0, [r2, #4]'), ('str', 'r1, [r2, #8]'),
            ('str', 'r3, [r2, #0x18]'),
        ]
        if not matches(ins[3:], expected):
            continue
        if ins[4].mnemonic != 'ldr' or not ins[4].op_str.startswith('r4, [pc, #'):
            continue
        if ins[11].mnemonic != 'ldr' or not ins[11].op_str.startswith('r2, [pc, #'):
            continue
        try:
            original = struct.unpack('<I', driver.read(driver.literal(ins[4]), 4))[0]
            effective = struct.unpack('<I', driver.read(driver.literal(ins[11]), 4))[0]
            failure = int(ins[2].op_str.removeprefix('#'), 0)
            driver.offset(failure, 2, True)
            last_copy = ins[3 + len(expected) - 1]
            if (failure < last_copy.address + last_copy.size
                    or not driver.writable(original, 28) or not driver.writable(effective, 28)
                    or abs(original - effective) < 28):
                continue
            # Corroborating format xref near this handler; logger ABI remains unproved.
            formats = []
            block_offset = driver.offset(ins[3].address)
            for item in driver.cs.disasm(driver.data[block_offset:block_offset + 192], ins[3].address):
                if item.mnemonic == 'ldr' and item.op_str.startswith('r2, [pc, #'):
                    ptr = struct.unpack('<I', driver.read(driver.literal(item), 4))[0]
                    try:
                        if driver.read(ptr, len(OPEN_FORMAT)) == OPEN_FORMAT:
                            formats.append(dict(load_va=item.address, format_va=ptr))
                    except ValueError:
                        pass
            if len(formats) != 1:
                continue
        except ValueError:
            continue
        results.append(dict(
            hook=driver.site(ins[3]), validation_va=ins[0].address,
            copy_end_va=last_copy.address + last_copy.size,
            malformed_branch_va=failure, original_open_va=original, effective_open_va=effective,
            format_xref=formats[0], evidence=[
                'length field at message+4 compared with 28; unequal branch bypasses copy',
                'payload pointer loaded from message+16 before two 28-byte structure copies',
                'width/height/fps flow from original into distinct writable effective structure',
                'nearby PC-relative xref resolves to exact Open geometry log format',
            ], unproved=['post-decryption reachability', 'incoming control-flow edges and register liveness',
                         'downstream HU_SCREEN_INFO / AA link / Open response / RemoteCxCy consumers'],
        ))
    return results


def touch_candidates(driver):
    results = []
    text, start = driver.text.data(), driver.text['sh_addr']
    for offset in range(0, len(text) - 54, 2):
        # Coprocessor load family seed, followed by independently decoded flow.
        if text[offset + 1] != 0xed:
            continue
        ins = list(driver.cs.disasm(text[offset:offset + 64], start + offset))
        if len(ins) < 15:
            continue
        size = re.fullmatch(r'(r[0-9]+|ip|lr), #0x18', ins[1].op_str)
        kind = re.fullmatch(r'(r[0-9]+|ip|lr), #0xb', ins[3].op_str)
        action = re.fullmatch(r'r5, (r[0-9]+|sl|sb|fp), r5, lsl #8', ins[4].op_str)
        if (not size or not kind or not action or ins[1].mnemonic not in ('movs', 'mov.w')
                or ins[3].mnemonic not in ('movs', 'mov.w') or size[1] == kind[1]
                or {size[1], kind[1]} & {'r3', 'r4', 'r5'} or action[1] in {size[1], kind[1], 'r3', 'r4', 'r5'}):
            continue
        # STM stores registers in numeric order; header length must precede type.
        registers = {f'r{i}': i for i in range(13)} | {'ip': 12, 'lr': 14}
        if size[1] not in registers or kind[1] not in registers or registers[size[1]] >= registers[kind[1]]:
            continue
        extra = 1 if ins[9].mnemonic == 'ldr.w' and ins[9].op_str == 'r0, [sb]' else 0
        literal_index = 9 + extra
        if len(ins) < 15 + extra:
            continue
        expected = [
            ('vldr', 's15, [r4, #4]'), (ins[1].mnemonic, ins[1].op_str),
            (ins[2].mnemonic, ins[2].op_str), (ins[3].mnemonic, ins[3].op_str),
            ('orr.w', ins[4].op_str), ('vldr', 's14, [r4, #8]'),
            ('stm.w', f'r3, {{{size[1]}, {kind[1]}}}'), ('str', 'r5, [r3, #0x18]'),
            ('vcvt.f64.s32', 'd6, s15'),
        ]
        if extra:
            expected.append(('ldr.w', 'r0, [sb]'))
        expected.extend([(ins[literal_index].mnemonic, ins[literal_index].op_str),
            ('vcvt.f64.s32', 'd7, s14'), ('vdiv.f64', 'd6, d6, d5'),
            ('vdiv.f64', 'd7, d7, d5'), ('vstr', 'd6, [r3, #8]'), ('vstr', 'd7, [r3, #0x10]')])
        if not matches(ins, expected):
            continue
        if ins[2].mnemonic != 'ldr' or not ins[2].op_str.startswith('r3, [sp, #'):
            continue
        if ins[literal_index].mnemonic != 'vldr' or not ins[literal_index].op_str.startswith('d5, [pc, #'):
            continue
        try:
            divisor = driver.literal(ins[literal_index])
            if struct.unpack('<d', driver.read(divisor, 8))[0] != 10000.0:
                continue
        except ValueError:
            continue
        results.append(dict(
            hook=driver.site(ins[5]), normalization_start_va=ins[0].address,
            normalization_end_va=ins[14 + extra].address + ins[14 + extra].size,
            size_register=size[1], type_register=kind[1], action_register=action[1],
            scheduled_integer_load_va=ins[9].address if extra else None,
            divisor_va=divisor, divisor=10000, evidence=[
                'distinct X/Y integer loads feed signed conversions and double division by literal 10000',
                'normalized X/Y written at output+8/+16, size24/type11 header',
                'action and pointer packed with OR and eight-bit shift into output+24',
            ], unproved=['AA channel discriminator and saved-stack offset',
                         'incoming control-flow edges, ABI and register/flag liveness'],
        ))
    return results


def analyze_driver(data):
    driver = Driver(data)
    opens, touches = open_candidates(driver), touch_candidates(driver)
    from generic_semantics import analyze_semantics
    result = dict(
        sha256=sha256(data), bytes=len(data), entry=driver.elf['e_entry'], loads=driver.loads,
        candidate_grammar='restricted Thumb data flow with checked register allocation/scheduling roles; other shapes unsupported',
        open_candidates=opens, touch_candidates=touches,
        unique_candidates=len(opens) == len(touches) == 1,
        semantic_evidence=analyze_semantics(driver, opens, touches),
        patchable=False,
        blockers=['candidate discovery is not complete semantic proof',
                  'no audited patch plan, insertion layout or parameterized independent emulator yet'],
    )
    from generic_channel import analyze_channel
    result['channel_storage_evidence'] = analyze_channel(driver, result)
    return result
