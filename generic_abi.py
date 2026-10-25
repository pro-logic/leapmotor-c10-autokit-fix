"""Restricted hook-transfer and EHABI arithmetic evidence; never generation authority.

Original table words are interpreted independently of the candidate finder.
Only compact personality-zero core-register recipes are simulated. New unwind
records can be proposed at an existing index tail without moving its old bytes.
This does not establish asynchronous unwinding, runtime stack limits or callers.
"""
from __future__ import annotations

from bisect import bisect_right
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm_const import (ARM_CC_AL, ARM_OP_IMM, ARM_OP_REG, ARM_REG_PC, ARM_REG_SP,
                                ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_CBZ, ARM_INS_CBNZ)

from firmware import sha256
from generic_flow import ThumbGraph, enclosing_range, plt_import


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)


def prel31_target(word, place):
    _need(type(word) is int and 0 <= word < 0x80000000, 'Unsupported prel31 word')
    target = place + (word - 0x80000000 if word & 0x40000000 else word)
    _need(0 <= target < 2**32, 'prel31 address overflow')
    return target


def encode_prel31(target, place):
    _need(type(target) is int and type(place) is int and 0 <= target < 2**32 and 0 <= place < 2**32,
          'Invalid prel31 address')
    relative = target - place
    _need(-(1 << 30) <= relative < (1 << 30), 'prel31 target is out of range')
    return relative & 0x7fffffff


def unwind_index(driver):
    section = driver.elf.get_section_by_name('.ARM.exidx')
    _need(section is not None and section['sh_type'] == 'SHT_ARM_EXIDX'
          and section['sh_flags'] & 2 and 0 < section['sh_size'] <= 65536
          and section['sh_size'] % 8 == 0, 'Unsupported ARM exception index section')
    _need(driver.offset(section['sh_addr'], section['sh_size']) == section['sh_offset'],
          'Exception index section has inconsistent file mapping')
    segments = [(i, p) for i, p in enumerate(driver.elf.iter_segments()) if p['p_type'] == 'PT_ARM_EXIDX']
    _need(len(segments) == 1, 'Need one authoritative PT_ARM_EXIDX segment')
    index, segment = segments[0]
    _need(segment['p_vaddr'] == section['sh_addr'] and segment['p_offset'] == section['sh_offset']
          and segment['p_filesz'] == segment['p_memsz'] == section['sh_size'],
          'Exception index section/segment disagree')
    entries = []
    for offset in range(0, section['sh_size'], 8):
        function, descriptor = struct.unpack_from('<II', section.data(), offset)
        place = section['sh_addr'] + offset
        target = prel31_target(function, place)
        _need(target % 2 == 0, 'Odd exception-index function boundary unsupported')
        driver.offset(target, 2, executable=True)
        kind = 'cantunwind' if descriptor == 1 else 'compact0' if descriptor >> 24 == 0x80 else (
            'compact-other' if descriptor & 0x80000000 else 'external-table')
        item = dict(entry_va=place, function_va=target, descriptor_word=descriptor, kind=kind)
        if kind == 'external-table':
            item['external_table_va'] = prel31_target(descriptor, place + 4)
            driver.offset(item['external_table_va'], 4)
        entries.append(item)
    _need([e['function_va'] for e in entries] == sorted(set(e['function_va'] for e in entries)),
          'Exception-index boundaries are not strictly ordered')
    return dict(section_va=section['sh_addr'], file_offset=section['sh_offset'], bytes=section['sh_size'],
                segment_index=index, entries=entries, sha256=sha256(section.data()))


def unwind_lookup(index, pc, return_address=False):
    """Select a table record; return-address lookup uses the call interior.

    A return address points just after the call. The subtract-two adjustment
    retains a final call in its own function even at the next boundary.
    The final index entry has an open-ended range within its containing module.
    """
    _need(type(pc) is int and 0 <= pc < 2**32, 'Invalid unwind lookup PC')
    address = (pc - 2 if return_address else pc) & ~1
    starts = [e['function_va'] for e in index['entries']]
    offset = bisect_right(starts, address) - 1
    _need(offset >= 0, 'No exception-index entry for PC')
    return dict(index['entries'][offset], interval_end=starts[offset + 1] if offset + 1 < len(starts) else 2**32)


def compact0_recipe(word):
    """Decode a deliberately small core-register EHABI subset into stack facts."""
    _need(type(word) is int and word >> 24 == 0x80, 'Need inline compact personality-zero word')
    stream = [(word >> shift) & 255 for shift in (16, 8, 0)]
    cursor, displacement, restored, operations = 0, 0, {}, []
    finished = False
    while cursor < len(stream):
        opcode = stream[cursor]
        cursor += 1
        if opcode < 0x80:
            change = ((opcode & 0x3f) + 1) * 4 * (1 if opcode < 0x40 else -1)
            displacement += change
            operations.append(dict(kind='adjust_vsp', bytes=change))
        elif 0xa0 <= opcode <= 0xaf:
            registers = list(range(4, 5 + (opcode & 7)))
            if opcode & 8:
                registers.append(14)
            operations.append(dict(kind='pop_core', registers=registers))
            for register in registers:
                _need(register not in restored, 'Repeated core-register restoration unsupported')
                restored[register] = displacement
                displacement += 4
        elif opcode == 0xb0:
            finished = True
            break
        else:
            raise ValueError(f'Unsupported compact0 opcode {opcode:#x}')
        _need(0 <= displacement <= 65536, 'Unsupported unwind stack displacement')
    # The byte stream ending after the final restoration has the same terminal
    # VRS PC=LR operation as an explicit Finish; no additional memory is read.
    return dict(word=word, operations=operations, stack_bytes=displacement,
                restored_register_offsets={str(r): o for r, o in sorted(restored.items())},
                return_register=15 if 15 in restored else 14, explicit_finish=finished,
                scope='compact0 core-register arithmetic only; personalities/cleanups not executed')


def recover_compact0(word, sp, lr, saved_words):
    """Apply supported stack facts to a supplied synthetic/runtime snapshot."""
    recipe = compact0_recipe(word)
    _need(type(sp) is int and sp % 4 == 0 and 0 <= sp < 2**32, 'Invalid unwind SP')
    registers = {}
    for register, offset in recipe['restored_register_offsets'].items():
        address = sp + offset
        _need(address in saved_words, 'Unwind reads a missing saved word')
        value = saved_words[address]
        _need(type(value) is int and 0 <= value < 2**32, 'Invalid saved register word')
        registers[register] = value
    final_sp = sp + recipe['stack_bytes']
    _need(final_sp < 2**32, 'Unwind SP overflow')
    pc = registers.get('15', registers.get('14', lr))
    _need(type(pc) is int and 0 <= pc < 2**32, 'Invalid unwound return PC')
    return dict(sp=final_sp, pc=pc, restored_registers=registers)


def unwind_tail_extension(driver, new_entries, empty_eh_frame=False):
    """Propose append-only index records at a zero-padded executable LOAD tail.

    No ELF is changed. Existing table VA, existing records and their prel31
    places remain identical. Ordinary padding and the explicit opt-in empty
    .eh_frame route are distinguished. The latter preserves all four null
    terminator bytes but requires that already-empty section's sh_size become
    zero, so no byte belongs to two sections. A leading CANTUNWIND record reuses
    those unchanged zero bytes as its first prel31 word.
    """
    index = unwind_index(driver)
    section = driver.elf.get_section_by_name('.ARM.exidx')
    rx = [p for p in driver.loads if p['p_flags'] == 5
          and p['p_offset'] <= section['sh_offset']
          and section['sh_offset'] + section['sh_size'] <= p['p_offset'] + p['p_filesz']]
    _need(len(rx) == 1, 'Exception index lacks one RX LOAD')
    rx = rx[0]
    cut, cut_va = rx['p_offset'] + rx['p_filesz'], rx['p_vaddr'] + rx['p_filesz']
    end = section['sh_offset'] + section['sh_size']
    padding = cut - end
    _need(0 <= padding <= 4 and driver.data[end:cut] == bytes(padding),
          'Exception index is not at a supported zero-padded RX tail')
    _need(type(empty_eh_frame) is bool, 'Empty-EH-frame policy must be explicit boolean')
    overlap, empty = [], None
    for other in driver.elf.iter_sections():
        if other.name != '.ARM.exidx' and other['sh_type'] != 'SHT_NOBITS' and other['sh_size']:
            if other['sh_offset'] < cut and end < other['sh_offset'] + other['sh_size']:
                overlap.append(other)
    if overlap:
        _need(empty_eh_frame and len(overlap) == 1, 'Another section overlaps exception-index tail padding')
        other = overlap[0]
        _need(other.name == '.eh_frame' and other['sh_type'] == 'SHT_PROGBITS'
              and other['sh_flags'] == 2 and padding == other['sh_size'] == 4
              and other['sh_offset'] == end and other['sh_addr'] == section['sh_addr'] + section['sh_size']
              and other.data() == bytes(4), 'Only an exact four-byte empty EH-frame terminator is supported')
        _need(driver.elf.get_section_by_name('.eh_frame_hdr') is None
              and not any(p['p_type'] == 'PT_GNU_EH_FRAME' for p in driver.elf.iter_segments()),
              'An EH-frame header has an unsupported empty-section size contract')
        empty = dict(name=other.name, file_offset=end, va=other['sh_addr'], original_size=4,
                     replacement_size=0, original_sha256=sha256(other.data()),
                     contract='Retain mapped null terminator bytes/VA; zero already-empty section size to avoid overlap')
    _need(type(new_entries) in (list, tuple) and 1 <= len(new_entries) <= 64,
          'Unsupported appended unwind entry count')
    previous = index['entries'][-1]['function_va']
    encoded, entries = bytearray(), []
    table_end = section['sh_addr'] + section['sh_size'] + len(new_entries) * 8
    code_start = max(cut_va, (table_end + 3) & ~3)
    for offset, pair in enumerate(new_entries):
        _need(type(pair) in (list, tuple) and len(pair) == 2, 'Invalid appended unwind entry')
        target, word = pair
        leading_empty = bool(empty and offset == 0)
        _need(type(target) is int and target % 2 == 0 and previous < target
              and (target == empty['va'] and word == 1 if leading_empty else code_start <= target < 2**32),
              'Appended unwind functions are not ordered supported boundaries')
        _need(type(word) is int and (word == 1 or word >> 24 == 0x80), 'Unsupported appended unwind descriptor')
        if word != 1:
            compact0_recipe(word)
        place = section['sh_addr'] + section['sh_size'] + offset * 8
        encoded.extend(struct.pack('<II', encode_prel31(target, place), word))
        entries.append(dict(function_va=target, descriptor_word=word, entry_va=place))
        previous = target
    _need(new_entries[-1][1] == 1, 'Append an explicit CANTUNWIND end boundary')
    if empty:
        _need(len(new_entries) >= 3 and encoded[:4] == bytes(4),
              'Empty EH-frame route needs leading CANTUNWIND, new function and end records')
    _need(index['entries'][-1]['kind'] == 'cantunwind', 'Original last unwind interval is not CANTUNWIND')
    prefix = bytes(encoded[padding:])
    prefix += bytes((-(cut_va + len(prefix))) % 4)
    return dict(status='checked append-only exception-index proposal', generation_allowed=False,
                original_index=index, appended_entries=entries, appended_bytes=bytes(encoded).hex(),
                new_index_bytes=section['sh_size'] + len(encoded),
                original_padding_edit=dict(file_offset=end, original=driver.data[end:cut].hex(),
                                           replacement=bytes(encoded[:padding]).hex()),
                empty_eh_frame_section=empty,
                policy='preserve-empty-EH-terminator-and-zero-section-size' if empty else 'unallocated-zero-padding',
                insertion_file_offset=cut, insertion_va=cut_va, insertion_prefix_bytes=prefix.hex(),
                minimum_code_start_va=cut_va + len(prefix),
                metadata_changes=['PT_ARM_EXIDX p_filesz/p_memsz', '.ARM.exidx sh_size']
                    + (['.eh_frame sh_size 4 -> 0; mapped null terminator bytes/VA retained'] if empty else []),
                old_index_records_preserved=True,
                limits=['New-code mapping, frame correspondence and all original ELF bytes require independent validation',
                        'Synchronous callsite unwinding only; asynchronous stack walking remains unproved'])


def verify_unwind_tail_extension(original, changed, proposal):
    """Check actual tables, authoritative headers and all original lookup records."""
    entries = [(e['function_va'], e['descriptor_word']) for e in proposal['appended_entries']]
    expected = unwind_tail_extension(original, entries, empty_eh_frame=bool(proposal.get('empty_eh_frame_section')))
    _need(proposal == expected, 'Edited/stale exception-index proposal')
    before, after = unwind_index(original), unwind_index(changed)
    _need(after['section_va'] == before['section_va'] and after['file_offset'] == before['file_offset']
          and after['bytes'] == proposal['new_index_bytes'], 'Extended exception index moved or has wrong size')
    old = original.read(before['section_va'], before['bytes'])
    _need(changed.read(before['section_va'], before['bytes']) == old, 'Original exception-index bytes changed')
    _need(changed.read(before['section_va'] + before['bytes'], len(entries) * 8).hex() == proposal['appended_bytes'],
          'Appended exception-index bytes differ')
    _need(after['entries'][:len(before['entries'])] == before['entries'], 'Original exception-index records differ')
    empty = proposal['empty_eh_frame_section']
    if empty:
        old_section = original.elf.get_section_by_name('.eh_frame')
        new_section = changed.elf.get_section_by_name('.eh_frame')
        _need(new_section is not None, 'Empty EH-frame section metadata disappeared')
        for field, value in old_section.header.items():
            _need(new_section[field] == (0 if field == 'sh_size' else value),
                  'Empty EH-frame metadata changed beyond its declared size')
        _need(changed.read(empty['va'], 4) == bytes(4), 'Original empty EH-frame null terminator changed')
    occupied = sorted((s['sh_offset'], s['sh_offset'] + s['sh_size']) for s in changed.elf.iter_sections()
                      if s['sh_type'] != 'SHT_NOBITS' and s['sh_size'])
    _need(all(left[1] <= right[0] for left, right in zip(occupied, occupied[1:])),
          'Extended exception index overlaps a nonempty ELF section')
    for entry in before['entries']:
        old_lookup, new_lookup = unwind_lookup(before, entry['function_va']), unwind_lookup(after, entry['function_va'])
        _need({k: v for k, v in old_lookup.items() if k != 'interval_end'} ==
              {k: v for k, v in new_lookup.items() if k != 'interval_end'}, 'Original unwind lookup changed')
    return dict(status='checked preserved original unwind records and appended authoritative index',
                original_entries=len(before['entries']), appended_entries=len(entries), generation_allowed=False)


def branch_contract(source, target, encoded, link=False):
    _need(type(source) is int and type(target) is int and source % 2 == target % 2 == 0
          and 0 <= source < 2**32 and 0 <= target < 2**32, 'Invalid Thumb branch addresses')
    _need(isinstance(encoded, bytes) and len(encoded) == 4, 'Need one four-byte Thumb branch')
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs.detail = True
    instructions = list(cs.disasm(encoded, source))
    _need(len(instructions) == 1, 'Branch bytes do not decode uniquely')
    ins = instructions[0]
    _need(ins.size == 4 and ins.mnemonic == ('bl' if link else 'b.w') and ins.cc == ARM_CC_AL
          and len(ins.operands) == 1 and ins.operands[0].type == ARM_OP_IMM
          and ins.operands[0].imm == target and not ins.update_flags,
          'Branch encoding, target, predicate or flags differ')
    _need(-(1 << 24) <= target - (source + 4) < (1 << 24), 'Thumb branch exceeds signed reach')
    return dict(source_va=source, target_va=target, replacement=encoded.hex(), link=link,
                return_address=(source + 4) | 1 if link else None, flags_unchanged=True)


def hook_transfer_contract(original, changed, site, target, link=False):
    """Validate bounded source instruction and actual generated branch/mapping."""
    va = site['va']
    _need(site['mode'] == 'Thumb' and site['return_va'] == va + 4
          and site['file_offset'] == original.offset(va, 4, executable=True)
          and original.read(va, 4).hex() == site['original_bytes'], 'Original hook identity differs')
    graph = ThumbGraph(original, *enclosing_range(original, va))
    _need(not graph.issues and va in graph.nodes and graph.nodes[va].size == 4,
          'Hook lacks a closed bounded instruction graph')
    ins = graph.nodes[va]
    _need(va not in graph.predicated and va not in graph.it_interiors, 'Hook is inside an IT block')
    _need(va + 2 not in graph.nodes and not graph.predecessors[va + 2], 'Incoming edge enters displaced instruction interior')
    reads, writes = ins.regs_access()
    if link:
        _need(ins.mnemonic == 'blx' and len(ins.operands) == 1 and ins.operands[0].type == ARM_OP_IMM
              and ins.operands[0].imm % 4 == 0 and plt_import(original, ins.operands[0].imm),
              'Call observer requires direct interworking PLT call')
        displaced = dict(kind='interworking call', target_va=ins.operands[0].imm,
                         return_address=(va + 4) | 1)
    else:
        _need(ARM_REG_PC not in reads and ARM_REG_PC not in writes and not ins.update_flags,
              'Displaced instruction depends on PC or changes flags')
        displaced = dict(kind='replay with identical read-register values and addressed memory',
                         reads=[graph.cs.reg_name(r) for r in reads],
                         writes=[graph.cs.reg_name(r) for r in writes], pc_independent=True,
                         requires_original_sp=ARM_REG_SP in reads)
    changed.offset(target, 2, executable=True)
    transfer = branch_contract(va, target, changed.read(va, 4), link)
    return dict(status='checked bounded hook transfer', source=original.site(ins), displaced=displaced,
                transfer=transfer, bounded_predecessors=sorted(graph.predecessors[va]), generation_allowed=False,
                limits=['All outside/indirect entry contracts remain separate',
                        'Instruction replay requires original read-register values and addressed memory; SP only if read'])


def validate_stack_separation(sp, scratch_bytes, regions):
    """Check concrete descriptor/payload/state extents against new saved scratch."""
    _need(type(sp) is int and type(scratch_bytes) is int and sp % 4 == scratch_bytes % 4 == 0
          and 0 < scratch_bytes <= 65536 and scratch_bytes <= sp < 2**32, 'Invalid saved-stack extent')
    for name, start, size in regions:
        _need(type(start) is int and type(size) is int and 0 < size and 0 <= start < start + size <= 2**32,
              'Invalid nonaliasing region')
        _need(start + size <= sp - scratch_bytes or start >= sp, f'{name} aliases hook saved-stack scratch')
    return dict(status='checked concrete stack separation', scratch_start=sp - scratch_bytes,
                scratch_end=sp, scratch_bytes=scratch_bytes, generation_allowed=False,
                limit='Concrete extents only; source allocation/stack-limit invariants need separate proof')


def _stack_deltas(graph):
    """Abstract only explicit SP allocation/restoration, with equal joins."""
    deltas, pending, maximum, exits = {graph.start: 0}, [graph.start], 0, []
    while pending:
        va = pending.pop()
        ins = graph.nodes[va]
        delta, change = deltas[va], 0
        mnemonic = ins.mnemonic.split('.')[0]
        _, writes = ins.regs_access()
        if mnemonic in ('push', 'pop'):
            _need(all(o.type == ARM_OP_REG and o.reg != ARM_REG_SP for o in ins.operands),
                  'Unsupported observer stack register list')
            change = len(ins.operands) * (4 if mnemonic == 'pop' else -4)
        elif ARM_REG_SP in writes:
            operands = ins.operands
            _need(mnemonic in ('add', 'sub') and operands[0].type == ARM_OP_REG
                  and operands[0].reg == ARM_REG_SP and operands[-1].type == ARM_OP_IMM
                  and (len(operands) == 2 or len(operands) == 3
                       and operands[1].type == ARM_OP_REG and operands[1].reg == ARM_REG_SP),
                  'Observer has an unsupported SP definition')
            change = operands[-1].imm * (1 if mnemonic == 'add' else -1)
        if change:
            _need(va not in graph.predicated and change % 4 == 0, 'Predicated/unaligned observer SP change')
        following = delta + change
        _need(-65536 <= following <= 0, 'Observer stack escapes allocated frame')
        maximum = max(maximum, -following)
        if not graph.edges[va]:
            _need(mnemonic == 'bx' and ins.op_str == 'lr' and following == 0,
                  'Observer exit does not restore SP before BX LR')
            exits.append(va)
        for target in graph.edges[va]:
            _need(target in graph.nodes, 'Observer stack path leaves checked graph')
            if target in deltas:
                _need(deltas[target] == following, 'Observer join has inconsistent SP displacement')
            else:
                deltas[target] = following
                pending.append(target)
    _need(exits, 'Observer has no checked return')
    return dict(deltas=deltas, peak_scratch_bytes=maximum, exits=sorted(exits))


def observer_frame_contract(driver, entry, end):
    """Check the supported relay frame and actual synchronous unwind record."""
    graph = ThumbGraph(driver, entry, end)
    _need(not graph.issues and not graph.predicated, 'Observer has unsupported control flow/predication')
    prefix, va = [], entry
    expected = [('push.w', '{r4, r5, r6, lr}'), ('sub', 'sp, #0x10'),
                ('ldr.w', 'ip, [sp, #0x20]'), ('str.w', 'ip, [sp]'),
                ('ldr.w', 'ip, [sp, #0x24]'), ('str.w', 'ip, [sp, #4]'),
                ('ldr.w', 'ip, [sp, #0x28]'), ('str.w', 'ip, [sp, #8]')]
    for mnemonic, operands in expected:
        _need(va in graph.nodes, 'Truncated observer relay prefix')
        ins = graph.nodes[va]
        _need((ins.mnemonic, ins.op_str) == (mnemonic, operands), 'Unsupported observer relay prefix')
        _need(graph.edges[va] == {va + ins.size}, 'Observer relay prefix branches')
        if prefix:
            _need(graph.predecessors[va] == {prefix[-1].address}, 'Observer relay prefix can be entered midway')
        prefix.append(ins)
        va += ins.size
    _need(len(graph.calls) == 1 and graph.calls[0]['va'] == va and graph.calls[0]['mode'] == 'ARM'
          and graph.calls[0]['imported'] and graph.calls[0]['imported']['symbol'] == 'AES_cfb128_encrypt',
          'Observer requires one original ARM CFB import call')
    stack = _stack_deltas(graph)
    _need(stack['deltas'][va] == -32, 'Observer CFB call does not have its 32-byte frame')
    _need(stack['peak_scratch_bytes'] == 56, 'Observer saved-scratch extent differs')
    # The new code intentionally has no floating-point instructions. Relative
    # to the real imported call's return, FPSCR/FPEXC/D-register state is untouched.
    for ins in graph.nodes.values():
        _need(not ins.mnemonic.startswith(('v', 'mcr', 'mrc', 'ldc', 'stc', 'cdp', 'cps'))
              and ins.mnemonic not in ('setend', 'svc', 'hvc', 'smc', 'eret', 'rfe', 'srs'),
              'Observer changes unsupported floating-point/system control state')
        if ins.mnemonic == 'msr':
            _need(ins.op_str.startswith('apsr_nzcvq, '), 'Observer writes non-flag system control state')
    recipe_word = 0x8003aab0
    recipe = compact0_recipe(recipe_word)
    _need(recipe['stack_bytes'] == 32 and recipe['restored_register_offsets'] ==
          {'4': 16, '5': 20, '6': 24, '14': 28}, 'Observer unwind recipe does not match relay frame')
    record = unwind_lookup(unwind_index(driver), va + graph.nodes[va].size | 1, return_address=True)
    registered = record['function_va'] == entry and record['descriptor_word'] == recipe_word
    return dict(status='checked observer relay/frame arithmetic', entry_va=entry, end_va=end,
                call=graph.calls[0], public_call_sp_delta=-32, stack_alignment_preserved_mod8=True,
                peak_scratch_bytes=stack['peak_scratch_bytes'], return_sites=stack['exits'],
                synchronous_unwind_recipe=recipe, actual_unwind_record=record,
                synchronous_unwind_registered=registered, generation_allowed=False,
                blocker=None if registered else 'Observer call still resolves to an unsuitable unwind record',
                floating_point_control='No added VFP/coprocessor instruction; imported CFB behavior remains its original contract',
                limits=['Imported CFB preserves callee-saved registers/SP under its ABI contract',
                        'Caller/result/flag preservation requires independent native emulation',
                        'Concrete stack bounds/nonaliasing and asynchronous unwinding remain separate'])


def direct_entry_audit(driver, protected_spans):
    """Overapproximate direct targets from every Thumb halfword and ARM word.

    Decoding every alignment includes literal/data and wrong-ISA false positives.
    Potential hits remain visible; this is not an indirect-target enumeration.
    """
    spans = []
    for name, start, size in protected_spans:
        _need(type(start) is int and type(size) is int and size > 0 and 0 <= start < start + size <= 2**32,
              'Invalid protected entry span')
        spans.append((name, start, start + size))
    regions = [(p['p_vaddr'], driver.data[p['p_offset']:p['p_offset'] + p['p_filesz']])
               for p in driver.loads if p['p_flags'] & 1]
    hits, examined = [], dict(Thumb=0, ARM=0)
    for mode, stride in (('Thumb', 2), ('ARM', 4)):
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB if mode == 'Thumb' else CS_MODE_ARM)
        decoder.detail = True
        for base, text, offset in ((base, text, offset) for base, text in regions
                                   for offset in range(0, len(text) - (1 if mode == 'Thumb' else 3), stride)):
            address = base + offset
            if mode == 'ARM' and address % 4:
                continue
            first = int.from_bytes(text[offset:offset + 2], 'little')
            if mode == 'Thumb':
                candidate = (first & 0xf800 in (0xe000, 0xf000) or
                             first & 0xf000 == 0xd000 and first & 0x0f00 not in (0xe00, 0xf00)
                             or first & 0xf500 == 0xb100)
            else:
                candidate = int.from_bytes(text[offset:offset + 4], 'little') & 0x0e000000 == 0x0a000000
            if not candidate:
                continue
            ins = next(decoder.disasm(text[offset:offset + 4], address, count=1), None)
            examined[mode] += 1
            if ins is None or ins.id not in (ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_CBZ, ARM_INS_CBNZ):
                continue
            if not ins.operands or ins.operands[-1].type != ARM_OP_IMM:
                continue
            target = ins.operands[-1].imm
            matches = [name for name, start, end in spans if start <= target < end]
            if matches:
                hits.append(dict(source_va=address, mode=mode, bytes=ins.bytes.hex(),
                                 instruction=ins.mnemonic + ' ' + ins.op_str, target_va=target,
                                 source_sections=[dict(name=s.name, declared_code=bool(s['sh_flags'] & 4))
                                     for s in driver.elf.iter_sections() if s['sh_flags'] & 2
                                     and s['sh_addr'] <= address
                                     and address + ins.size <= s['sh_addr'] + s['sh_size']],
                                 protected_spans=matches, classification='potential decode; reachability/ISA unproved'))
    # Refine only candidate Thumb hits reached with matching bytes from the
    # existing bounded traversal. Other alignments remain conservative evidence.
    cache = {}
    for hit in hits:
        if hit['mode'] != 'Thumb':
            continue
        try:
            bounds = enclosing_range(driver, hit['source_va'])
            if bounds not in cache:
                cache[bounds] = ThumbGraph(driver, *bounds)
            graph = cache[bounds]
            ins = graph.nodes.get(hit['source_va'])
            if ins and ins.bytes.hex() == hit['bytes']:
                hit['classification'] = 'reached matching Thumb instruction in bounded graph'
                hit['source_graph_has_issues'] = bool(graph.issues)
        except ValueError:
            pass
    return dict(status='no potential direct targets' if not hits else 'potential direct targets require resolution',
                scanned_regions=[dict(start=base, end=base + len(text)) for base, text in regions],
                protected_spans=[dict(name=n, start=a, end=b) for n, a, b in spans],
                examined_candidate_encodings=examined, hits=hits, generation_allowed=False,
                limits=['No indirect-register/table/data-derived target proof',
                        'Literal pools and wrong-ISA decodes deliberately remain conservative potential hits'])
