"""Conservative original-image static references into proposed hook/code spans.

Every file-backed LOAD byte alignment is inspected for an absolute pointer;
Thumb/ARM direct branches and narrow supported address constructors are separate.
Absence of these references is not a proof about arbitrary computed pointers.
"""
from __future__ import annotations

import hashlib
import json

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm_const import (ARM_OP_IMM, ARM_OP_REG, ARM_REG_PC, ARM_INS_MOV, ARM_INS_MOVW,
                                ARM_INS_MOVT, ARM_INS_ADR, ARM_INS_ADD, ARM_INS_SUB)

from generic_abi import direct_entry_audit


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)


def _spans(items):
    _need(isinstance(items, (list, tuple)) and 0 < len(items) <= 64,
          'Invalid protected static-reference span count')
    result = []
    names = set()
    for name, start, size in items:
        _need(isinstance(name, str) and name and name not in names,
              'Invalid or duplicate protected static-reference span name')
        _need(type(start) is int and type(size) is int and 0 <= start < start + size <= 2**32,
              'Invalid protected static-reference span')
        names.add(name)
        result.append((name, start, start + size))
    return result


def _matches(spans, target):
    return [name for name, start, end in spans if start <= target < end]


def absolute_pointer_inventory(driver, protected_spans, max_candidates=20000):
    """Read all LOAD byte alignments, including unaligned packed pointer fields."""
    spans = _spans(protected_spans)
    _need(type(max_candidates) is int and 0 < max_candidates <= 100000,
          'Invalid static code-pointer candidate budget')
    executable = [(p['p_vaddr'], p['p_vaddr'] + p['p_filesz'])
                  for p in driver.loads if p['p_flags'] & 1]
    pointers, hits, words = [], [], 0
    for segment in driver.loads:
        raw = driver.data[segment['p_offset']:segment['p_offset'] + segment['p_filesz']]
        for offset in range(max(0, len(raw) - 3)):
            value = int.from_bytes(raw[offset:offset + 4], 'little')
            target = value & ~1
            words += 1
            source = segment['p_vaddr'] + offset
            if any(start <= target < end for start, end in executable):
                pointers.append(dict(source_va=source, target_va=target, thumb=bool(value & 1),
                                     source_writable=bool(segment['p_flags'] & 2), aligned_word=source % 4 == 0))
                _need(len(pointers) <= max_candidates, 'Static code-pointer candidate budget exceeded')
            matching = _matches(spans, target)
            if matching:
                hits.append(dict(source_va=source, file_offset=segment['p_offset'] + offset,
                                 target_va=target, thumb=bool(value & 1), protected_spans=matching,
                                 classification='potential absolute pointer; data type/role not assumed'))
                _need(len(hits) <= max_candidates, 'Protected-reference candidate budget exceeded')
    # A readonly aligned run is a possible vtable or absolute jump table; do
    # not invent type information or call a numeric coincidence a proven vtable.
    aligned = {p['source_va']: p for p in pointers if p['aligned_word'] and not p['source_writable']}
    runs = []
    for source in sorted(aligned):
        if source - 4 in aligned:
            continue
        sequence, address = [], source
        while address in aligned:
            sequence.append(aligned[address])
            address += 4
        if len(sequence) >= 2:
            runs.append(dict(source_va=source, entries=len(sequence), targets=[p['target_va'] for p in sequence],
                             classification='readonly code-pointer run; vtable/jump-table meaning unproved'))
    digest = hashlib.sha256(json.dumps(pointers, sort_keys=True).encode()).hexdigest()
    return dict(status='no potential absolute references' if not hits else 'potential absolute references require resolution',
                inspected_byte_aligned_words=words, potential_code_pointers=len(pointers),
                potential_code_pointer_digest=digest, readonly_code_pointer_runs=runs, hits=hits,
                generation_allowed=False,
                limits=['Numeric coincidences are retained; vtable/data types are not inferred',
                        'Runtime writes, relocations, external libraries and computed pointers are separate'])


def address_constructor_inventory(driver, protected_spans):
    """Inspect MOVW/MOVT pairs and direct ADR constructors at every alignment."""
    spans = _spans(protected_spans)
    wanted_high = {word for _, start, end in spans for word in range(start >> 16, ((end - 1) >> 16) + 1)}
    regions = [(p['p_vaddr'], driver.data[p['p_offset']:p['p_offset'] + p['p_filesz']])
               for p in driver.loads if p['p_flags'] & 1]
    hits, partials, examined = [], [], dict(Thumb=0, ARM=0)
    for mode, stride in (('Thumb', 2), ('ARM', 4)):
        cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB if mode == 'Thumb' else CS_MODE_ARM)
        cs.detail = True
        for base, raw, offset in ((base, raw, offset) for base, raw in regions
                                 for offset in range(0, max(0, len(raw) - (1 if mode == 'Thumb' else 3)), stride)):
            va = base + offset
            if mode == 'ARM' and va % 4:
                continue
            half = int.from_bytes(raw[offset:offset + 2], 'little')
            word = int.from_bytes(raw[offset:offset + 4], 'little')
            candidate = (half & 0xfbf0 in (0xf240, 0xf2c0) or half & 0xf800 == 0xa000
                         or half & 0xfbff in (0xf20f, 0xf2af)) if mode == 'Thumb' else (
                word & 0x0ff00000 in (0x03000000, 0x03400000)
                or word & (1 << 25) and word >> 16 & 15 == 15 and word >> 21 & 15 in (2, 4))
            if not candidate:
                continue
            ins = next(cs.disasm(raw[offset:offset + 4], va, count=1), None)
            examined[mode] += 1
            if ins is None:
                continue
            operands = ins.operands
            target, description = None, None
            # Capstone 5 reports the MOVW encoding with ARM_INS_MOV on both
            # ISAs. Keep the encoding prefilter and the mnemonic family too.
            if (ins.id in (ARM_INS_MOV, ARM_INS_MOVW) and ins.mnemonic.startswith('movw')
                    and len(operands) == 2 and operands[0].type == ARM_OP_REG and operands[1].type == ARM_OP_IMM):
                following = next(cs.disasm(raw[offset + ins.size:offset + ins.size + 4], va + ins.size, count=1), None)
                if (following and following.id == ARM_INS_MOVT and len(following.operands) == 2
                        and following.operands[0].type == ARM_OP_REG and following.operands[0].reg == operands[0].reg
                        and following.operands[1].type == ARM_OP_IMM):
                    target = (operands[1].imm & 65535) | (following.operands[1].imm & 65535) << 16
                    description = 'adjacent MOVW/MOVT candidate; predicate/entry contracts separate'
            elif (ins.id == ARM_INS_MOVT and len(operands) == 2
                  and operands[0].type == ARM_OP_REG and operands[1].type == ARM_OP_IMM):
                if operands[1].imm & 65535 in wanted_high:
                    partials.append(dict(source_va=va, mode=mode, register=cs.reg_name(operands[0].reg),
                                         high_half=operands[1].imm & 65535,
                                         classification='MOVT high half can cover a protected span; incoming low half/entry not proved'))
            elif ins.id == ARM_INS_ADR and len(operands) == 2 and operands[1].type == ARM_OP_IMM:
                target = ((va + 4) & ~3) + operands[1].imm if mode == 'Thumb' else va + 8 + operands[1].imm
                description = 'PC-relative ADR candidate'
            elif (ins.id in (ARM_INS_ADD, ARM_INS_SUB) and len(operands) == 3
                  and operands[1].type == ARM_OP_REG and operands[1].reg == ARM_REG_PC
                  and operands[2].type == ARM_OP_IMM):
                pc = (va + 4) & ~3 if mode == 'Thumb' else va + 8
                target = pc + operands[2].imm * (-1 if ins.id == ARM_INS_SUB else 1)
                description = 'PC-relative arithmetic candidate'
            if target is not None and 0 <= target < 2**32:
                matching = _matches(spans, target & ~1)
                if matching:
                    hits.append(dict(source_va=va, mode=mode, target_va=target & ~1,
                                     instruction=ins.mnemonic + ' ' + ins.op_str,
                                     protected_spans=matching, classification=description))
    return dict(status='no resolved constructor targets' if not hits else 'potential constructor targets require resolution',
                scanned_regions=[dict(start=base, end=base + len(raw)) for base, raw in regions],
                examined_candidate_encodings=examined, hits=hits, partial_movt_constructors=partials,
                generation_allowed=False,
                limits=['All-alignments scans include literal pools and wrong ISA',
                        'Nonadjacent arithmetic, loads/runtime writes and arbitrary computed pointers remain unproved'])


def static_entry_inventory(driver, protected_spans):
    direct = direct_entry_audit(driver, protected_spans)
    absolute = absolute_pointer_inventory(driver, protected_spans)
    constructors = address_constructor_inventory(driver, protected_spans)
    hits = len(direct['hits']) + len(absolute['hits']) + len(constructors['hits'])
    return dict(schema='c10-static-entry-inventory-v1',
                status='no enumerated static targets' if hits == 0 else 'enumerated potential static targets require resolution',
                protected_spans=[dict(name=n, start=a, end=b) for n, a, b in _spans(protected_spans)],
                direct=direct, absolute=absolute, constructors=constructors,
                enumerated_target_hits=hits, complete_indirect_target_proof=False, generation_allowed=False,
                assumptions=['All file-backed executable LOAD decode alignments are overapproximated',
                             'Whole original image is fixed during this analysis'],
                blockers=['Runtime computed/loaded/register-indirect targets are not exhaustively resolved',
                          'Partial MOVT constructors have no complete incoming-value proof'])
