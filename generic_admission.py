"""Read-only, bounded transport/header/virtual-callback admission evidence.

This identifies a supported callback/reader/header grammar and a dispatch state
writer. It does not prove every indirect caller, runtime writer or IPC contract.
No firmware/version/hash/address oracle participates in discovery.
"""
from __future__ import annotations

import struct

from generic_analysis import matches
from generic_crypto import caller_seed_source
from generic_flow import ThumbGraph, linear, preceding
from generic_semantics import Context


def _target(ins):
    return int(ins.op_str.rsplit('#', 1)[1], 0)


def _literal(driver, ins):
    return struct.unpack('<I', driver.read(driver.literal(ins), 4))[0]


def _sequence(graph, start, specs):
    items = linear(graph, start, len(specs))
    if not matches(items, specs) or any(i.address in graph.predicated for i in items):
        raise ValueError('Unsupported admission instruction/data-flow block')
    return items


def header_contract(driver, target, encrypted_marker):
    """Decode this exact small leaf from a direct call, not an unwind guess."""
    try:
        text = driver.text
        if not text['sh_addr'] <= target < target + 34 <= text['sh_addr'] + text['sh_size']:
            return None
        graph = ThumbGraph(driver, target, target + 34)
        if graph.issues:
            return None
        first = linear(graph, target, 4)
        if len(first) != 4 or not first[1].op_str.startswith('r2, [pc, #'):
            return None
        _sequence(graph, target, [('ldr', 'r3, [r0]'), ('ldr', first[1].op_str),
                                 ('cmp', 'r3, r2'), ('beq', first[3].op_str)])
        second = linear(graph, target + 8, 3)
        if (len(second) != 3 or second[0].mnemonic != 'add.w'
                or not second[0].op_str.startswith('r2, r2, #')):
            return None
        _sequence(graph, target + 8, [('add.w', second[0].op_str), ('cmp', 'r3, r2'),
                                    ('bne', second[2].op_str)])
        good = _sequence(graph, target + 16, [
            ('ldr', 'r3, [r0, #8]'), ('mvns', 'r2, r3'), ('ldr', 'r3, [r0, #0xc]'),
            ('subs', 'r3, r3, r2'), ('rsbs', 'r0, r3, #0'), ('adcs', 'r0, r3'), ('bx', 'lr')])
        bad = _sequence(graph, target + 30, [('movs', 'r0, #0'), ('bx', 'lr')])
        if _target(first[3]) != good[0].address or _target(second[2]) != bad[0].address:
            return None
        base = _literal(driver, first[1])
        other = (base + int(second[0].op_str.rsplit('#', 1)[1], 0)) & 0xffffffff
        if base == other or other != encrypted_marker:
            return None
        if len(graph.nodes) != 16:
            return None
        return dict(status='checked header leaf', function_entry=target, plain_marker=base,
                    encrypted_marker=other, header_bytes=16, type_offset=8, inverse_type_offset=12,
                    predicate='marker in {plain_marker, encrypted_marker} and word[12] == uint32(~word[8])',
                    crypto_readiness_checked=False, payload_authentication=False,
                    graph=graph.summary(), generation_allowed=False)
    except (ValueError, IndexError):
        return None


def _readonly(driver, va, size):
    driver.offset(va, size)
    return not driver.writable(va, size)


def _typeinfo(driver, va):
    try:
        if not _readonly(driver, va, 8):
            return None
        pointer = struct.unpack('<II', driver.read(va, 8))[1]
        name = bytearray()
        for offset in range(128):
            if not _readonly(driver, pointer + offset, 1):
                return None
            byte = driver.read(pointer + offset, 1)[0]
            if byte == 0:
                if not name or not name[0:1].isdigit():
                    return None
                return dict(typeinfo_va=va, type_name_va=pointer, mangled_name=name.decode('ascii'))
            if byte not in b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_':
                return None
            name.append(byte)
    except ValueError:
        pass
    return None


def virtual_tables(driver, dispatch_entry):
    """Find readonly Itanium-style vtables containing the discovered dispatch."""
    findings = []
    for section in driver.elf.iter_sections():
        if (section['sh_type'] == 'SHT_NOBITS' or not section['sh_flags'] & 2
                or section['sh_flags'] & 1 or section['sh_size'] > 4 * 1024 * 1024):
            continue
        data, start = section.data(), section['sh_addr']
        for offset in range(0, len(data) - 3, 4):
            if struct.unpack_from('<I', data, offset)[0] != dispatch_entry | 1:
                continue
            for index in range(32):
                top = offset - 4 * (index + 2)
                if top < 0 or struct.unpack_from('<I', data, top)[0] != 0:
                    continue
                info = _typeinfo(driver, struct.unpack_from('<I', data, top + 4)[0])
                if info is None:
                    continue
                words = struct.unpack_from('<' + 'I' * (index + 1), data, top + 8)
                try:
                    for pointer in words:
                        if not pointer & 1:
                            raise ValueError('Non-Thumb vtable member')
                        driver.offset(pointer & ~1, 2, executable=True)
                except ValueError:
                    continue
                findings.append(dict(address_point_va=start + top + 8, slot_offset=index * 4,
                                     dispatch_pointer_va=start + offset, dispatch_entry=dispatch_entry,
                                     typeinfo=info, scope='readonly vtable structure; not exhaustive indirect-caller proof'))
    return findings


def callback_readers(context, tables, encrypted_marker):
    driver = context.driver
    text, base = driver.text.data(), driver.text['sh_addr']
    wanted = {t['slot_offset'] for t in tables}
    findings = []
    # The compiler-shape seed is a register BLX, followed backwards by the
    # object/vtable/message setup. Raw halfword matches must survive CFG decoding.
    for offset in range(8, len(text) - 1, 2):
        if text[offset:offset + 2] != b'\x98\x47':  # blx r3
            continue
        raw = list(driver.cs.disasm(text[offset - 8:offset + 2], base + offset - 8))
        if len(raw) != 5 or not matches(raw, [('ldr', 'r3, [r4]'), ('mov', 'r0, r4'), ('mov', 'r1, r5')]):
            continue
        if raw[3].mnemonic != 'ldr' or not raw[3].op_str.startswith('r3, [r3, #'):
            continue
        slot = int(raw[3].op_str.split('#')[1].split(']')[0], 0)
        if slot not in wanted:
            continue
        try:
            graph = context.graph(base + offset)
            if graph.nodes[base + offset].bytes != raw[-1].bytes:
                continue
            before = preceding(graph, raw[0].address, 7)
            if (len(before) != 7 or not matches(before[:3], [
                    ('add.w', 'r5, r4, #0x38'), ('ldr', 'r1, [r4, #0x1c]'), ('mov', 'r0, r5')])
                    or before[3].mnemonic != 'bl' or before[4].mnemonic != 'cbz'
                    or not before[4].op_str.startswith('r0, #')
                    or not matches(before[5:6], [('ldr', 'r3, [r4, #0x5c]')])
                    or before[6].mnemonic != 'cbnz' or not before[6].op_str.startswith('r3, #')):
                continue
            reader = context.graph(_target(before[3]))
            headers = []
            for call in reader.calls:
                if call['mode'] != 'Thumb' or call['target'] is None:
                    continue
                checked = header_contract(driver, call['target'], encrypted_marker)
                if checked:
                    headers.append(dict(call=call, contract=checked))
            if not headers:
                continue
            findings.append(dict(callback_va=base + offset, vtable_slot=slot, function_entry=graph.start,
                reader_call_va=before[3].address, reader_entry=reader.start,
                message_object_offset=0x38, descriptor_fd_offset=0x1c, override_callback_offset=0x5c,
                reader_nonzero_guard_va=before[4].address, callback_override_guard_va=before[6].address,
                header_validation_calls=headers, reader_graph=reader.summary(),
                scope='this virtual callback path requires nonzero native reader result; encrypted header is accepted by its leaf',
                unproved=['all successful reader postconditions and transport/library contracts',
                          'object/vtable ownership and all indirect callback callers']))
        except ValueError:
            continue
    return findings


def _type_source(graph, compare):
    sources = []
    for va, ins in graph.nodes.items():
        if (ins.mnemonic != 'ldr' or ins.op_str != 'r3, [r6, #8]' or va in graph.predicated
                or not graph.dominates(va, compare)):
            continue
        between = graph.reachable_from(va) & graph.reaching(compare)
        if any(graph.nodes[a].mnemonic in ('bl', 'blx') or
               {'r3', 'r6'} & {graph.cs.reg_name(r) for r in graph.nodes[a].regs_access()[1]}
               for a in between if a != va):
            continue
        sources.append(va)
    return sources[0] if len(sources) == 1 else None


def state_writers(graph, active_state):
    """Recognize positive type240 seed installation, modulo callees preserving r4/r6."""
    findings = []
    for va, ins in graph.nodes.items():
        if ins.mnemonic != 'cmp' or ins.op_str != 'r3, #0xf0' or va in graph.predicated:
            continue
        pair = linear(graph, va, 2)
        if len(pair) != 2 or pair[1].mnemonic not in ('beq', 'beq.w'):
            continue
        kind_source = _type_source(graph, va)
        if kind_source is None:
            continue
        body = _target(pair[1])
        guard = linear(graph, body, 7)
        if (len(guard) != 7 or not matches(guard[:2], [('ldr', 'r3, [r6, #4]'), ('cmp', 'r3, #4')])
                or guard[2].mnemonic not in ('bne', 'bne.w')
                or not matches(guard[3:6], [('ldr', 'r3, [r6, #0x10]'), ('ldr', 'r3, [r3]'), ('cmp', 'r3, #0')])
                or guard[6].mnemonic not in ('ble', 'ble.w') or _target(guard[2]) != _target(guard[6])):
            continue
        for target, store in graph.nodes.items():
            if store.mnemonic != 'str' or store.op_str != 'r3, [r4]' or target not in graph.reachable_from(body):
                continue
            copied = preceding(graph, target, 5)
            if (len(copied) != 5 or not matches(copied[:2], [('ldr', 'r3, [r6, #0x10]'), ('movs', 'r0, #5')])
                    or not copied[2].op_str.startswith('r1, [pc, #') or copied[2].mnemonic != 'ldr'
                    or not copied[3].op_str.startswith('r2, [pc, #') or copied[3].mnemonic != 'ldr'
                    or not matches(copied[4:], [('ldr', 'r3, [r3]')])):
                continue
            source = caller_seed_source(graph, dict(va=target))
            if source.get('source_va') != active_state or not graph.dominates(guard[6].address, target):
                continue
            findings.append(dict(message_type=240, length=4, signed_payload_test='int32(payload[0]) > 0',
                type_load_va=kind_source, type_compare_va=va, guard_va=body, store_va=target, destination_va=active_state,
                payload_reload_va=copied[0].address, source='descriptor[16] first word after response send',
                pointer_source=source, scope='bounded dispatch path; not an exhaustive writer/race proof',
                assumptions=['intervening calls preserve callee-saved r4/r6 and descriptor/payload']))
    return findings


def analyze_admission(driver, dispatch_entry, crypto_contract):
    context = Context(driver)
    result = dict(schema='c10-bounded-admission-evidence-v1', generation_allowed=False,
                  unconditional_plaintext_proved=False, complete_indirect_entry_proof=False)
    try:
        graph = context.graph(dispatch_entry)
        if graph.start != dispatch_entry or graph.issues:
            raise ValueError('Dispatch has no closed supported range')
        marker = crypto_contract['encrypted_flag']['encrypted_marker']
        active = crypto_contract['active_state_va']
        tables = virtual_tables(driver, dispatch_entry)
        result.update(vtables=tables, callback_readers=callback_readers(context, tables, marker),
                      crypto_state_writers=state_writers(graph, active), crypto_state_va=active,
                      elf_zero_initialized=any(s['p_flags'] == 6 and s['p_vaddr'] + s['p_filesz'] <= active
                          and active + 4 <= s['p_vaddr'] + s['p_memsz'] for s in driver.loads),
                      limits=['readonly vtable candidates do not enumerate every indirect entry',
                              'header validation accepts encrypted framing and does not establish decrypted payload',
                              'all aliases/writers, transport postconditions and runtime ordering remain unproved'])
    except (ValueError, KeyError) as error:
        result['unsupported'] = str(error)
    return result
