"""Restricted checked geometry consumers selected by effective-Open data xrefs.

Reports code-level contracts and unresolved interprocedural assumptions. These
are supporting evidence, not a complete ABI proof or permission to generate.
"""
import struct

from generic_analysis import matches
from generic_flow import linear, preceding, plt_import


def value(driver, ins):
    return struct.unpack('<I', driver.read(driver.literal(ins), 4))[0]


def response(graph, xref):
    start = xref['site']['va']
    block = linear(graph, start, 10)
    before = preceding(graph, start, 5)
    if len(block) != 10 or len(before) != 5:
        return None
    if not matches(before[:4], [('add', 'r0, sp, #4'), ('movs', 'r1, #0x1c'),
                               ('movs', 'r3, #1'), ('str', 'r3, [sp, #0xc]')]) or before[4].mnemonic != 'bl':
        return None
    if not matches(block[1:9], [('ldr', 'r4, [sp, #0x14]'), ('ldm', 'r5!, {r0, r1, r2, r3}'),
            ('stm', 'r4!, {r0, r1, r2, r3}'), ('ldm.w', 'r5, {r0, r1, r2}'),
            ('stm.w', 'r4, {r0, r1, r2}'), ('mov', 'r0, r6'), ('add', 'r1, sp, #4'), ('movs', 'r2, #0')]):
        return None
    if not block[0].op_str.startswith('r5, [pc, #') or block[9].mnemonic != 'bl':
        return None
    initializer = min(graph.calls, key=lambda c: c['va'])
    return dict(function_entry=graph.start, source_xref_va=start, source_va=xref['pointer_va'],
                initializer_target=initializer['target'],
                size=28, message_type=1, resize_call_va=before[4].address,
                resize_target=before[4].operands[0].imm, copy_start_va=block[2].address,
                send_call_va=block[9].address, send_target=block[9].operands[0].imm,
                scope='28-byte effective Open copy after type1/length28 object setup')


def remote(graph, xref):
    start = xref['site']['va']
    source = linear(graph, start, 5)
    if len(source) != 5 or not source[0].op_str.startswith('r4, [pc, #') or not matches(source[1:2], [('ldr', 'r3, [r4]')]):
        return None
    if (source[2].mnemonic != 'cbz' or not source[2].op_str.startswith('r3, #')
            or source[3].mnemonic != 'ldr' or source[3].op_str != 'r3, [r4, #4]'
            or source[4].mnemonic != 'cbnz' or not source[4].op_str.startswith('r3, #')):
        return None
    body = source[4].operands[-1].imm
    build = linear(graph, body, 5)
    if not matches(build[:4], [('add', 'r0, sp, #0xc'), ('movs', 'r1, #0xf0'),
                              ('mov', 'r2, r4'), ('movs', 'r3, #0x1c')]) or len(build) != 5 or build[4].mnemonic != 'bl':
        return None
    sends = []
    for va in graph.nodes:
        seq = linear(graph, va, 3)
        if matches(seq, [('movs', 'r0, #0x1e'), ('add', 'r1, sp, #0xc'),
                         ('bl', seq[2].op_str if len(seq) == 3 else '')]) and graph.dominates(body, va):
            sends.append(seq)
    if len(sends) != 1:
        return None
    seq = sends[0]
    guards = preceding(graph, start, 3)
    flag = None
    if (len(guards) == 3 and guards[0].mnemonic == 'ldr' and guards[0].op_str.startswith('r3, [pc, #')
            and guards[1].mnemonic == 'ldrb' and guards[1].op_str == 'r3, [r3, #0x14]' and guards[2].mnemonic == 'cbz'):
        flag = value(graph.driver, guards[0]) + 20
    logger_calls = [c for c in graph.calls if build[4].address < c['va'] < seq[0].address]
    return dict(function_entry=graph.start, source_xref_va=start, source_va=xref['pointer_va'],
                open_flag_va=flag,
                nonzero_width_guard=source[2].address, nonzero_height_guard=source[4].address,
                build_va=body, inner_type=240, outer_type=30, size=28,
                build_call_va=build[4].address, build_target=build[4].operands[0].imm,
                send_call_va=seq[2].address, send_target=seq[2].operands[0].imm,
                intermediate_calls=logger_calls,
                scope='effective Open passed as inner240 payload before outer30 send; not box-info/type25')


def aa_link(graph, xref):
    start = xref['site']['va']
    seq = linear(graph, start, 8)
    if len(seq) != 8 or not seq[0].op_str.startswith('r3, [pc, #') or not matches(seq[1:], [
            ('movs', 'r0, #2'), ('strb.w', 'r5, [sp, #0x24]'), ('str', 'r0, [sp, #0x14]'),
            ('ldm', 'r3, {r1, r2, r3}'), ('str', 'r1, [sp, #0x18]'),
            ('str', 'r2, [sp, #0x1c]'), ('str', 'r3, [sp, #0x20]')]):
        return None
    guard = preceding(graph, start, 3)
    if (len(guard) != 3 or guard[0].mnemonic != 'ldr' or guard[0].op_str != 'r3, [r7]'
            or guard[1].mnemonic != 'cmp' or guard[2].mnemonic not in ('beq', 'beq.w')):
        return None
    selectors = [i for va, i in graph.nodes.items() if i.mnemonic == 'ldr'
                 and i.op_str.startswith('r7, [pc, #') and graph.dominates(va, start)]
    if len(selectors) != 1:
        return None
    gates, sends = [], []
    for va in graph.nodes:
        gate = linear(graph, va, 5)
        if (len(gate) == 5 and matches(gate[:1], [('mov', 'r0, r8')])
                and gate[1].mnemonic == 'ldr' and gate[1].op_str.startswith('r1, [pc, #')
                and gate[2].mnemonic == 'blx' and gate[3].mnemonic == 'mov'
                and gate[3].op_str == 'r5, r0' and gate[4].mnemonic == 'cbnz'
                and graph.dominates(gate[2].address, start)):
            imp = plt_import(graph.driver, gate[2].operands[0].imm)
            if imp and imp['symbol'] == 'strcmp' and graph.driver.read(value(graph.driver, gate[1]), 4) == b'AAP\0':
                gates.append(gate[2].address)
        send = linear(graph, va, 4)
        if (len(send) == 4 and send[0].mnemonic == 'movs' and send[0].op_str == 'r0, #5' and send[1].mnemonic == 'movs'
                and send[1].op_str.startswith('r1, #') and send[2].mnemonic == 'add' and send[2].op_str == 'r2, sp, #0x14'
                and send[3].mnemonic == 'bl' and va in graph.reachable_from(seq[-1].address)):
            sends.append(send)
    if len(gates) != 1 or len(sends) != 1:
        return None
    send = sends[0]
    return dict(function_entry=graph.start, source_xref_va=start, source_va=xref['pointer_va'],
                aap_strcmp_va=gates[0], selector_variable_va=value(graph.driver, selectors[0]),
                already_connected_selector=int(guard[1].op_str.split('#')[1], 0),
                channel=int(send[1].op_str.split('#')[1], 0),
                link_record_stack_offset=20, dimensions_stack_offsets=[24, 28, 32],
                copy_start_va=seq[4].address, send_setup_va=send[0].address,
                send_call_va=send[3].address, send_target=send[3].operands[0].imm,
                scope='AAP string gate supplies geometry link channel; link-state and touch-selector globals require separate comparison')


def hu_screen(graph, xref):
    if not xref['site']['instruction'].startswith('ldr.w sb, [pc, #'):
        return None
    aliases = [va for va, i in graph.nodes.items() if i.mnemonic == 'mov' and i.op_str == 'r6, sb'
               and graph.dominates(xref['site']['va'], va)]
    copies, writers = [], []
    expected = [('ldr', 'r3, [r6]'), ('add', 'r1, sp, #0x10'), ('movs', 'r2, #0x18'),
                ('str', 'r3, [r4]'), ('ldr', 'r3, [r6, #4]'), ('str', 'r3, [r4, #4]'),
                ('ldr', 'r3, [sp, #8]'), ('str', 'r3, [r4, #8]'), ('ldr', 'r3, [sp, #0xc]'),
                ('str', 'r3, [r4, #0xc]'), ('ldr', 'r3, [r6, #8]'), ('str', 'r3, [r4, #0x10]'),
                ('str', 'r0, [r4, #0x14]')]
    for va in graph.nodes:
        if matches(linear(graph, va, len(expected)), expected) and any(graph.dominates(a, va) for a in aliases):
            copies.append(va)
        seq = linear(graph, va, 4)
        if (len(seq) == 4 and seq[0].mnemonic == 'ldr' and seq[0].op_str.startswith('r0, [pc, #')
                and matches(seq[1:3], [('mov', 'r1, r4'), ('movs', 'r2, #0x18')]) and seq[3].mnemonic == 'bl'):
            try:
                if graph.driver.read(value(graph.driver, seq[0]), 15) == b'HU_SCREEN_INFO\0':
                    writers.append(seq)
            except ValueError:
                pass
    if len(copies) != 1 or len(writers) != 1 or not graph.dominates(copies[0], writers[0][0].address):
        return None
    aliases = [va for va in aliases if graph.dominates(va, copies[0])]
    if len(aliases) != 1:
        return None
    between = graph.reachable_from(aliases[0]) & graph.reaching(copies[0])
    if any(va != aliases[0] and any(graph.cs.reg_name(r) == 'r6' for r in ins.regs_access()[1])
           for va, ins in graph.nodes.items() if va in between):
        return None
    seq = writers[0]
    copy = linear(graph, copies[0], len(expected))
    return dict(function_entry=graph.start, source_xref_va=xref['site']['va'], source_va=xref['pointer_va'],
                source_alias_va=aliases[0], copy_start_va=copies[0], write_setup_va=seq[0].address,
                copy_end_va=copy[-1].address + copy[-1].size,
                write_call_va=seq[3].address, write_target=seq[3].operands[0].imm,
                record_size=24, width_offset=0, height_offset=4, fps_offset=16,
                scope='effective dimensions flow into named HU_SCREEN_INFO record before write call')


def geometry_consumers(context, xrefs):
    result = {role: [] for role in ('type1_response', 'remote_cxcy', 'aa_link', 'hu_screen_info')}
    for xref in xrefs:
        if xref['role'] != 'effective Open':
            continue
        graph = context.graph(xref['site']['va'])
        if graph.issues:
            continue
        for role, detector in zip(result, (response, remote, aa_link, hu_screen)):
            item = detector(graph, xref)
            if item:
                item.update(graph_closed_within_range=True, interprocedural_contracts_proved=False)
                result[role].append(item)
    return result
