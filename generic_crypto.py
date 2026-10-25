"""Restricted, entry-relative Open message-CFB contract recognition.

This is separate from packed-file CBC decoding. No key/IV bytes are reported.
Import implementations, external entries and runtime state provenance remain
assumptions; a conditional CFB contract never establishes unconditional plaintext.
"""
from __future__ import annotations

import struct

from capstone.arm_const import ARM_CC_LT, ARM_OP_IMM

from firmware import sha256
from generic_flow import ThumbGraph, linear


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _sequence(graph, start, specs, it_indices=()):
    items = linear(graph, start, len(specs))
    _need(len(items) == len(specs), 'Truncated/disconnected message-crypto block')
    for index, (ins, (mnemonic, operands)) in enumerate(zip(items, specs)):
        _need(ins.mnemonic in mnemonic.split('|') and (operands is None or ins.op_str == operands),
              f'Unsupported message-crypto instruction at {ins.address:#x}')
        _need((ins.address in graph.predicated) == (index in it_indices),
              'Unexpected message-crypto predication')
        if index in it_indices:
            _need(graph.predicated[ins.address] == ARM_CC_LT, 'Unexpected key-loop IT condition')
        following = ins.address + ins.size
        if ins.mnemonic in ('b', 'b.w'):
            expected = {_target(ins)}
        elif ins.mnemonic.startswith('b') and ins.mnemonic not in ('bl', 'blx', 'bx'):
            expected = {_target(ins), following}
        elif ins.mnemonic in ('bx', 'pop', 'pop.w'):
            expected = set()
        else:
            expected = {following}
        _need(graph.edges[ins.address] == expected, 'Unexpected message-crypto block successors')
    return items


def _target(ins):
    _need(ins.operands[-1].type == ARM_OP_IMM, 'Indirect message-crypto transfer')
    return ins.operands[-1].imm


def _after(ins):
    return ins.address + ins.size


def _literal(driver, ins, register):
    _need(ins.mnemonic in ('ldr', 'ldr.w') and ins.op_str.startswith(register + ', [pc, #'),
          'Unsupported message-crypto literal load')
    return struct.unpack('<I', driver.read(driver.literal(ins), 4))[0]


def _import(graph, ins, name):
    calls = [c for c in graph.calls if c['va'] == ins.address]
    _need(len(calls) == 1 and calls[0]['imported'] and calls[0]['imported']['symbol'] == name,
          f'Message-crypto import is not {name}')
    return calls[0]


def _flag(context, target):
    # Leaf helpers need not have individual unwind entries. Decode this exact
    # six-instruction, 12-byte leaf from its direct-call target, never an
    # enclosing unrelated unwind entry. Its literal remains separately mapped.
    text = context.driver.text
    _need(text['sh_addr'] <= target < target + 12 <= text['sh_addr'] + text['sh_size'],
          'Encryption-marker leaf is outside .text')
    graph = ThumbGraph(context.driver, target, target + 12)
    _need(not graph.issues, 'Unsupported encryption-marker helper graph')
    items = _sequence(graph, target, [
        ('ldr', 'r0, [r0]'), ('ldr', None), ('subs', 'r3, r0, r3'),
        ('rsbs', 'r0, r3, #0'), ('adcs', 'r0, r3'), ('bx', 'lr')])
    _need(set(graph.nodes) == {i.address for i in items}, 'Unexpected encryption-marker helper path')
    marker = _literal(context.driver, items[1], 'r3')
    return dict(function_entry=target, descriptor_offset=0, encrypted_marker=marker,
                result='1 iff descriptor word equals encrypted_marker; otherwise 0')


def caller_seed_source(graph, call):
    """Derive the dominating literal-backed r4 seed source, modulo callee ABI."""
    sources = []
    for va, ins in graph.nodes.items():
        if ins.mnemonic != 'ldr' or not ins.op_str.startswith('r4, [pc, #') or va in graph.predicated:
            continue
        if not graph.dominates(va, call['va']):
            continue
        between = graph.reachable_from(va) & graph.reaching(call['va'])
        if any('r4' in {graph.cs.reg_name(r) for r in graph.nodes[a].regs_access()[1]}
               for a in between if a != va):
            continue
        source = _literal(graph.driver, ins, 'r4')
        if graph.driver.writable(source, 4):
            sources.append(dict(literal_load_va=va, source_va=source))
    if graph.issues or len(sources) != 1:
        return dict(status='unsupported', reason='No unique unmodified dominating seed pointer')
    return dict(status='checked modulo callee-saved r4 contract', **sources[0],
                assumptions=['intervening callees preserve r4', 'runtime writers/concurrency not proved'])


def plain_packet_marker(driver, initializer):
    """Derive the native packet initializer's explicit unencrypted marker.

    This is a restricted initializer contract, not transport admission proof.
    """
    graph = ThumbGraph(driver, initializer, initializer + 28)
    _need(not graph.issues, 'Unsupported packet initializer graph')
    specs = [('ldr', None), ('str', 'r2, [r0]'), ('movs', 'r2, #0')]
    specs += [('str', f'r2, [r0, #{offset:#x}]' if offset >= 10 else f'r2, [r0, #{offset}]')
              for offset in range(4, 32, 4)]
    specs += [('mov.w', 'r2, #-1'), ('str', 'r2, [r0, #0x20]'), ('bx', 'lr')]
    items = _sequence(graph, initializer, specs)
    _need(set(graph.nodes) == {i.address for i in items}, 'Unexpected initializer paths')
    return dict(status='checked explicit packet initializer marker', initializer_va=initializer,
                marker=_literal(driver, items[0], 'r2'),
                scope='descriptor offset zero; remaining fields initialized independently')


def open_cfb_contract(context, helper, call):
    """Recognize *all entry paths* specialized to direction=0 and type=1.

    Nonzero directions and non-Open logging switches are deliberately outside
    scope. Exact branch relationships connect checked blocks, including bypasses.
    No outside-entry or cryptographic-library implementation proof is implied.
    """
    try:
        return _open_cfb_contract(context, helper, call)
    except ValueError as error:
        return dict(status='unsupported', reason=str(error), plaintext_at_hook_proved=False,
                    generation_allowed=False)


def _open_cfb_contract(context, helper, call):
    d = context.driver
    _need(helper.start == call['target'] and not helper.issues, 'Unclosed message-crypto helper graph')
    prefix = _sequence(helper, helper.start, [
        ('push.w', '{r4, r5, r6, r7, r8, sb, lr}'), ('mov', 'r8, r0'),
        ('sub', 'sp, #0x12c'), ('mov', 'r0, r1'), ('mov', 'r4, r1'), ('mov', 'r7, r2'),
        ('bl', None), ('ldr', None), ('cmp', 'r0, #0'), ('beq|beq.w', None),
        ('cmp.w', 'r8, #0'), ('bne|bne.w', None), ('ldr', 'r2, [r3]'),
        ('cmp', 'r2, #0'), ('bgt|bgt.w', None), ('ldr', 'r3, [r4, #8]')])
    flag = _flag(context, _target(prefix[6]))
    active = _literal(d, prefix[7], 'r3')
    _need(d.writable(active, 4), 'Crypto active-state word is not writable')
    gate = _target(prefix[9])
    _need(_target(prefix[11]) == gate == _target(prefix[14]), 'Crypto entry guards disagree')
    # For type=1, only pure comparisons and their untaken branches precede the
    # selected logging arm. No first-match search or unchecked intervening code.
    va = _after(prefix[-1])
    for _ in range(64):
        compare, branch = _sequence(helper, va, [('cmp', None), ('beq|beq.w', None)])
        _need(compare.op_str.startswith('r3, #') and compare.operands[1].type == ARM_OP_IMM,
              'Unsupported Open logging switch')
        if compare.operands[1].imm == 1:
            va = _target(branch)
            break
        va = _after(branch)
    else:
        raise ValueError('Open diagnostic arm not found within switch budget')
    log_arm = _sequence(helper, va, [('ldr', None), ('b|b.w', None)])
    _literal(d, log_arm[0], 'r3')
    log = _sequence(helper, _target(log_arm[1]), [
        ('ldr', None), ('movs', 'r0, #6'), ('ldr', None), ('bl', None), ('b|b.w', None)])
    for ins, register in ((log[0], 'r1'), (log[2], 'r2')):
        _literal(d, ins, register)
    exit_va = _target(log[-1])
    _sequence(helper, exit_va, [('add', 'sp, #0x12c'), ('pop.w', '{r4, r5, r6, r7, r8, sb, pc}')])
    guards = _sequence(helper, gate, [
        ('ldr', 'r3, [r3]'), ('cmp', 'r3, #0'), ('ble|ble.w', None),
        ('ldr', 'r3, [r4, #4]'), ('cmp', 'r3, #0'), ('beq|beq.w', None),
        ('cmp.w', 'r8, #0'), ('beq|beq.w', None)])
    _need(_target(guards[2]) == _target(guards[5]) == exit_va, 'Crypto bypass does not return directly')
    flag_check = _sequence(helper, _target(guards[-1]), [
        ('mov', 'r0, r4'), ('bl', None), ('cmp', 'r0, #0'), ('beq|beq.w', None)])
    _need(_target(flag_check[1]) == flag['function_entry'] and _target(flag_check[-1]) == exit_va,
          'Crypto marker recheck/bypass differs')
    init = _sequence(helper, _after(flag_check[-1]), [
        ('add', 'r5, sp, #0x14'), ('add.w', 'sb, sp, #0x24'), ('movs', 'r1, #0'),
        ('movs', 'r2, #0x10'), ('mov', 'r0, r5'), ('add', 'r6, sp, #0x10'), ('blx', None),
        ('movs', 'r1, #0'), ('mov', 'r0, sb'), ('movs', 'r2, #0x10'), ('blx', None),
        ('ldr', None), ('asrs', 'r3, r7, #8'), ('movs', 'r1, #0'), ('strb', 'r3, [r5, #4]'),
        ('asrs', 'r3, r7, #0x10'), ('str', 'r1, [r6]'), ('strb', 'r3, [r5, #9]'),
        ('lsrs', 'r3, r7, #0x18'), ('strb', 'r7, [r5, #1]'), ('strb', 'r3, [r5, #0xc]')])
    for index in (6, 10):
        _import(helper, init[index], 'memset')
    table = _literal(d, init[11], 'r0')
    # Signed C remainder can address up to fifteen bytes *before* the table.
    table_window = d.read(table - 15, 31)
    _need(not d.writable(table - 15, 31), 'Message key table is writable')
    loop = _sequence(helper, _after(init[-1]), [
        ('ldr', None), ('adds', 'r2, r1, r7'), ('ands', 'r3, r2'), ('cmp', 'r3, #0'),
        ('ittt', 'lt'), ('add.w', 'r3, r3, #-1'), ('orn', 'r3, r3, #0xf'),
        ('adds', 'r3, #1'), ('ldrb', 'r3, [r3, r0]'), ('strb.w', 'r3, [sb, r1]'),
        ('adds', 'r1, #1'), ('cmp', 'r1, #0x10'), ('bne|bne.w', None)], it_indices=(5, 6, 7))
    _need(_literal(d, loop[0], 'r3') == 0x8000000f and _target(loop[-1]) == loop[0].address,
          'Unsupported signed key-table indexing or loop bound')
    key = _sequence(helper, _after(loop[-1]), [
        ('mov', 'r0, sb'), ('movs', 'r1, #0x80'), ('add', 'r2, sp, #0x34'),
        ('blx', None), ('cmp.w', 'r8, #0'), ('beq|beq.w', None)])
    key_call = _import(helper, key[3], 'AES_set_encrypt_key')
    cfb = _sequence(helper, _target(key[-1]), [
        ('stm.w', 'sp, {r5, r6, r8}'), ('add', 'r3, sp, #0x34'),
        ('ldr', 'r0, [r4, #0x10]'), ('ldr', 'r2, [r4, #4]'), ('mov', 'r1, r0'), ('blx', None)])
    cfb_call = _import(helper, cfb[-1], 'AES_cfb128_encrypt')
    _need(_after(cfb[-1]) == exit_va, 'CFB continuation does not return directly')
    return dict(schema='c10-open-message-cfb-contract-v1',
                status='checked entry-relative Open CFB contract', direction=0, message_type=1,
                plaintext_at_hook_proved=False, generation_allowed=False, encrypted_flag=flag,
                active_state_va=active, active_test='signed int32 > 0',
                helper_entry=helper.start, helper_exit_va=exit_va, logger_target=_target(log[3]),
                key_setup=key_call, cfb_call=cfb_call,
                key_derivation=dict(seed='incoming uint32 r2, preserved as r7',
                    table_va=table, table_read_window_sha256=sha256(table_window),
                    table_index_bounds=[-15, 15], bytes=16,
                    expression='table[truncating_signed_remainder(int32(seed + i), 16)], i=0..15'),
                iv_derivation=dict(bytes=16, initial_value='all zero',
                    seed_byte_to_iv_offset=[1, 4, 9, 12]),
                cfb_arguments=dict(input='descriptor[16]', output='same payload pointer',
                    length='descriptor[4]', key_bits=128, num_initial=0, direction=0,
                    iv='stack-local seed-derived 16 bytes', key='stack-local expanded key'),
                entry_paths=[
                    dict(when='marker differs', effect='return without CFB'),
                    dict(when='marker matches, active <= 0', effect='diagnostic call; no CFB; plaintext unestablished'),
                    dict(when='marker matches, active > 0, length == 0', effect='return without CFB'),
                    dict(when='active > 0, length != 0, marker matches', effect='in-place CFB with direction 0')],
                assumptions=['entry receives a valid nonaliasing descriptor and length-bounded payload',
                    'imported memset and AES implementations obey the recorded contracts',
                    'diagnostic callee preserves message and callee-saved state; not proved here',
                    'no outside entry; runtime crypto-state/seed and caller provenance are not proved'],
                blocker='Encrypted Open with inactive crypto state has no established plaintext postcondition')
