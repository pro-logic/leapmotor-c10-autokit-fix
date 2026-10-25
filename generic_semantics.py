"""Checked, narrowly scoped semantic evidence; never generation authority.

No fixture addresses, firmware versions, complete-file hashes or channel values
select a site. This adds bounded CFG/data-flow checks to candidate discovery.
Outside entries, callee contracts and end-to-end protocol meanings stay explicit.
"""
from __future__ import annotations

import re
import struct

from capstone.arm_const import ARM_REG_PC

from generic_analysis import matches
from generic_flow import ThumbGraph, enclosing_range, unwind_ranges, preceding


class Context:
    def __init__(self, driver):
        self.driver = driver
        self.ranges = unwind_ranges(driver)
        self.graphs = {}

    def graph(self, va):
        bounds = [(lo, hi) for lo, hi in self.ranges if lo <= va < hi]
        if len(bounds) != 1:
            raise ValueError('No unique unwind interval')
        lo, hi = bounds[0]
        if (lo, hi) not in self.graphs:
            # Check against executable .text before traversing.
            enclosing_range(self.driver, va)
            self.graphs[lo, hi] = ThumbGraph(self.driver, lo, hi)
        graph = self.graphs[lo, hi]
        if va not in graph.nodes:
            raise ValueError('Site is not reachable from bounded range entry')
        return graph


def instruction_effects(graph, va):
    ins = graph.nodes[va]
    reads, writes = ins.regs_access()
    return dict(**graph.site(va), reads=[graph.cs.reg_name(r) for r in reads],
                writes=[graph.cs.reg_name(r) for r in writes],
                updates_flags=ins.update_flags, predicated=va in graph.predicated,
                pc_independent=ARM_REG_PC not in reads and ARM_REG_PC not in writes,
                relocation_status='instruction effects only; trampoline not generated')


def dead_before_read(graph, start, registers=('r0', 'r1', 'r2', 'r3')):
    pending, dead, blocked = set(registers), set(), set()
    va = start
    for _ in range(32):
        if not pending or va not in graph.nodes or va in graph.predicated:
            break
        ins = graph.nodes[va]
        if len(graph.edges[va]) != 1 or va + ins.size not in graph.edges[va] or ins.mnemonic in ('bl', 'blx'):
            break
        reads, writes = ins.regs_access()
        old_reads = pending & {graph.cs.reg_name(r) for r in reads}
        blocked |= old_reads
        pending -= old_reads
        killed = pending & {graph.cs.reg_name(r) for r in writes}
        dead |= killed
        pending -= killed
        va += ins.size
    return dict(dead=sorted(dead), read_before_overwrite=sorted(blocked), unknown=sorted(pending),
                scope='unconditional straight-line continuation; integer registers only')


def preprocessing(context, graph, hook):
    results = []
    if graph.issues:
        return results
    for call in graph.calls:
        if call['mode'] != 'Thumb' or call['target'] is None or call['va'] in graph.predicated or not graph.dominates(call['va'], hook):
            continue
        before = preceding(graph, call['va'], 3)
        if not matches(before, [('movs', 'r0, #0'), ('mov', 'r1, r6'), ('ldr', 'r2, [r4]')]):
            continue
        try:
            helper = context.graph(call['target'])
        except ValueError:
            continue
        if helper.issues:
            continue
        aes = [c for c in helper.calls if c['imported'] and c['imported']['symbol'] == 'AES_cfb128_encrypt']
        key = [c for c in helper.calls if c['imported'] and c['imported']['symbol'] == 'AES_set_encrypt_key']
        prefix = [helper.nodes[v] for v in sorted(helper.nodes)[:6]]
        if not aes or not key or not matches(prefix, [
                ('push.w', '{r4, r5, r6, r7, r8, sb, lr}'), ('mov', 'r8, r0'),
                ('sub', 'sp, #0x12c'), ('mov', 'r0, r1'), ('mov', 'r4, r1'), ('mov', 'r7, r2')]):
            continue
        for crypto in aes:
            args = preceding(helper, crypto['va'], 4)
            if not matches(args, [('add', 'r3, sp, #0x34'), ('ldr', 'r0, [r4, #0x10]'),
                                  ('ldr', 'r2, [r4, #4]'), ('mov', 'r1, r0')]):
                continue
            directions = [helper.nodes[v] for v in helper.predecessors[args[0].address]
                          if matches([helper.nodes[v]], [('stm.w', 'sp, {r5, r6, r8}')])]
            if len(directions) != 1:
                continue
            direction = directions[0]
            guards = [helper.nodes[v] for v in helper.predecessors[direction.address]]
            if len(guards) != 1 or guards[0].mnemonic not in ('beq', 'beq.w') or not matches(
                    preceding(helper, guards[0].address, 1), [('cmp.w', 'r8, #0')]):
                continue
            results.append(dict(call=call, call_dominates_hook=True, input_message_register='r6', direction_argument=0,
                                helper_graph=helper.summary(), cfb_call=crypto, key_setup_calls=key,
                                zero_direction_store_va=direction.address, zero_direction_guard_va=guards[0].address,
                                checked=['helper receives the same message descriptor before Open dispatch',
                                         'conditional CFB call uses message payload in-place and message length',
                                         'CFB direction stack argument derives from incoming zero'],
                                unproved=['helper encryption-flag/bypass conditions and caller contracts',
                                          'cryptographic primitive implementation and key derivation correctness']))
    return results


def channel_routes(graph, touch):
    if graph.issues:
        return dict(status='unsupported', reason='Control-flow graph has unresolved transfers')
    hook, start = touch['hook']['va'], touch['normalization_start_va']
    stores = []
    for va, ins in graph.nodes.items():
        match = re.fullmatch(r'r2, \[sp, #(0x[0-9a-f]+|[0-9]+)\]', ins.op_str)
        if (ins.mnemonic in ('str', 'str.w') and match and 0 < start - va < 128
                and graph.dominates(va, hook)):
            stores.append((va, int(match[1], 0)))
    if len(stores) != 1:
        return dict(status='unsupported', reason='Need unique dominating channel stack store')
    store, offset = stores[0]
    prior = preceding(graph, store, 1)
    if len(prior) != 1 or prior[0].mnemonic != 'cmp.w' or not prior[0].op_str.startswith('sl, #'):
        return dict(status='unsupported', reason='Unsupported channel join')
    join = prior[0].address
    routes = []
    for source in sorted(graph.predecessors[join]):
        ins = graph.nodes[source]
        assignment = ins if source + ins.size == join else None
        if ins.mnemonic in ('b', 'b.w'):
            prev = preceding(graph, source, 1)
            assignment = prev[0] if prev else None
        match = re.fullmatch(r'r2, #(0x[0-9a-f]+|[0-9]+)', assignment.op_str) if assignment else None
        if not match or assignment.mnemonic != 'movs':
            return dict(status='unsupported', reason='Unresolved channel input to join')
        selector = []
        for edge in sorted(graph.predecessors[assignment.address]):
            branch = graph.nodes[edge]
            compare = preceding(graph, edge, 1)
            if branch.mnemonic not in ('beq', 'beq.w') or len(compare) != 1:
                continue
            condition = re.fullmatch(r'r3, #(0x[0-9a-f]+|[0-9]+)', compare[0].op_str)
            if compare[0].mnemonic == 'cmp' and condition:
                selector.append(dict(compare_va=compare[0].address, branch_va=edge, value=int(condition[1], 0),
                                     variable_va=selector_variable(graph, compare[0].address)))
        routes.append(dict(assignment_va=assignment.address, channel=int(match[1], 0), selector_edges=selector))
    # Explicit SP writes between the store and hook would invalidate this offset.
    between = graph.reachable_from(store) & graph.reaching(hook)
    sp_writes = []
    for va in between:
        if va == store or va == hook:
            continue
        ins = graph.nodes[va]
        _, writes = ins.regs_access()
        if any(graph.cs.reg_name(r) == 'sp' for r in writes):
            sp_writes.append(va)
    selector_loads = [v for v, i in graph.nodes.items() if i.mnemonic == 'ldr' and i.op_str == 'r3, [r2]'
                      and preceding(graph, v, 1) and preceding(graph, v, 1)[0].mnemonic == 'ldr'
                      and preceding(graph, v, 1)[0].op_str.startswith('r2, [pc, #')
                      and graph.dominates(v, hook)]
    return dict(status='checked bounded routing' if not sp_writes else 'unsupported',
                channel_store_va=store, join_va=join, channel_stack_offset=offset,
                selector_load_va=selector_loads[0] if len(selector_loads) == 1 else None,
                selector_setup_va=preceding(graph, selector_loads[0], 1)[0].address if len(selector_loads) == 1 else None,
                output_pointer_stack_offset=int(graph.nodes[start + 6].op_str.split('#')[1].split(']')[0], 0),
                store_dominates_hook=graph.dominates(store, hook), routes=routes,
                explicit_sp_writes_before_hook=sorted(sp_writes),
                unproved=['AA meaning of selector/channel values', 'callee stack balance and all outside incoming edges',
                          'saved stack offset depends on a future generated hook prologue'])


def selector_variable(graph, va):
    """Trace the unmodified selector back to a literal-backed global word load."""
    for _ in range(64):
        preds = graph.predecessors[va]
        if len(preds) != 1:
            return None
        ins = graph.nodes[next(iter(preds))]
        if ins.mnemonic in ('bl', 'blx'):
            return None
        _, writes = ins.regs_access()
        if any(graph.cs.reg_name(r) == 'r3' for r in writes):
            if ins.mnemonic != 'ldr' or ins.op_str != 'r3, [r2]':
                return None
            source = preceding(graph, ins.address, 1)
            if not source or source[0].mnemonic != 'ldr' or not source[0].op_str.startswith('r2, [pc, #'):
                return None
            return struct.unpack('<I', graph.driver.read(graph.driver.literal(source[0]), 4))[0]
        va = ins.address
    return None


def geometry_xrefs(context, original, effective):
    driver = context.driver
    result = []
    text, base = driver.text.data(), driver.text['sh_addr']
    wanted = {original: 'original Open', effective: 'effective Open', effective + 4: 'effective height',
              effective + 8: 'effective fps'}
    for off in range(0, len(text) - 4, 2):
        half = struct.unpack_from('<H', text, off)[0]
        if half & 0xf800 != 0x4800 and half != 0xf8df:
            continue
        ins = next(driver.cs.disasm(text[off:off + 4], base + off, count=1), None)
        if ins is None or ins.mnemonic not in ('ldr', 'ldr.w') or '[pc, #' not in ins.op_str:
            continue
        try:
            literal = driver.literal(ins)
            pointer = struct.unpack('<I', driver.read(literal, 4))[0]
            if pointer not in wanted:
                continue
            graph = context.graph(ins.address)
            if graph.nodes[ins.address].bytes != ins.bytes:
                continue
            result.append(dict(site=driver.site(ins), pointer_va=pointer, role=wanted[pointer],
                               function_entry=graph.start, function_end=graph.end,
                               graph_closed_within_range=not graph.issues))
        except ValueError:
            continue
    return result


def analyze_semantics(driver, opens, touches):
    result = dict(schema='c10-bounded-semantic-evidence-v1', patchable=False, complete_functional_proof=False,
                  open=[], touch=[], geometry_pointer_xrefs=[], blockers=[
                      'outside/indirect entries and interprocedural contracts are not fully proved',
                      'downstream geometry protocol meanings need independent functional checks',
                      'AA channel meaning, full ABI/alias liveness and native generation remain incomplete'])
    try:
        context = Context(driver)
    except ValueError as error:
        result['unsupported'] = str(error)
        return result
    for op in opens:
        try:
            graph = context.graph(op['hook']['va'])
            hook, check, failure = op['hook']['va'], op['validation_va'], op['malformed_branch_va']
            result['open'].append(dict(graph=graph.summary((hook, check, failure)),
                length_check_dominates_hook=graph.dominates(check, hook) if not graph.issues else None,
                failure_path_can_reach_hook=hook in graph.reachable_from(failure) if not graph.issues else None,
                hook_predecessors=[graph.site(v) for v in sorted(graph.predecessors[hook])],
                preprocessing=preprocessing(context, graph, hook),
                displaced=instruction_effects(graph, hook),
                scratch_registers=dead_before_read(graph, op['hook']['return_va'])))
            result['geometry_pointer_xrefs'].extend(geometry_xrefs(context, op['original_open_va'], op['effective_open_va']))
        except ValueError as error:
            result['open'].append(dict(unsupported=str(error)))
    for touch in touches:
        try:
            graph = context.graph(touch['hook']['va'])
            result['touch'].append(dict(graph=graph.summary((touch['hook']['va'],)),
                routing=channel_routes(graph, touch), displaced=instruction_effects(graph, touch['hook']['va'])))
        except ValueError as error:
            result['touch'].append(dict(unsupported=str(error)))
    from generic_geometry import geometry_consumers
    result['geometry_consumers'] = geometry_consumers(context, result['geometry_pointer_xrefs'])
    return result
