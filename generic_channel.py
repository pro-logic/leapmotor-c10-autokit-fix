"""Bounded AAP channel, touch source and native packet-storage contracts.

These derive code relationships, not universal protocol or all-caller ownership
claims. Allocator/mapping and callee ABI contracts remain explicit assumptions.
"""
from __future__ import annotations

from generic_analysis import matches
from generic_flow import linear, preceding, plt_import
from generic_semantics import Context


def _target(ins):
    return int(ins.op_str.rsplit('#', 1)[1], 0)


def _need(condition, message):
    if not condition:
        raise ValueError(message)


# Labels express branch relationships, not fixture addresses. This restricted
# compiler grammar covers all reached instructions and return paths in the
# native storage helper, including reuse, mapping cleanup and allocation failure.
STORAGE = [
    ('entry', 'push', '{r3, r4, r5, r6, r7, lr}'),
    ('', 'mov', 'r4, r0'), ('', 'mov', 'r7, r2'), ('', 'cbz', 'r2, @zero'),
    ('', 'add.w', 'r6, r2, #0xc0'), ('', 'b', '@size'), ('zero', 'mov', 'r6, r2'),
    ('size', 'ldr', 'r3, [r4, #0x20]'), ('', 'str', 'r1, [r4, #8]'), ('', 'cmp', 'r3, #0'),
    ('', 'blt', '@heap'), ('', 'ldr', 'r0, [r4, #0x14]'), ('', 'ldr', 'r1, [r4, #0x18]'),
    ('', 'blx', '$munmap'), ('', 'ldr', 'r0, [r4, #0x20]'), ('', 'cmp', 'r0, #0'),
    ('', 'blt', '@nomap'), ('', 'blx', '$close'), ('', 'mov.w', 'r3, #-1'),
    ('', 'str', 'r3, [r4, #0x20]'), ('nomap', 'movs', 'r3, #0'),
    ('', 'str', 'r3, [r4, #0x10]'), ('', 'str', 'r3, [r4, #0x14]'), ('', 'str', 'r3, [r4, #0x18]'),
    ('heap', 'ldr', 'r3, [r4, #0x18]'), ('', 'ldr', 'r0, [r4, #0x14]'), ('', 'cmp', 'r3, r6'),
    ('', 'bhs', '@reuse'), ('', 'cbz', 'r0, @allocate'), ('', 'blx', '$free'),
    ('allocate', 'mov', 'r0, r6'), ('', 'blx', '$malloc'), ('', 'cmp', 'r0, #0'),
    ('', 'str', 'r0, [r4, #0x14]'), ('', 'mov.w', 'r0, #0'), ('', 'it', 'eq'),
    ('', 'movs', 'r6, #0'), ('', 'str', 'r6, [r4, #0x18]'), ('', 'b', '@finish'),
    ('reuse', 'movs', 'r5, #0'), ('', 'cbnz', 'r6, @keep'), ('', 'cbz', 'r0, @clear'),
    ('', 'blx', '$free'), ('', 'str', 'r5, [r4, #0x14]'), ('clear', 'str', 'r5, [r4, #0x18]'),
    ('', 'movs', 'r0, #1'), ('', 'str', 'r5, [r4, #0x1c]'), ('', 'b', '@finish'),
    ('keep', 'mov', 'r0, r5'), ('finish', 'ldr', 'r3, [r4, #0x14]'), ('', 'cbz', 'r3, @failure'),
    ('', 'movs', 'r2, #0x60'), ('', 'str', 'r7, [r4, #4]'), ('', 'add', 'r3, r2'),
    ('', 'str', 'r2, [r4, #0x1c]'), ('', 'str', 'r3, [r4, #0x10]'), ('', 'movs', 'r0, #1'),
    ('', 'pop', '{r3, r4, r5, r6, r7, pc}'), ('failure', 'str', 'r3, [r4, #0x10]'),
    ('', 'str', 'r3, [r4, #4]'), ('', 'pop', '{r3, r4, r5, r6, r7, pc}'),
]


def packet_storage_contract(context, resize_target):
    try:
        graph = context.graph(resize_target)
        _need(graph.start == resize_target and not graph.issues, 'Unsupported packet-storage CFG')
        nodes = [graph.nodes[a] for a in sorted(graph.nodes)]
        _need(len(nodes) == len(STORAGE), 'Packet-storage instruction count differs')
        labels = {label: ins.address for (label, _, _), ins in zip(STORAGE, nodes) if label}
        imports = []
        for index, ((_, mnemonic, operands), ins) in enumerate(zip(STORAGE, nodes)):
            _need(ins.mnemonic == mnemonic, f'Unsupported storage instruction at {ins.address:#x}')
            if operands.startswith('$'):
                imported = plt_import(context.driver, _target(ins))
                _need(imported and imported['symbol'] == operands[1:], 'Packet-storage import differs')
                imports.append(dict(va=ins.address, **imported))
            else:
                expected = operands
                for label, va in labels.items():
                    expected = expected.replace('@' + label, '#' + hex(va))
                _need(ins.op_str == expected, f'Unsupported storage data flow at {ins.address:#x}')
            _need((ins.address in graph.predicated) == (index == 36), 'Unexpected storage predication')
            if index == 36:
                _need(graph.predicated[ins.address] == 1, 'Storage allocation failure IT condition differs')
        return dict(status='checked bounded native packet storage', function_entry=resize_target,
                    descriptor_owner_offset=20, descriptor_capacity_offset=24, descriptor_payload_offset=16,
                    descriptor_length_offset=4, descriptor_type_offset=8, descriptor_mapping_fd_offset=32,
                    payload_owner_bias=96, nonzero_allocation_overhead=192, allocator='malloc',
                    valid_length_range=[0, 2**32 - 1 - 192], stack_scratch_bytes=24,
                    return_paths=['new/reused owner: payload=owner+96, length=request, return1',
                                  'failed allocation: owner/capacity/payload/length zero, return0',
                                  'zero length: release owner/mapping, clear payload and length'],
                    type_preservation='descriptor[8] is assigned incoming r1', imported_calls=imports,
                    graph=graph.summary(),
                    ownership_assumptions=['initial owner/capacity/mapping fields have valid constructor/previous-storage provenance',
                        'malloc/munmap/free/close and callee-saved registers obey their native API/ABI contracts',
                        'successful malloc or mmap storage is disjoint from the active stack'],
                    all_input_aliases_proved=False, generation_allowed=False)
    except (ValueError, IndexError) as error:
        return dict(status='unsupported', reason=str(error), generation_allowed=False)


def preserving_resize_helper(context, target, storage_target=None):
    try:
        d = context.driver
        # This eight-byte tail helper has no independent unwind entry in some
        # inputs. Its exact three instructions preserve the descriptor type.
        instructions = list(d.cs.disasm(d.read(target, 8), target))
        _need(len(instructions) == 3 and matches(instructions[:2], [
            ('mov', 'r2, r1'), ('ldr', 'r1, [r0, #8]')])
            and instructions[2].mnemonic == 'b.w',
            'Unsupported type-preserving resize tail helper')
        derived_target = _target(instructions[2])
        d.offset(derived_target, 2, executable=True)
        _need(storage_target is None or derived_target == storage_target,
              'Type-preserving resize helpers use different storage targets')
        return dict(status='checked type-preserving resize helper', function_entry=target,
                    storage_target=derived_target, descriptor_register='r0', length_register='r1',
                    effect='r2=length; r1=descriptor[8]; tail-call storage; packet channel/type retained')
    except ValueError as error:
        return dict(status='unsupported', reason=str(error))


def touch_source_contract(graph, touch):
    try:
        _need(not graph.issues, 'Touch source has unsupported control flow')
        hook = touch['hook']['va']
        sources = [va for va, ins in graph.nodes.items() if ins.mnemonic == 'ldr'
                   and ins.op_str == 'r4, [r6, #0x10]' and va not in graph.predicated
                   and graph.dominates(va, hook)]
        _need(len(sources) == 1, 'Need unique dominating touch payload pointer load')
        source = sources[0]
        guard = preceding(graph, source, 3)
        _need(len(guard) == 3 and matches(guard[:2], [('ldr', 'r3, [r6, #4]'), ('cmp', 'r3, #0x10')])
              and guard[2].mnemonic in ('bne', 'bne.w'), 'Unsupported touch length/source guard')
        _need(graph.dominates(guard[1].address, hook) and hook not in graph.reachable_from(_target(guard[2])),
              'Touch length guard has a live bypass')
        between = graph.reachable_from(source) & graph.reaching(hook)
        _need(not any('r4' in {graph.cs.reg_name(r) for r in graph.nodes[a].regs_access()[1]}
                      for a in between if a != source), 'Touch source register is clobbered')
        return dict(status='checked bounded touch source alias', payload_load_va=source,
                    descriptor_register='r6', payload_register='r4', payload_pointer_offset=16,
                    validated_length=16, length_guard_va=guard[0].address, malformed_target=_target(guard[2]),
                    x_offset=4, y_offset=8, input_payload_writes_in_hook=False,
                    intermediate_calls=[c for c in graph.calls if c['va'] in between],
                    assumptions=['intermediate callees preserve r4 and input descriptor/payload ownership'],
                    all_callers_ownership_proved=False)
    except (ValueError, IndexError) as error:
        return dict(status='unsupported', reason=str(error))


def channel_contract(link, routing):
    try:
        _need(routing['status'] == 'checked bounded routing', 'Touch routing is not checked')
        channel = link['channel']
        routes = [r for r in routing['routes'] if r['channel'] == channel]
        _need(len(routes) == 1 and len(routes[0]['selector_edges']) == 1, 'AAP channel has ambiguous touch route')
        edge = routes[0]['selector_edges'][0]
        _need(edge['variable_va'] is not None and edge['variable_va'] != link['selector_variable_va'],
              'Touch selector and link-state globals are absent or conflated')
        _need(edge['value'] == link['already_connected_selector'], 'AAP enum/route correspondence differs')
        return dict(status='checked AAP link/touch channel correspondence', channel=channel,
                    selector_value=edge['value'], touch_selector_va=edge['variable_va'],
                    distinct_link_state_va=link['selector_variable_va'], touch_assignment_va=routes[0]['assignment_va'],
                    aap_string_gate_va=link['aap_strcmp_va'], link_send_call_va=link['send_call_va'],
                    channel_stack_offset=routing['channel_stack_offset'],
                    scope='native AAP string-gated link channel equals the selected native touch packet type',
                    unproved=['external IPC consumer/protocol interpretation', 'all enum writers and runtime ordering'])
    except (ValueError, KeyError, IndexError) as error:
        return dict(status='unsupported', reason=str(error))


def analyze_channel(driver, native):
    """Compose checked relationships while keeping ownership limits explicit."""
    result = dict(schema='c10-bounded-channel-storage-evidence-v1', generation_allowed=False,
                  all_source_aliases_proved=False, external_aa_protocol_proved=False)
    try:
        context = Context(driver)
        sem = native['semantic_evidence']
        _need(len(native['touch_candidates']) == len(sem['touch']) == 1
              and len(sem['geometry_consumers']['aa_link']) == len(sem['geometry_consumers']['type1_response']) == 1,
              'Need unique touch/AAP/type1 findings')
        touch = native['touch_candidates'][0]
        graph = context.graph(touch['hook']['va'])
        routing = sem['touch'][0]['routing']
        link = sem['geometry_consumers']['aa_link'][0]
        resize_target = sem['geometry_consumers']['type1_response'][0]['resize_target']
        result['channel'] = channel_contract(link, routing)
        result['touch_source'] = touch_source_contract(graph, touch)
        _need(result['channel']['status'] == 'checked AAP link/touch channel correspondence'
              and result['touch_source']['status'] == 'checked bounded touch source alias',
              'Channel correspondence or touch source contract is unsupported')
        result['response_resize'] = preserving_resize_helper(context, resize_target)
        _need(result['response_resize']['status'] == 'checked type-preserving resize helper',
              'Type1 response resize tail helper is unsupported')
        storage_target = result['response_resize']['storage_target']
        result['packet_storage'] = packet_storage_contract(context, storage_target)
        setup = preceding(graph, touch['normalization_start_va'], 3)
        _need(len(setup) == 3 and setup[0].mnemonic == 'add' and setup[0].op_str.startswith('r0, sp, #')
              and matches(setup[1:2], [('movs', 'r1, #0x20')]) and setup[2].mnemonic == 'bl',
              'Unsupported touch output-packet resize setup')
        packet_offset = int(setup[0].op_str.split('#')[1], 0)
        result['touch_resize'] = preserving_resize_helper(context, _target(setup[2]), storage_target)
        _need(result['packet_storage']['status'] == 'checked bounded native packet storage'
              and result['touch_resize']['status'] == 'checked type-preserving resize helper',
              'Native storage or touch resize contract is unsupported')
        _need(routing['channel_stack_offset'] == packet_offset + 8
              and routing['output_pointer_stack_offset'] == packet_offset + 16,
              'Touch channel/output stack offsets do not name the same packet')
        result['output_packet_stack'] = dict(status='checked local output-packet layout', packet_offset=packet_offset,
            packet_bytes=36, channel_offset=packet_offset + 8, payload_pointer_offset=packet_offset + 16,
            requested_payload_bytes=32, hook_saved_stack_interval=[-56, 0],
            local_descriptor_disjoint_from_hook_scratch=packet_offset >= 0,
            scope='local output descriptor only; incoming payload separation additionally requires checked allocator ownership')
        result['conditional_nonalias'] = dict(
            status='conditional on native packet storage and allocator ownership',
            when='incoming descriptor/payload originate from the native stream-reader constructor/storage path, with valid prior owner fields',
            conclusion='heap payload is disjoint from newly saved hook stack; local output descriptor lies above current SP',
            remaining=['recvmsg/mmap and borrowed packet paths need their own ownership contracts',
                       'all virtual/override/external callers are not proved', 'descriptor/payload aliasing cannot be excluded for arbitrary supplied pointers'])
        result['status'] = 'checked bounded channel and conditional storage relationships'
    except (ValueError, KeyError, IndexError) as error:
        result['unsupported'] = str(error)
        result['status'] = 'unsupported'
    return result
