"""Relocated packet-storage/channel contracts and mutation refusals."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from driver_layout import assemble
from generic_analysis import Driver
from generic_channel import (STORAGE, analyze_channel, channel_contract, packet_storage_contract,
                             preserving_resize_helper, touch_source_contract)
from generic_flow import ThumbGraph
from tests.test_generic_flow import indexed_fixture


def storage_fixture(base=0x10000, change=None):
    imports = {name: base + 0x900 + index * 4 for index, name in
               enumerate(('munmap', 'close', 'free', 'malloc'))}
    source = []
    for label, mnemonic, operands in STORAGE:
        if label:
            source.append(label + ':')
        for name, target in imports.items():
            operands = operands.replace('$' + name, hex(target))
        source.append(mnemonic + ' ' + operands.replace('@', ''))
    code = '\n'.join(source)
    if change:
        code = code.replace(*change, 1)
    code = code.replace('it eq\nmovs ', 'it eq\nmoveq ')
    data = indexed_fixture(base)
    body = assemble(code, base + 0x100)
    data[0x100:0x100 + len(body)] = body
    wrapper = assemble(f'mov r2,r1\nldr r1,[r0,#8]\nb.w {base + 0x100:#x}', base + 0x700)
    data[0x700:0x708] = wrapper
    driver = Driver(bytes(data))
    symbols = {target: name for name, target in imports.items()}
    resolver = lambda d, target: dict(symbol=symbols[target], plt_va=target) if target in symbols else None
    with patch('generic_flow.plt_import', side_effect=resolver):
        graph = ThumbGraph(driver, base + 0x100, base + 0x300)
    context = SimpleNamespace(driver=driver, graph=lambda target: graph)
    return context, resolver


class ChannelTests(unittest.TestCase):
    def test_storage_target_is_derived_through_relocated_resize_wrapper(self):
        for base in (0x10000, 0x430000):
            context, resolver = storage_fixture(base)
            wrapper = preserving_resize_helper(context, base + 0x700)
            self.assertEqual(wrapper['storage_target'], base + 0x100)
            self.assertEqual(preserving_resize_helper(context, base + 0x700, base + 0x200)['status'], 'unsupported')
            with patch('generic_channel.plt_import', side_effect=resolver):
                storage = packet_storage_contract(context, wrapper['storage_target'])
            self.assertEqual(storage['status'], 'checked bounded native packet storage', storage)
            self.assertEqual(storage['payload_owner_bias'], 96)
            self.assertEqual(storage['nonzero_allocation_overhead'], 192)
            self.assertFalse(storage['all_input_aliases_proved'])
            self.assertFalse(storage['generation_allowed'])

    def test_storage_mutations_and_wrong_imports_refuse(self):
        for change in (('add.w r6, r2, #0xc0', 'add.w r6, r2, #0x80'),
                       ('str r3, [r4, #0x10]', 'str r3, [r4, #0xc]'),
                       ('movs r2, #0x60', 'movs r2, #0x40'),
                       ('bhs reuse', 'bhi reuse'), ('movs r6, #0', 'movs r6, #1')):
            context, resolver = storage_fixture(change=change)
            with self.subTest(change=change), patch('generic_channel.plt_import', side_effect=resolver):
                self.assertEqual(packet_storage_contract(context, 0x10100)['status'], 'unsupported')
        context, _ = storage_fixture()
        with patch('generic_channel.plt_import', return_value=dict(symbol='realloc')):
            self.assertEqual(packet_storage_contract(context, 0x10100)['status'], 'unsupported')

    def test_touch_source_guard_and_register_preservation_are_required(self):
        for base in (0x10000, 0x430000):
            for change in (None, ('bne failure', 'beq failure'), ('#0x10', '#0x14'),
                           ('nop', 'movs r4,#0')):
                source = '''ldr r3,[r6,#4]
cmp r3,#0x10
bne failure
ldr r4,[r6,#0x10]
nop
vldr s14,[r4,#8]
bx lr
failure: bx lr
'''
                if change:
                    source = source.replace(*change, 1)
                data = indexed_fixture(base)
                body = assemble(source, base + 0x100)
                data[0x100:0x100 + len(body)] = body
                graph = ThumbGraph(Driver(bytes(data)), base + 0x100, base + 0x300)
                hook = next(i for i in graph.nodes.values() if i.mnemonic == 'vldr')
                result = touch_source_contract(graph, dict(hook=dict(va=hook.address)))
                with self.subTest(base=base, change=change):
                    self.assertEqual(result['status'] == 'checked bounded touch source alias', change is None)

    def test_aap_route_requires_unique_correspondence_and_distinct_globals(self):
        link = dict(channel=17, selector_variable_va=0x9000, already_connected_selector=12,
                    aap_strcmp_va=0x1100, send_call_va=0x1200)
        route = dict(channel=17, assignment_va=0x1300,
                     selector_edges=[dict(variable_va=0xa000, value=12)])
        def check(routes):
            return channel_contract(link, dict(status='checked bounded routing', routes=routes, channel_stack_offset=0x60))
        result = check([route])
        self.assertEqual(result['channel'], 17)
        self.assertEqual(check([route, route])['status'], 'unsupported')
        for variable, value in ((0x9000, 12), (None, 12), (0xa000, 11)):
            changed = dict(route, selector_edges=[dict(variable_va=variable, value=value)])
            self.assertEqual(check([changed])['status'], 'unsupported')

    def test_unsupported_child_contracts_cannot_produce_composite_ownership_claim(self):
        native = dict(touch_candidates=[dict(hook=dict(va=0x10100))], semantic_evidence=dict(
            touch=[dict(routing={})], geometry_consumers=dict(aa_link=[{}],
                type1_response=[dict(resize_target=0x10700)])))
        context = SimpleNamespace(graph=lambda target: None)
        for role in ('channel', 'source'):
            channel = dict(status='checked AAP link/touch channel correspondence')
            source = dict(status='checked bounded touch source alias')
            (channel if role == 'channel' else source)['status'] = 'unsupported'
            with self.subTest(role=role), patch('generic_channel.Context', return_value=context), \
                 patch('generic_channel.channel_contract', return_value=channel), \
                 patch('generic_channel.touch_source_contract', return_value=source):
                result = analyze_channel(None, native)
            self.assertEqual(result['status'], 'unsupported')
            self.assertNotIn('conditional_nonalias', result)
            self.assertFalse(result['generation_allowed'])


if __name__ == '__main__':
    unittest.main()
