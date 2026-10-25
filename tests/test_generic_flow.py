"""Relocated CFG fixtures and bypass/indirect/table/stack adversaries."""
import struct
import unittest

from driver_layout import assemble
from generic_analysis import Driver, analyze_driver, touch_candidates
from generic_flow import ThumbGraph, enclosing_range
from generic_semantics import channel_routes
from tests.test_generic import native_fixture


def indexed_fixture(base=0x10000, entry=0x100, next_entry=0x300):
    data = bytearray(native_fixture(base))
    names = b'\0.text\0.data\0.shstrtab\0.ARM.exidx\0'
    data[0x1200:0x1200 + len(names)] = names
    struct.pack_into('<H', data, 48, 5)
    struct.pack_into('<I', data, 0x1300 + 3 * 40 + 20, len(names))
    struct.pack_into('<10I', data, 0x1300 + 4 * 40, names.index(b'.ARM.exidx'), 0x70000001,
                     2, base + 0xa00, 0xa00, 24, 1, 0, 4, 8)
    for i, offset in enumerate((entry, next_entry, 0x800)):
        struct.pack_into('<II', data, 0xa00 + i * 8, (offset - 0xa00 - i * 8) & 0x7fffffff, 1)
    return data


def graph_fixture(source, base=0x10000):
    data = indexed_fixture(base)
    code = assemble(source, base + 0x100)
    data[0x100:0x100 + len(code)] = code
    return ThumbGraph(Driver(bytes(data)), base + 0x100, base + 0x300)


class FlowTests(unittest.TestCase):
    def test_relocated_open_graph_checks_local_guard_and_register_effects(self):
        for base in (0x10000, 0x430000):
            with self.subTest(base=base):
                report = analyze_driver(bytes(indexed_fixture(base)))
                op = report['semantic_evidence']['open'][0]
                self.assertTrue(op['graph']['closed_within_range'])
                self.assertTrue(op['length_check_dominates_hook'])
                self.assertFalse(op['failure_path_can_reach_hook'])
                self.assertEqual(op['scratch_registers']['dead'], ['r0', 'r1', 'r2', 'r3'])
                self.assertEqual(op['displaced']['reads'], ['r6'])
                self.assertEqual(op['displaced']['writes'], ['lr'])
                self.assertFalse(report['patchable'])

    def test_local_open_signature_does_not_prove_no_length_check_bypass(self):
        data = indexed_fixture(entry=0xf0)
        struct.pack_into('<III', data, 0x1300 + 40 + 12, 0x100e0, 0xe0, 0xf20)
        validation = ','.join(str(v) for v in data[0x100:0x108])
        code = assemble('cmp r7,#0\nbeq.w hook\nb.w validate\n.space 6\nvalidate:\n.byte '
                        + validation + '\nhook: nop', 0x100f0)
        data[0xf0:0x100] = code[:16]
        report = analyze_driver(bytes(data))
        self.assertEqual(len(report['open_candidates']), 1)
        self.assertTrue(report['semantic_evidence']['open'][0]['graph']['closed_within_range'])
        self.assertFalse(report['semantic_evidence']['open'][0]['length_check_dominates_hook'])
        self.assertFalse(report['patchable'])

    def test_literal_pool_is_not_decoded_as_fallthrough(self):
        graph = graph_fixture('ldr r0, pool\nb done\n.align 2\npool: .word 0xe7fee7fe\ndone: bx lr')
        self.assertFalse(graph.issues)
        self.assertEqual(len(graph.nodes), 3)

    def test_outside_and_overlapping_edges_are_explicit(self):
        for source, reason in (('b.w 0x10400', 'leaves'),
                               ('bne 0x10104\nmov.w r0,#1\nbx lr', 'overlapping')):
            graph = graph_fixture(source)
            self.assertTrue(any(reason in i['reason'] for i in graph.issues))
            self.assertFalse(graph.summary()['closed_within_range'])

    def test_indirect_jump_is_not_assumed_to_be_return(self):
        for source in ('bx r0', 'ldm.w r1!,{r0,pc}'):
            with self.subTest(source=source):
                graph = graph_fixture(source)
                self.assertTrue(graph.issues)
        self.assertFalse(graph_fixture('bx lr').issues)
        self.assertFalse(graph_fixture('pop {r4,pc}').issues)

    def test_it_block_interior_entry_is_rejected(self):
        graph = graph_fixture('cmp r0,#0\nbeq bypass\nit eq\nmoveq r1,#1\nbx lr\nbypass: b.w 0x10106')
        self.assertTrue(any('IT block interior' in i['reason'] for i in graph.issues))

    def test_bounded_table_traversal_and_data_targets(self):
        source = '''cmp r0,#1
bhi fallback
tbb [pc,r0]
.byte 2,4
nop
movs r1,#3
bx lr
movs r1,#5
bx lr
fallback: bx lr
'''
        graph = graph_fixture(source)
        self.assertFalse(graph.issues)
        self.assertEqual(graph.tables[0]['entries'], 2)
        self.assertEqual(graph.tables[0]['targets'], [0x1010c, 0x10110])
        halfwords = source.replace('tbb [pc,r0]\n.byte 2,4\nnop', 'tbh [pc,r0,lsl #1]\n.hword 2,4')
        graph = graph_fixture(halfwords)
        self.assertFalse(graph.issues)
        self.assertEqual(graph.tables[0]['width'], 2)
        self.assertEqual(graph.tables[0]['targets'], [0x1010c, 0x10110])
        for changed in (source.replace('.byte 2,4', '.byte 0,4'), source.replace('cmp r0,#1', 'movs r0,#1')):
            with self.subTest(source=changed):
                self.assertTrue(graph_fixture(changed).issues)

    def test_table_guard_bypass_is_not_a_closed_graph(self):
        graph = graph_fixture('''cmp r7,#0
beq tablebranch
cmp r0,#1
bhi fallback
tablebranch: tbb [pc,r0]
.byte 2,4
nop
movs r1,#3
bx lr
movs r1,#5
bx lr
fallback: bx lr
''')
        self.assertTrue(any('bound can be bypassed' in i['reason'] for i in graph.issues))

    def test_unwind_index_must_be_ordered_and_file_backed(self):
        for off, value in ((0xa08, (-0xa08 + 0x100) & 0x7fffffff),
                           (0xa00, 0x80000000), (0x1300 + 4 * 40 + 12, 0x900000),
                           (0x1300 + 4 * 40 + 16, 0xb00)):
            data = indexed_fixture()
            struct.pack_into('<I', data, off, value)
            with self.subTest(offset=off), self.assertRaises(ValueError):
                enclosing_range(Driver(bytes(data)), 0x10108)


class ChannelTests(unittest.TestCase):
    def fixture(self, stack_change=False, base=0x430000):
        data = indexed_fixture(base, entry=0x280, next_entry=0x600)
        source = f'''ldr r2, selector
ldr r3,[r2]
cmp r3,#5
beq aap
movs r2,#6
b join
aap: movs r2,#9
b join
join: cmp.w sl,#14
str r2,[sp,#0x38]
{'sub sp,#8' if stack_change else 'nop'}
b.w {base + 0x300:#x}
.align 2
selector: .word {base + 0x3020}
'''
        code = assemble(source, base + 0x280)
        data[0x280:0x280 + len(code)] = code
        # Terminate the source-generated normalization block before its literal.
        driver = Driver(bytes(data))
        touch = touch_candidates(driver)[0]
        end = touch['normalization_end_va'] - base
        data[end:end + 2] = assemble('bx lr', base + end)
        driver = Driver(bytes(data))
        graph = ThumbGraph(driver, base + 0x280, base + 0x600)
        return graph, touch

    def test_channel_stack_position_is_derived_at_relocated_site(self):
        graph, touch = self.fixture()
        routing = channel_routes(graph, touch)
        self.assertEqual(routing['status'], 'checked bounded routing')
        self.assertEqual(routing['channel_stack_offset'], 0x38)
        self.assertEqual(routing['output_pointer_stack_offset'], 0x70)
        self.assertEqual({r['channel'] for r in routing['routes']}, {6, 9})

    def test_stack_adjustment_between_store_and_hook_is_unsupported(self):
        graph, touch = self.fixture(stack_change=True)
        routing = channel_routes(graph, touch)
        self.assertEqual(routing['status'], 'unsupported')
        self.assertTrue(routing['explicit_sp_writes_before_hook'])


if __name__ == '__main__':
    unittest.main()
