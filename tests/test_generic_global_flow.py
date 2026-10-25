"""Relocated all-LOAD reference scans, edge boundaries and refusal budgets."""
import struct
import unittest

from driver_layout import assemble
from generic_analysis import Driver
from generic_global_flow import (absolute_pointer_inventory, address_constructor_inventory,
                                 static_entry_inventory)
from tests.test_generic_abi import tail_fixture


class GlobalEntryTests(unittest.TestCase):
    def test_unaligned_load_pointers_and_readonly_runs_are_retained(self):
        for base in (0x10000, 0x430000):
            data = bytearray(tail_fixture(base))
            struct.pack_into('<I', data, 0x1001, (base + 0x112) | 1)
            struct.pack_into('<II', data, 0x980, (base + 0x110) | 1, (base + 0x120) | 1)
            report = absolute_pointer_inventory(Driver(bytes(data)), [('interior', base + 0x112, 2)])
            self.assertTrue(any(h['source_va'] == base + 0x3001 and h['target_va'] == base + 0x112
                                and h['thumb'] for h in report['hits']))
            self.assertTrue(any(r['source_va'] <= base + 0x980 and
                                base + 0x984 < r['source_va'] + 4 * r['entries']
                                for r in report['readonly_code_pointer_runs']))
            self.assertFalse(report['generation_allowed'])

    def test_branches_and_constructors_outside_text_still_count(self):
        for base in (0x10000, 0x430000):
            data = bytearray(tail_fixture(base))
            target = base + 0xa40
            data[0x940:0x944] = assemble(f'b.w {target:#x}', base + 0x940)
            body = assemble(f'movw r0,#{target & 65535}\nmovt r0,#{target >> 16}', base + 0x950)
            data[0x950:0x950 + len(body)] = body
            report = static_entry_inventory(Driver(bytes(data)), [('extension', base + 0xa1c, 0x100)])
            self.assertTrue(any(h['source_va'] == base + 0x940 for h in report['direct']['hits']))
            self.assertTrue(any(h['source_va'] == base + 0x950 and h['target_va'] == target
                                for h in report['constructors']['hits']))
            self.assertFalse(report['complete_indirect_target_proof'])
            self.assertFalse(report['generation_allowed'])

    def test_final_thumb_halfword_and_arm_pc_constructor_are_scanned(self):
        for base in (0x10000, 0x430000):
            data = bytearray(tail_fixture(base))
            struct.pack_into('<H', data, 0xa1a, 0xa000)  # narrow ADR r0, #0 at last RX halfword
            struct.pack_into('<I', data, 0x940, 0xe28f0000)  # ARM ADD r0, PC, #0
            report = address_constructor_inventory(Driver(bytes(data)),
                [('tail', base + 0xa1c, 4), ('arm', base + 0x948, 4)])
            self.assertTrue(any(h['source_va'] == base + 0xa1a and h['target_va'] == base + 0xa1c
                                for h in report['hits']))
            self.assertTrue(any(h['source_va'] == base + 0x940 and h['mode'] == 'ARM'
                                and h['target_va'] == base + 0x948 for h in report['hits']))

    def test_movt_low_half_is_never_invented(self):
        data = bytearray(tail_fixture())
        body = assemble('movt r0,#8\nbx lr', 0x10940)
        data[0x940:0x940 + len(body)] = body
        report = address_constructor_inventory(Driver(bytes(data)), [('extension', 0x80000, 0x100)])
        self.assertTrue(any(p['source_va'] == 0x10940 for p in report['partial_movt_constructors']))
        self.assertFalse(any(h['source_va'] == 0x10940 for h in report['hits']))

    def test_conditional_arm_calls_and_address_constructors_are_retained(self):
        for base in (0x10000, 0x430000):
            data = bytearray(tail_fixture(base))
            target = base + 0xa40
            # BLNE, MOVWNE/MOVTNE and ADDNE PC; conditional execution is not
            # grounds to omit any potential reference from this inventory.
            displacement = (target - (base + 0x940) - 8) >> 2
            struct.pack_into('<I', data, 0x940, 0x1b000000 | (displacement & 0xffffff))
            for offset, half, upper in ((0x950, target & 65535, False), (0x954, target >> 16, True)):
                word = (0x13400000 if upper else 0x13000000) | ((half & 0xf000) << 4) | (half & 0xfff)
                struct.pack_into('<I', data, offset, word)
            struct.pack_into('<I', data, 0x960, 0x128f0000)
            report = static_entry_inventory(Driver(bytes(data)),
                [('extension', base + 0xa1c, 0x100), ('pc-constant', base + 0x968, 4)])
            self.assertTrue(any(h['source_va'] == base + 0x940 and h['mode'] == 'ARM'
                                for h in report['direct']['hits']))
            self.assertTrue(any(h['source_va'] == base + 0x950 and h['target_va'] == target
                                for h in report['constructors']['hits']))
            self.assertTrue(any(h['source_va'] == base + 0x960 and h['mode'] == 'ARM'
                                for h in report['constructors']['hits']))

    def test_bad_spans_and_exhausted_budgets_refuse(self):
        driver = Driver(tail_fixture())
        for spans in ([], [('x', True, 2)], [('x', 0xffffffff, 2)],
                      [('x', 0x10000, 0)], [('x', 0x10000, 2), ('x', 0x20000, 2)]):
            with self.subTest(spans=spans), self.assertRaises(ValueError):
                static_entry_inventory(driver, spans)
        for budget in (True, 0, 100001):
            with self.assertRaises(ValueError):
                absolute_pointer_inventory(driver, [('x', 0x10100, 2)], budget)
        data = bytearray(tail_fixture())
        struct.pack_into('<II', data, 0x980, 0x10101, 0x10111)
        with self.assertRaisesRegex(ValueError, 'budget'):
            absolute_pointer_inventory(Driver(bytes(data)), [('x', 0x10100, 2)], 1)


if __name__ == '__main__':
    unittest.main()
