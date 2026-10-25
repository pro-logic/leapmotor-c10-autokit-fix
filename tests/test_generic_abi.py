"""Source-only relocated hook transfers, index-tail edits and unwind recovery."""
import copy
import struct
import unittest
from unittest.mock import patch

from driver_layout import assemble
from generic_analysis import Driver
from generic_abi import (branch_contract, compact0_recipe, encode_prel31,
                         direct_entry_audit, hook_transfer_contract, observer_frame_contract,
                         prel31_target, recover_compact0,
                         unwind_index, unwind_lookup, unwind_tail_extension,
                         validate_stack_separation, verify_unwind_tail_extension)
from generic_flow import ThumbGraph
from tests.test_generic_flow import indexed_fixture


def tail_fixture(base=0x10000):
    data = indexed_fixture(base)
    struct.pack_into('<H', data, 44, 3)
    struct.pack_into('<8I', data, 116, 0x70000001, 0xa00, base + 0xa00, base + 0xa00, 24, 24, 4, 4)
    struct.pack_into('<II', data, 52 + 16, 0xa1c, 0xa1c)
    struct.pack_into('<I', data, 0x1300 + 40 + 20, 0x800)
    return bytes(data)


def append_fixture(source, proposal):
    """Independent minimal table/RX materializer; no vendor fixture or export."""
    d = Driver(source)
    cut, gap = proposal['insertion_file_offset'], 0x1000
    changed = bytearray(source[:cut] + bytes(gap) + source[cut:])
    pad = proposal['original_padding_edit']
    changed[pad['file_offset']:cut] = bytes.fromhex(pad['replacement'])
    prefix = bytes.fromhex(proposal['insertion_prefix_bytes'])
    changed[cut:cut + len(prefix)] = prefix
    for i, segment in enumerate(d.elf.iter_segments()):
        p = list(struct.unpack_from('<8I', source, 52 + 32 * i))
        if segment['p_type'] == 'PT_LOAD' and segment['p_flags'] == 5:
            p[4] += 0x300
            p[5] += 0x300
        if segment['p_type'] == 'PT_ARM_EXIDX':
            p[4] = p[5] = proposal['new_index_bytes']
        if p[1] >= cut:
            p[1] += gap
        struct.pack_into('<8I', changed, 52 + 32 * i, *p)
    table = d.elf['e_shoff'] + gap
    struct.pack_into('<I', changed, 32, table)
    for i, section in enumerate(d.elf.iter_sections()):
        s = list(struct.unpack_from('<10I', source, d.elf['e_shoff'] + 40 * i))
        if s[4] >= cut:
            s[4] += gap
        if section.name == '.ARM.exidx':
            s[5] = proposal['new_index_bytes']
        if section.name == '.eh_frame' and proposal['empty_eh_frame_section']:
            s[5] = 0
        struct.pack_into('<10I', changed, table + 40 * i, *s)
    return bytes(changed)


def empty_eh_fixture(base=0x10000):
    data = bytearray(tail_fixture(base))
    names = b'\0.text\0.data\0.shstrtab\0.ARM.exidx\0.eh_frame\0.eh_frame_hdr\0'
    data[0x1200:0x1200 + len(names)] = names
    struct.pack_into('<H', data, 48, 6)
    struct.pack_into('<I', data, 0x1300 + 3 * 40 + 20, len(names))
    struct.pack_into('<10I', data, 0x1300 + 5 * 40, names.index(b'.eh_frame'), 1,
                     2, base + 0xa18, 0xa18, 4, 0, 0, 4, 0)
    return bytes(data)


class UnwindTests(unittest.TestCase):
    def test_empty_eh_terminator_route_is_explicit_preserves_bytes_and_avoids_overlap(self):
        for base in (0x10000, 0x430000):
            source = empty_eh_fixture(base)
            original = Driver(source)
            entries = [(base + 0xa18, 1), (base + 0xb1c, 0x8003aab0), (base + 0xc1c, 1)]
            with self.assertRaisesRegex(ValueError, 'overlaps'):
                unwind_tail_extension(original, entries)
            proposal = unwind_tail_extension(original, entries, empty_eh_frame=True)
            changed = Driver(append_fixture(source, proposal))
            self.assertEqual(len(bytes.fromhex(proposal['insertion_prefix_bytes'])), 20)
            self.assertEqual(proposal['original_padding_edit']['replacement'], '00000000')
            self.assertEqual(proposal['empty_eh_frame_section']['replacement_size'], 0)
            self.assertEqual(changed.read(base + 0xa18, 4), original.read(base + 0xa18, 4))
            self.assertEqual(changed.elf.get_section_by_name('.eh_frame')['sh_addr'], base + 0xa18)
            self.assertEqual(changed.elf.get_section_by_name('.eh_frame')['sh_size'], 0)
            self.assertEqual(verify_unwind_tail_extension(original, changed, proposal)['appended_entries'], 3)
            damaged = bytearray(append_fixture(source, proposal))
            struct.pack_into('<I', damaged, changed.elf['e_shoff'] + 5 * 40 + 20, 4)
            with self.assertRaisesRegex(ValueError, 'metadata changed'):
                verify_unwind_tail_extension(original, Driver(bytes(damaged)), proposal)
            with self.assertRaises(ValueError):
                unwind_tail_extension(original, entries[1:], empty_eh_frame=True)
        source = bytearray(empty_eh_fixture())
        for off, value in ((0xa18, 1), (0x1300 + 5 * 40 + 20, 3)):
            damaged = bytearray(source)
            struct.pack_into('<I', damaged, off, value)
            with self.subTest(off=off), self.assertRaises(ValueError):
                unwind_tail_extension(Driver(bytes(damaged)), [(0x10a18, 1), (0x10b1c, 0x8003aab0), (0x10c1c, 1)], True)
        # Even an empty named .eh_frame_hdr is an unsupported size contract.
        struct.pack_into('<H', source, 48, 7)
        names = source[0x1200:0x1250]
        struct.pack_into('<10I', source, 0x1300 + 6 * 40, names.index(b'.eh_frame_hdr'), 1,
                         2, 0x10a1c, 0xa1c, 0, 0, 0, 4, 0)
        with self.assertRaisesRegex(ValueError, 'EH-frame header'):
            unwind_tail_extension(Driver(bytes(source)), [(0x10a18, 1), (0x10b1c, 0x8003aab0), (0x10c1c, 1)], True)

    def test_prel31_signed_arithmetic_and_range(self):
        for target, place in ((0x10100, 0x10a00), (0x430100, 0x430a00), (0x80000000, 0x80000004)):
            self.assertEqual(prel31_target(encode_prel31(target, place), place), target)
        for target, place in ((0, 0x40000001), (0x80000000, 0x40000000), (-1, 0), (True, 0)):
            with self.subTest(target=target), self.assertRaises(ValueError):
                encode_prel31(target, place)
        with self.assertRaises(ValueError):
            prel31_target(0x80000000, 0x10000)

    def test_compact_observer_and_original_helper_recover_two_frames(self):
        stub_sp, helper_sp = 0x5000, 0x5020
        original_sp = helper_sp + 328
        helper_return, caller_return = 0x184bd, 0x1d30b
        words = {stub_sp + 16: 0x11111111, stub_sp + 20: 0x22222222,
                 stub_sp + 24: 0x33333333, stub_sp + 28: helper_return}
        for index, register in enumerate(range(4, 10)):
            words[helper_sp + 300 + index * 4] = 0x12340000 + register
        words[helper_sp + 324] = caller_return
        self.assertEqual(compact0_recipe(0x8003aab0)['stack_bytes'], 32)
        self.assertEqual(compact0_recipe(0x800a3fad)['stack_bytes'], 328)
        first = recover_compact0(0x8003aab0, stub_sp, 0xdeadbeef, words)
        self.assertEqual((first['sp'], first['pc']), (helper_sp, helper_return))
        second = recover_compact0(0x800a3fad, first['sp'], first['pc'], words)
        self.assertEqual((second['sp'], second['pc']), (original_sp, caller_return))
        self.assertEqual(second['restored_registers']['9'], 0x12340009)
        for word in (1, 0x8103aab0, 0x808000b0, 0x80b100b0, 0x80c900b0):
            with self.subTest(word=word), self.assertRaises(ValueError):
                compact0_recipe(word)
        with self.assertRaisesRegex(ValueError, 'missing saved'):
            recover_compact0(0x8003aab0, stub_sp, 0, {})

    def test_relocated_tail_append_preserves_old_records_and_new_lookup(self):
        for base in (0x10000, 0x430000):
            source = tail_fixture(base)
            original = Driver(source)
            start, end = base + 0xb1c, base + 0xc1c
            proposal = unwind_tail_extension(original, [(start, 0x8003aab0), (end, 1)])
            changed = Driver(append_fixture(source, proposal))
            check = verify_unwind_tail_extension(original, changed, proposal)
            with self.subTest(base=base):
                self.assertEqual(check['original_entries'], 3)
                self.assertEqual(check['appended_entries'], 2)
                self.assertEqual(proposal['minimum_code_start_va'], base + 0xa28)
                self.assertEqual(len(bytes.fromhex(proposal['insertion_prefix_bytes'])), 12)
                index = unwind_index(changed)
                self.assertEqual(unwind_lookup(index, start + 4)['descriptor_word'], 0x8003aab0)
                self.assertEqual(unwind_lookup(index, end | 1, return_address=True)['descriptor_word'], 0x8003aab0)
                self.assertEqual(unwind_lookup(index, end)['kind'], 'cantunwind')
                self.assertEqual(unwind_lookup(index, base + 0xa00)['kind'], 'cantunwind')
                self.assertFalse(check['generation_allowed'])

    def test_ambiguous_moved_overlap_nonzero_padding_and_wrong_entries_refuse(self):
        source = tail_fixture()
        for off, value in ((0xa18, 1), (116 + 16, 16), (0x1300 + 40 + 20, 0x91c),
                           (0xa08, encode_prel31(0x10100, 0x10a08))):
            changed = bytearray(source)
            struct.pack_into('<I', changed, off, value)
            with self.subTest(off=off), self.assertRaises(ValueError):
                unwind_tail_extension(Driver(bytes(changed)), [(0x10b1c, 0x8003aab0), (0x10c1c, 1)])
        for entries in ([(0x10b1c, 0x8003aab0)], [(0x10b1c, 1), (0x10b1c, 1)],
                        [(0x10a20, 0x8003aab0), (0x10c1c, 1)], [(0x10b1d, 0x8003aab0), (0x10c1c, 1)]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                unwind_tail_extension(Driver(source), entries)
        original = Driver(source)
        proposal = unwind_tail_extension(original, [(0x10b1c, 0x8003aab0), (0x10c1c, 1)])
        changed = bytearray(append_fixture(source, proposal))
        changed[0xa00 + 4] ^= 1
        with self.assertRaises(ValueError):
            verify_unwind_tail_extension(original, Driver(bytes(changed)), proposal)
        edited = copy.deepcopy(proposal)
        edited['generation_allowed'] = True
        with self.assertRaisesRegex(ValueError, 'Edited/stale'):
            verify_unwind_tail_extension(original, Driver(append_fixture(source, proposal)), edited)


class TransferTests(unittest.TestCase):
    def test_observer_frame_recipe_matches_call_and_balanced_return(self):
        source = '''push.w {r4,r5,r6,lr}
sub sp,#16
ldr.w ip,[sp,#32]
str.w ip,[sp]
ldr.w ip,[sp,#36]
str.w ip,[sp,#4]
ldr.w ip,[sp,#40]
str.w ip,[sp,#8]
blx TARGET
push.w {r0,r1,r2,r3,ip}
mrs r0,apsr
push {r0}
nop
pop {r0}
msr apsr_nzcvq,r0
pop.w {r0,r1,r2,r3,ip}
add sp,#16
pop.w {r4,r5,r6,lr}
bx lr
'''
        for base in (0x10000, 0x430000):
            for change in (None, ('sub sp,#16', 'sub sp,#20'),
                           ('ldr.w ip,[sp,#36]', 'ldr.w ip,[sp,#32]'),
                           ('nop', 'vmov s0,r0'), ('nop', 'msr cpsr_c,r0'), ('nop', 'blx TARGET')):
                data = bytearray(tail_fixture(base))
                text = source.replace(*change, 1) if change else source
                code = assemble(text.replace('TARGET', hex(base + 0x900)), base + 0x100)
                data[0x100:0x100 + len(code)] = code
                struct.pack_into('<I', data, 0xa04, 0x8003aab0)
                with patch('generic_flow.plt_import', return_value=dict(symbol='AES_cfb128_encrypt',
                           plt_va=base + 0x900, got_va=base + 0x3040)):
                    with self.subTest(base=base, change=change):
                        if change:
                            with self.assertRaises(ValueError):
                                observer_frame_contract(Driver(bytes(data)), base + 0x100, base + 0x100 + len(code))
                        else:
                            result = observer_frame_contract(Driver(bytes(data)), base + 0x100, base + 0x100 + len(code))
                            self.assertEqual(result['peak_scratch_bytes'], 56)
                            self.assertTrue(result['synchronous_unwind_registered'])
                            self.assertEqual(result['synchronous_unwind_recipe']['word'], 0x8003aab0)

    def test_all_alignment_audit_retains_thumb_and_arm_targets(self):
        for base in (0x10000, 0x430000):
            data = bytearray(tail_fixture(base))
            data[0x100:0x104] = assemble(f'b.w {base + 0x112:#x}', base + 0x100)
            target, source = base + 0xa1c, base + 0x200
            arm_b = 0xea000000 | (((target - source - 8) >> 2) & 0xffffff)
            struct.pack_into('<I', data, 0x200, arm_b)
            report = direct_entry_audit(Driver(bytes(data)), [('hook interior', base + 0x112, 2),
                                                             ('new RX', base + 0xa1c, 0x100)])
            self.assertTrue(any(h['source_va'] == base + 0x100 and h['target_va'] == base + 0x112
                                and h['mode'] == 'Thumb' for h in report['hits']))
            self.assertTrue(any(h['source_va'] == base + 0x200 and h['target_va'] == base + 0xa1c
                                and h['mode'] == 'ARM' for h in report['hits']))
            self.assertFalse(report['generation_allowed'])

    def test_branch_target_link_reach_and_predicate_are_checked(self):
        for source, target in ((0x10108, 0x10b1c), (0x430108, 0x430b1c)):
            for link in (False, True):
                encoded = assemble(f'{"bl" if link else "b.w"} {target:#x}', source)
                self.assertTrue(branch_contract(source, target, encoded, link)['flags_unchanged'])
                with self.assertRaises(ValueError):
                    branch_contract(source, target + 2, encoded, link)
                with self.assertRaises(ValueError):
                    branch_contract(source, target, encoded, not link)
        for source, target in ((0x10000, 0x2000000), (0x10001, 0x11000)):
            with self.assertRaises(ValueError):
                branch_contract(source, target, assemble('nop\nnop', source))

    def test_hook_replay_boundary_and_pc_independence_are_checked(self):
        source = bytearray(tail_fixture())
        code = assemble('ldr.w lr,[r6,#0x10]\nbx lr', 0x10100)
        source[0x100:0x100 + len(code)] = code
        original = Driver(bytes(source))
        graph = ThumbGraph(original, 0x10100, 0x10300)
        site = original.site(graph.nodes[0x10100])
        changed = bytearray(source)
        changed[0x100:0x104] = assemble('b.w 0x10800', 0x10100)
        result = hook_transfer_contract(original, Driver(bytes(changed)), site, 0x10800)
        self.assertTrue(result['displaced']['pc_independent'])
        for instruction in ('ldr.w r0,[pc,#0]', 'cmp.w r0,#1'):
            other = bytearray(source)
            other[0x100:0x104] = assemble(instruction, 0x10100)
            d = Driver(bytes(other));g = ThumbGraph(d, 0x10100, 0x10300)
            with self.subTest(instruction=instruction), self.assertRaises(ValueError):
                hook_transfer_contract(d, Driver(bytes(changed)), d.site(g.nodes[0x10100]), 0x10800)
        other = bytearray(source)
        code = assemble('cmp r0,#0\nit eq\nldreq.w lr,[r6,#0x10]\nbx lr', 0x10100)
        other[0x100:0x100 + len(code)] = code
        d = Driver(bytes(other));g = ThumbGraph(d, 0x10100, 0x10300)
        with self.assertRaisesRegex(ValueError, 'IT block'):
            hook_transfer_contract(d, Driver(bytes(changed)), d.site(g.nodes[0x10104]), 0x10800)

    def test_scratch_aliases_are_not_silently_treated_as_safe(self):
        self.assertEqual(validate_stack_separation(0x10000, 56,
            [('descriptor', 0x20000, 32), ('payload', 0x30000, 28)])['scratch_start'], 0xffc8)
        for start in (0xffc8, 0xfffc, 0xffc0):
            with self.subTest(start=start), self.assertRaisesRegex(ValueError, 'aliases'):
                validate_stack_separation(0x10000, 56, [('payload', start, 16)])


if __name__ == '__main__':
    unittest.main()
