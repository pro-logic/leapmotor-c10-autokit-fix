"""Source-generated admission/header/vtable fixtures and mutation refusals."""
import struct
import unittest

from driver_layout import assemble
from generic_admission import callback_readers, header_contract, state_writers, virtual_tables
from generic_analysis import Driver
from generic_flow import ThumbGraph
from generic_semantics import Context
from tests.test_generic_flow import indexed_fixture


HEADER = '''ldr r3,[r0]
ldr r2,plain
cmp r3,r2
beq valid
add.w r2,r2,#0x110011
cmp r3,r2
bne invalid
valid:
ldr r3,[r0,#8]
mvns r2,r3
ldr r3,[r0,#0xc]
subs r3,r3,r2
rsbs r0,r3,#0
adcs r0,r3
bx lr
invalid:
movs r0,#0
bx lr
.align 2
plain: .word 0x55aa55aa
'''


def admission_fixture(base=0x430000, header_change=None, callback_change=None):
    data = indexed_fixture(base)
    callback = f'''push {{r4,r5,lr}}
mov r4,r0
add.w r5,r4,#0x38
ldr r1,[r4,#0x1c]
mov r0,r5
bl {base + 0x300}
cbz r0,done
ldr r3,[r4,#0x5c]
cbnz r3,done
ldr r3,[r4]
mov r0,r4
mov r1,r5
ldr r3,[r3,#0x18]
blx r3
done: pop {{r4,r5,pc}}
'''
    if callback_change:
        callback = callback.replace(*callback_change, 1)
    reader = f'''push {{r4,lr}}
mov r4,r0
bl {base + 0x700}
pop {{r4,pc}}
'''
    header = HEADER.replace(*header_change, 1) if header_change else HEADER
    for offset, code in ((0x100, assemble(callback, base + 0x100)),
                         (0x300, assemble(reader, base + 0x300)),
                         (0x700, assemble(header, base + 0x700))):
        data[offset:offset + len(code)] = code
    data[0x900:0x902] = assemble('bx lr', base + 0x900)
    struct.pack_into('<II', data, 0xc00, 0, base + 0xc20)
    data[0xc20:0xc2a] = b'8CTest_fd\0'
    struct.pack_into('<9I', data, 0xd00, 0, base + 0xc00, *([base + 0x901] * 7))
    return data


class AdmissionTests(unittest.TestCase):
    def test_relocated_vtable_callback_and_header_are_derived(self):
        for base in (0x10000, 0x430000):
            d = Driver(bytes(admission_fixture(base)))
            tables = virtual_tables(d, base + 0x900)
            # Each synthetic slot names the same dummy function, so all seven
            # vtable member positions are candidates; only slot24 has a matching
            # checked callback grammar. No first-match selection is made.
            self.assertEqual({t['slot_offset'] for t in tables}, set(range(0, 28, 4)))
            readers = callback_readers(Context(d), tables, 0x55bb55bb)
            self.assertEqual(len(readers), 1)
            callback = readers[0]
            self.assertEqual(callback['reader_entry'], base + 0x300)
            self.assertEqual(callback['vtable_slot'], 24)
            header = callback['header_validation_calls'][0]['contract']
            self.assertEqual(header['function_entry'], base + 0x700)
            self.assertEqual(header['plain_marker'], 0x55aa55aa)
            self.assertEqual(header['encrypted_marker'], 0x55bb55bb)
            self.assertFalse(header['crypto_readiness_checked'])
            self.assertFalse(header['generation_allowed'])

    def test_marker_inverse_leaf_mutations_and_crypto_mismatch_refuse(self):
        for change in (('mvns r2,r3', 'mov r2,r3'), ('ldr r3,[r0,#0xc]', 'ldr r3,[r0,#4]'),
                       ('bne invalid', 'beq invalid'), ('rsbs r0,r3,#0', 'rsbs r0,r3,#1'),
                       ('#0x110011', '#0x220022')):
            with self.subTest(change=change):
                d = Driver(bytes(admission_fixture(header_change=change)))
                self.assertIsNone(header_contract(d, 0x430700, 0x55bb55bb))
        d = Driver(bytes(admission_fixture()))
        self.assertIsNone(header_contract(d, 0x430700, 0x12345678))

    def test_bad_rtti_members_and_virtual_argument_or_reader_gate_refuse(self):
        for offset, value in ((0xd04, 0x99999999), (0xc04, 0x433020), (0xd08, 0x430900)):
            data = admission_fixture()
            struct.pack_into('<I', data, offset, value)
            with self.subTest(offset=offset):
                self.assertEqual(virtual_tables(Driver(bytes(data)), 0x430900), [])
        for change in (('mov r1,r5', 'mov r1,r4'), ('cbz r0,done', 'cbnz r0,done'),
                       ('ldr r3,[r3,#0x18]', 'ldr r3,[r3,#0x20]')):
            d = Driver(bytes(admission_fixture(callback_change=change)))
            with self.subTest(change=change):
                self.assertEqual(callback_readers(Context(d), virtual_tables(d, 0x430900), 0x55bb55bb), [])

    def test_state_writer_requires_positive_length4_path_and_unmodified_pointer(self):
        for base in (0x10000, 0x430000):
            for change in (None, ('ble exit', 'blt exit'), ('cmp r3,#4', 'cmp r3,#8'),
                           ('ldr r3,[r6,#8]', 'ldr r3,[r6,#4]'),
                           ('bl reply', 'movs r4,#0\nbl reply')):
                source = f'''ldr r4,active
ldr r3,[r6,#8]
cmp r3,#0xf0
beq body
bx lr
body:
ldr r3,[r6,#4]
cmp r3,#4
bne exit
ldr r3,[r6,#0x10]
ldr r3,[r3]
cmp r3,#0
ble exit
bl reply
ldr r3,[r6,#0x10]
movs r0,#5
ldr r1,log_ptr
ldr r2,log_ptr
ldr r3,[r3]
str r3,[r4]
exit: bx lr
reply: bx lr
.align 2
active: .word {base + 0x3020}
log_ptr: .word {base + 0xc20}
'''
                if change:
                    source = source.replace(*change, 1)
                data = admission_fixture(base)
                code = assemble(source, base + 0x100)
                data[0x100:0x100 + len(code)] = code
                graph = ThumbGraph(Driver(bytes(data)), base + 0x100, base + 0x300)
                findings = state_writers(graph, base + 0x3020)
                with self.subTest(base=base, change=change):
                    self.assertEqual(len(findings), int(change is None))


if __name__ == '__main__':
    unittest.main()
