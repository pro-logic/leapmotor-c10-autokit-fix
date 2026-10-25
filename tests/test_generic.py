"""Source-only adversarial inventory and relocated Thumb discovery fixtures."""
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from driver_layout import assemble
from firmware import crypt, sha256
from generic import analyze, main
from generic_analysis import OPEN_FORMAT, analyze_driver
from generic_inventory import REQUIRED, inventory


def archive(extra=(), overrides=None, archive_format=tarfile.USTAR_FORMAT):
    files = {name: b'vendor fixture' for name in REQUIRED}
    files.update({'etc/box_product_type': b'A15W', 'etc/software_version': b'2026.01.02.0304'})
    files.update(overrides or {})
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz', format=archive_format) as tar:
        for name, data in list(files.items()) + list(extra):
            if isinstance(data, tarfile.TarInfo):
                tar.addfile(data)
            else:
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o755
                tar.addfile(info, io.BytesIO(data))
    return crypt(buffer.getvalue(), False)


def native_fixture(base=0x10000, duplicate=False, divisor=10000.0, invalid_length=False,
                   size_reg='r2', type_reg='lr', action_reg='sl', scheduled_load=False):
    """Small source-generated ELF; addresses/section offsets differ from vendor ELF."""
    data = bytearray(0x1800)
    rw = base + 0x3000
    open_start, touch_start = base + 0x100, base + 0x300
    original, effective = rw + 0x20, rw + 0x60
    header_registers = ','.join(sorted((size_reg,type_reg),key=lambda r: 14 if r == 'lr' else int(r[1:])))
    source = f'''
ldr r3, [r6, #4]
cmp r3, #{27 if invalid_length else 28}
bne.w malformed
ldr.w lr, [r6, #0x10]
ldr r4, original_ptr
ldm.w lr!, {{r0,r1,r2,r3}}
mov r5,r4
stm r5!, {{r0,r1,r2,r3}}
ldm.w lr, {{r0,r1,r2}}
ldr.w lr, [r4]
stm.w r5, {{r0,r1,r2}}
ldr r2, effective_ptr
ldr r3, [r4,#0x10]
ldr r0, [r4,#4]
ldr r1, [r4,#8]
mov r5,r2
str r3, [r2,#0x10]
movs r3,#5
str r3,[r4,#0xc]
str r3,[r2,#0xc]
ldr r3,[r4,#0x18]
str.w lr,[r2]
str r0,[r2,#4]
str r1,[r2,#8]
str r3,[r2,#0x18]
ldr r2, format_ptr
malformed:
b malformed
.align 2
original_ptr: .word {original}
effective_ptr: .word {effective}
format_ptr: .word {base + 0x900}
'''
    code = assemble(source, open_start)
    data[0x100:0x100 + len(code)] = code
    prefix = f'''
vldr s15,[r4,#4]
movs {size_reg},#24
ldr r3,[sp,#0x70]
{'mov.w' if type_reg == 'lr' else 'movs'} {type_reg},#11
orr.w r5,{action_reg},r5,lsl #8
vldr s14,[r4,#8]
stm.w r3,{{{header_registers}}}
str r5,[r3,#0x18]
vcvt.f64.s32 d6,s15
''' + ('ldr.w r0,[sb]\n' if scheduled_load else '')
    divisor_load = touch_start + len(assemble(prefix, touch_start))
    touch = assemble(prefix + f'''
vldr d5,[pc,#{base + 0x500 - ((divisor_load + 4) & ~3)}]
vcvt.f64.s32 d7,s14
vdiv.f64 d6,d6,d5
vdiv.f64 d7,d7,d5
vstr d6,[r3,#8]
vstr d7,[r3,#0x10]
nop
''', touch_start)
    data[0x300:0x300 + len(touch)] = touch
    struct.pack_into('<d', data, 0x500, divisor)
    data[0x900:0x900 + len(OPEN_FORMAT)] = OPEN_FORMAT
    if duplicate:
        # Reassemble to relocate the PC-relative loads and branch together.
        other = assemble(source, base + 0x600)
        data[0x600:0x600 + len(other)] = other
    names = b'\0.text\0.data\0.shstrtab\0'
    data[0x1200:0x1200 + len(names)] = names
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIIIIIHHHHHH', data, 0, ident, 2, 40, 1, open_start | 1,
                     52, 0x1300, 0x5000200, 52, 32, 2, 40, 4, 3)
    struct.pack_into('<8I', data, 52, 1, 0, base, base, 0x1000, 0x1000, 5, 0x1000)
    struct.pack_into('<8I', data, 84, 1, 0x1000, rw, rw, 0x100, 0x200, 6, 0x1000)
    for i, header in enumerate([
        [0] * 10,
        [1, 1, 6, base + 0x100, 0x100, 0xf00, 0, 0, 4, 0],
        [7, 1, 3, rw, 0x1000, 0x100, 0, 0, 4, 0],
        [13, 3, 0, 0, 0x1200, len(names), 0, 0, 1, 0],
    ]):
        struct.pack_into('<10I', data, 0x1300 + 40 * i, *header)
    return bytes(data)


class InventoryTests(unittest.TestCase):
    def test_genuine_shape_inventory_is_path_label_independent(self):
        report, files = inventory(archive())
        self.assertEqual(report['version'], '2026.01.02.0304')
        self.assertEqual(report['member_count'], len(REQUIRED))
        self.assertEqual(report['members']['usr/sbin/ARMadb-driver']['sha256'], sha256(files['usr/sbin/ARMadb-driver']))

    def test_unsafe_paths_and_canonical_duplicates_are_refused(self):
        for name in ('../outside', './a/../b', '/absolute', 'C:/outside', 'a\\b', 'a//b', '././a', 'bad\nname', './etc/software_version'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                inventory(archive([(name, b'bad')]))

    def test_member_types_and_alias_parents_are_refused(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.CONTTYPE):
            member = tarfile.TarInfo('unexpected')
            member.type, member.linkname = kind, '/etc/passwd'
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'member type'):
                inventory(archive([('unexpected', member)]))
        with self.assertRaisesRegex(ValueError, 'non-directory'):
            inventory(archive([('a', b'file'), ('a/b', b'child')]))
        for kind in (tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
            with self.subTest(format=kind), self.assertRaisesRegex(ValueError, 'metadata'):
                inventory(archive([('a' * 120, b'long name')], archive_format=kind))

    def test_known_alias_is_metadata_only_and_requires_regular_target(self):
        member = tarfile.TarInfo('./usr/lib/libcrypto.so')
        member.type, member.linkname = tarfile.SYMTYPE, 'libcrypto.so.1.1'
        with self.assertRaisesRegex(ValueError, 'target'):
            inventory(archive([('', member)]))
        r, f = inventory(archive([('', member), ('usr/lib/libcrypto.so.1.1', b'library')]))
        self.assertNotIn('usr/lib/libcrypto.so', f)
        self.assertEqual(r['members']['usr/lib/libcrypto.so']['type'], 'vendor-library-alias')

    def test_product_version_and_resource_bounds(self):
        for values in ({'etc/box_product_type': b'U2W'}, {'etc/software_version': b'../../escape'}):
            with self.assertRaises(ValueError):
                inventory(archive(overrides=values))
        image = archive()
        for constant, limit in (('MAX_IMAGE', 10), ('MAX_TAR', 64), ('MAX_MEMBERS', 2)):
            with patch('generic_inventory.' + constant, limit), self.assertRaises(ValueError):
                inventory(image)
        with self.assertRaisesRegex(ValueError, 'Invalid A15W'):
            inventory(b'not firmware')


class NativeTests(unittest.TestCase):
    def test_register_allocation_and_integer_scheduling_are_semantic_roles(self):
        for base in (0x10000, 0x430000):
            r = analyze_driver(native_fixture(base, size_reg='r0', type_reg='r2', action_reg='r7', scheduled_load=True))
            self.assertTrue(r['unique_candidates'])
            touch = r['touch_candidates'][0]
            self.assertEqual((touch['size_register'], touch['type_register'], touch['action_register']), ('r0','r2','r7'))
            self.assertEqual(touch['divisor_va'], base + 0x500)
            self.assertIsNotNone(touch['scheduled_integer_load_va'])
        for kwargs in (dict(size_reg='r2', type_reg='r0'), dict(size_reg='r3', type_reg='lr')):
            self.assertFalse(analyze_driver(native_fixture(**kwargs))['touch_candidates'])

    def test_relocated_sources_discover_roles_without_original_addresses(self):
        for base in (0x10000, 0x430000):
            with self.subTest(base=base):
                r = analyze_driver(native_fixture(base))
                self.assertTrue(r['unique_candidates'])
                self.assertEqual(r['open_candidates'][0]['hook']['va'], base + 0x108)
                self.assertEqual(r['open_candidates'][0]['original_open_va'], base + 0x3020)
                self.assertEqual(r['touch_candidates'][0]['hook']['va'], base + 0x310)
                self.assertEqual(r['touch_candidates'][0]['divisor_va'], base + 0x500)
                self.assertFalse(r['patchable'])

    def test_ambiguous_open_does_not_select_first_match(self):
        r = analyze_driver(native_fixture(duplicate=True))
        self.assertEqual(len(r['open_candidates']), 2)
        self.assertFalse(r['unique_candidates'])
        self.assertFalse(r['patchable'])

    def test_wrong_semantics_and_unsupported_elf(self):
        for kwargs, role in ((dict(divisor=9999.0), 'touch_candidates'), (dict(invalid_length=True), 'open_candidates')):
            r = analyze_driver(native_fixture(**kwargs))
            self.assertEqual(r[role], [])
            self.assertFalse(r['unique_candidates'])
        with self.assertRaises(ValueError):
            analyze_driver(b'not an ELF')
        data = bytearray(native_fixture())
        struct.pack_into('<I', data, 84 + 24, 7)
        with self.assertRaisesRegex(ValueError, 'permissions'):
            analyze_driver(bytes(data))

    def test_report_never_promotes_attestation_to_verified_support(self):
        image, driver = archive(), native_fixture()
        r, files = analyze(image, driver)
        identity = {k: r['pairing'][k] for k in ('image_sha256', 'packed_driver_sha256', 'unpacked_driver_sha256')}
        receipt = dict(schema='c10-unpack-attestation-v1', method='fixture only', **identity)
        r, _ = analyze(image, driver, receipt)
        self.assertEqual(r['pairing']['status'], 'matching-attestation-unverified')
        self.assertFalse(r['patchable'])
        receipt['packed_driver_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'packed_driver_sha256'):
            analyze(image, driver, receipt)
        self.assertEqual(files['usr/sbin/ARMadb-driver'], b'vendor fixture')


class CliTests(unittest.TestCase):
    def invoke(self, *args):
        with (patch.object(sys, 'argv', ['generic.py', *map(str, args)]),
              patch('sys.stdout', new_callable=io.StringIO), patch('sys.stderr', new_callable=io.StringIO)):
            main()

    def test_report_and_extraction_refuse_overwrite_and_emit_no_image(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            stock, output, extraction = root / 'source.img', root / 'analysis.json', root / 'packed'
            source = archive()
            stock.write_bytes(source)
            self.invoke('analyze', '--stock', stock, '--output', output)
            self.assertFalse(json.loads(output.read_text())['patchable'])
            before = output.read_bytes()
            for path in (stock, output):
                with self.assertRaises(SystemExit) as error:
                    self.invoke('analyze', '--stock', stock, '--output', path)
                self.assertEqual(error.exception.code, 1)
            self.assertEqual(stock.read_bytes(), source)
            self.assertEqual(output.read_bytes(), before)
            self.invoke('extract-driver', '--stock', stock, '--output', extraction)
            self.assertEqual((extraction / 'ARMadb-driver.packed').read_bytes(), b'vendor fixture')
            with self.assertRaises(SystemExit):
                self.invoke('extract-driver', '--stock', stock, '--output', extraction)
            self.assertEqual(list(root.rglob('A15W_Update.img')), [])

    def test_invalid_input_refuses_before_output_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            stock, output = root / 'source', root / 'missing' / 'report.json'
            stock.write_bytes(b'bad archive')
            with self.assertRaises(SystemExit):
                self.invoke('analyze', '--stock', stock, '--output', output)
            self.assertFalse(output.parent.exists())


if __name__ == '__main__':
    unittest.main()
