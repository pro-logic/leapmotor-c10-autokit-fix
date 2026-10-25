"""Adversarial partial-container and non-authorizing proof-draft checks."""
import copy
import lzma
import struct
import unittest
from unittest.mock import patch

from generic import analyze
from generic_packing import MAGIC, decode_lzma, inspect_packed
from generic_plan import HERE, SOURCES, draft_plan, insertion_layout, validate_draft
from tests.test_generic import archive, native_fixture


def packed_fixture():
    """Source-generated two-LOAD ELF in the observed container, no vendor bytes."""
    native = native_fixture()[:0x13a0]
    data = bytearray(172)
    h = list(struct.unpack_from('<16sHHIIIIIHHHHHH', native))
    h[0] = h[0][:7] + b'\x03' + h[0][8:]
    h[6], h[10], h[12], h[13] = 0, 3, 0, 0

    def add(body):
        filters = [dict(id=lzma.FILTER_LZMA1, dict_size=4096, lc=3, lp=0, pb=2)]
        encoded = bytes.fromhex('1a03') + lzma.compress(body, format=lzma.FORMAT_RAW, filters=filters)
        data.extend(struct.pack('<IIBBBB', len(body), len(encoded), 14, 0, 0, 0) + encoded)

    add(native[:116])
    add(native[116:0x1000])
    add(native[0x1000:0x1100])
    data.extend(bytes((-len(data)) % 4))
    loader_start = len(data)
    data.extend(bytes(16))
    add(native[0x1100:])
    data.extend(struct.pack('<III', 0, MAGIC, 0))
    h[4] = 0x10000 + loader_start + 12
    struct.pack_into('<16sHHIIIIIHHHHHH', data, 0, *h)
    struct.pack_into('<8I', data, 52, 1, 0, 0x10000, 0x10000, loader_start + 16, loader_start + 16, 5, 65536)
    struct.pack_into('<8I', data, 84, 1, 0, 0x50000, 0x50000, 0, 0x10000, 6, 65536)
    struct.pack_into('<8I', data, 116, 0x6474e551, 0, 0, 0, 0, 0, 6, 16)
    struct.pack_into('<IIHBBIII', data, 148, 0, MAGIC, 16, 13, 23, 0, len(native), len(native))
    return bytes(data)


class PackingTests(unittest.TestCase):
    def test_source_container_partial_decoding_never_establishes_native_input(self):
        r = inspect_packed(packed_fixture())
        self.assertEqual(r['original_file_bytes'], 0x13a0)
        self.assertEqual(len(r['blocks']), 4)
        self.assertTrue(all('decoded_sha256' in b for b in r['blocks']))
        self.assertFalse(r['complete_native_input'])
        self.assertIsNone(r['complete_unpacked_sha256'])
        self.assertFalse(r['patchable'])

    def test_bounds_headers_methods_and_terminator_fail_closed(self):
        source = packed_fixture()
        for off, fmt, value in ((28, '<I', 0), (156, '<H', 65535), (164, '<I', 0xffffffff),
                                (172, '<I', 0xffffffff), (176, '<I', 0xffffffff),
                                (180, '<B', 1), (181, '<B', 77), (len(source) - 8, '<I', 0)):
            b = bytearray(source)
            struct.pack_into(fmt, b, off, value)
            with self.subTest(offset=off), self.assertRaises(ValueError):
                inspect_packed(bytes(b))
        for b in (source[:20], source[:180], source[:-1], b'UPX!'):
            with self.assertRaises(ValueError):
                inspect_packed(b)

    def test_invalid_properties_and_output_limits_are_not_native_evidence(self):
        for source, size in ((b'\x45\xc1\x00', 200), (b'\x1a\x03', 10),
                             (b'\x1a\x03\x00', 2**32)):
            with self.assertRaises(ValueError):
                decode_lzma(source, size)


class ProofDraftTests(unittest.TestCase):
    def test_source_identity_covers_implementation_verifiers_and_harnesses(self):
        required = {p.relative_to(HERE).as_posix() for pattern in ('*.py', 'tests/*.py', 'tools/*.py',
                    'runtime/*.sh', 'templates/*.in', 'requirements.txt') for p in HERE.glob(pattern)}
        self.assertEqual(set(SOURCES), required)
        self.assertEqual(len(SOURCES), len(set(SOURCES)))
        self.assertTrue({'generic_channel.py', 'generic_global_flow.py', 'generic_package.py',
                         'verify_generic_contracts.py', 'tests/shell_runtime.py'} <= required)
        self.assertFalse(any(name.startswith(('inputs/', 'dist/', '.venv/')) for name in SOURCES))

    def test_relocated_layouts_derive_offsets_state_and_alignment(self):
        for base in (0x10000, 0x430000):
            with self.subTest(base=base):
                r = insertion_layout(native_fixture(base))
                self.assertEqual(r['insertion_file_offset'], 0x1000)
                self.assertEqual(r['rx_va'], base + 0x1000)
                self.assertEqual(r['state_va'], base + 0x3200)
                self.assertEqual(r['inserted_file_gap_bytes'], 0x1000)
                self.assertFalse(r['generation_allowed'])

    def test_virtual_gap_section_mapping_and_metadata_crossings_refused(self):
        source = native_fixture()
        for off, value in ((84 + 8, 0x11000),  # RW would collide with extended RX
                           (52 + 20, 0x1100),  # RX includes zero memory tail
                           (0x1300 + 40 + 4 * 4, 0x200),  # executable section offset mismatch
                           (0x1300 + 3 * 40 + 4 * 4, 0xff0),  # string table straddles insertion
                           (84 + 28, 0x200000)):
            b = bytearray(source)
            struct.pack_into('<I', b, off, value)
            with self.subTest(offset=off), self.assertRaises(ValueError):
                insertion_layout(bytes(b))
        for size in (0, 4097, 65540, True):
            with self.assertRaises(ValueError):
                insertion_layout(source, code_bytes=size)

    def test_edited_stale_and_cross_input_drafts_do_not_gain_authority(self):
        image, native = archive(), native_fixture()
        report, files = analyze(image, native)
        draft = draft_plan(report, files, native)
        self.assertFalse(validate_draft(draft, report, files, native)['generation_allowed'])
        self.assertTrue(all(p['status'] == 'unproved' for p in draft['required_proofs'].values()))
        altered = copy.deepcopy(draft)
        altered['required_proofs']['plaintext-open-after-decryption']['status'] = 'proved'
        with self.assertRaisesRegex(ValueError, 'Stale or edited'):
            validate_draft(altered, report, files, native)
        for change in ('generation_allowed', 'candidate_hooks', 'implementation_sha256'):
            altered = copy.deepcopy(draft)
            altered[change] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_draft(altered, report, files, native)
        for other in (native_fixture(0x430000), native[:-1] + b'changed'):
            with self.assertRaises(ValueError):
                validate_draft(draft, report, files, other)
        with patch('generic_plan.SOURCES', ('generic.py',)):
            with self.assertRaises(ValueError):
                validate_draft(draft, report, files, native)

    def test_missing_native_keeps_all_dependencies_explicit(self):
        report, files = analyze(archive())
        draft = draft_plan(report, files)
        self.assertIsNone(draft['unpacked_driver_sha256'])
        self.assertEqual(draft['candidate_hooks'], [])
        self.assertFalse(draft['generation_allowed'])
        self.assertIn('unavailable', draft['insertion_proposal']['status'])


if __name__ == '__main__':
    unittest.main()
