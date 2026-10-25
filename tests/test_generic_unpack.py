"""Host decoder integrity, wrong-pair refusal and independent filter vectors."""
import struct
import unittest
from unittest.mock import patch
import zlib

from generic import analyze
from generic_packing import inspect_packed, decode_lzma, MAGIC
from generic_unpack import unpack_driver, kernel_material, arm_call_filter
from tests.test_generic import archive, native_fixture
from tests.test_generic_proof import packed_fixture


def container():
    body = packed_fixture()
    parsed = inspect_packed(body)
    uncompressed, compressed = 1, 1
    for block in parsed['blocks']:
        start, size = block['payload_offset'], block['compressed_bytes']
        source = body[start:start + size]
        compressed = zlib.adler32(source, compressed)
        uncompressed = zlib.adler32(decode_lzma(source, block['uncompressed_bytes']), uncompressed)
    last = parsed['blocks'][-1]
    footer = bytearray(struct.pack('<I4B5I4B', MAGIC, 13, 23, 14, 8, uncompressed, compressed,
                        last['uncompressed_bytes'], last['compressed_bytes'], 0x13a0, 0, 0, 0, 0))
    footer[-1] = sum(footer[4:-1]) % 251
    return body + bytes(2) + footer + struct.pack('<I', 160)


class HostUnpackTests(unittest.TestCase):
    def material(self):
        return patch('generic_unpack.kernel_material', return_value=(bytes(16), bytes(16), {'fixture': True}))

    def test_full_source_generated_reconstruction_has_both_checksums(self):
        with self.material():
            decoded, proof = unpack_driver(container(), b'fixture')
        self.assertEqual(decoded, native_fixture()[:0x13a0])
        self.assertTrue(proof['complete_file_coverage'])
        self.assertTrue(proof['checksums']['compressed'])
        self.assertTrue(proof['checksums']['uncompressed'])
        self.assertFalse(proof['patchable'])

    def test_corruption_padding_footer_and_overlay_pointer_are_refused(self):
        original = container()
        for offset in (200, len(original)-38, len(original)-25, len(original)-5, len(original)-1):
            data = bytearray(original)
            data[offset] ^= 1
            with self.subTest(offset=offset), self.material(), self.assertRaises(ValueError):
                unpack_driver(bytes(data), b'fixture')

    def test_unknown_kernel_does_not_supply_material(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported kernel'):
            kernel_material(bytes(8388608))

    def test_reproduced_decode_rejects_wrong_native_pair(self):
        image = archive(overrides={'usr/sbin/ARMadb-driver': container()})
        exact = native_fixture()[:0x13a0]
        with self.material():
            report, _ = analyze(image, exact, kernel=b'fixture')
            self.assertEqual(report['pairing']['status'], 'reproduced-host-decode')
            self.assertFalse(report['patchable'])
            with self.assertRaisesRegex(ValueError, 'differs from reproduced'):
                analyze(image, exact[:-1] + bytes([exact[-1] ^ 1]), kernel=b'fixture')

    def test_arm_filter_known_vectors_and_final_word_boundary(self):
        # The operand at byte4 changes by one word; byte0 and final word stay.
        filtered = bytes.fromhex('010000eb 050000eb 123456aa ffffffeb')
        expected = bytes.fromhex('010000eb 040000eb 123456aa ffffffeb')
        self.assertEqual(arm_call_filter(filtered), expected)
        self.assertEqual(arm_call_filter(expected, reverse=False), filtered)
        wrapped = bytes.fromhex('00000000 000000eb 00000000')
        self.assertEqual(arm_call_filter(wrapped)[4:7], bytes.fromhex('ffffff'))
        with self.assertRaises(ValueError):
            arm_call_filter(bytes(4))


if __name__ == '__main__':
    unittest.main()
