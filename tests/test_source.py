"""Host-only negative input and archive-format checks; no firmware fixtures."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import build
from firmware import crypt, read_archive
from runtime_scripts import replace_once


class SourceTests(unittest.TestCase):
    def test_cipher_preserves_unaligned_tail_and_round_trips(self):
        for size in (0, 1, 15, 16, 17, 31, 32, 65):
            body = bytes(range(size))
            encrypted = crypt(body, False)
            self.assertEqual(crypt(encrypted, True), body)
            if size % 16:
                self.assertEqual(encrypted[-(size % 16):], body[-(size % 16):])

    def test_archives_are_read_in_memory(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            member = tarfile.TarInfo('./script/test.sh')
            member.size = 4
            archive.addfile(member, io.BytesIO(b'test'))
        _, _, files = read_archive(crypt(buffer.getvalue(), False))
        self.assertEqual(files, {'./script/test.sh': b'test'})

    def test_unknown_inputs_fail_before_emulation_or_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            bad = root / 'bad'
            bad.write_bytes(b'wrong revision')
            with patch.object(build, 'verify_driver') as emulate:
                with self.assertRaisesRegex(ValueError, 'Stock firmware SHA-256 mismatch'):
                    build.build(bad, bad, root / 'outputs')
                emulate.assert_not_called()
                self.assertFalse((root / 'outputs').exists())
            with self.assertRaisesRegex(ValueError, 'Unpacked original driver SHA-256 mismatch'):
                build.read_pinned(bad, '0' * 64, 'Unpacked original driver')

    def test_startup_edits_require_one_exact_anchor(self):
        for data in (b'no match', b'anchor anchor'):
            with self.assertRaises(ValueError):
                replace_once(data, b'anchor', b'replacement')


if __name__ == '__main__':
    unittest.main()
