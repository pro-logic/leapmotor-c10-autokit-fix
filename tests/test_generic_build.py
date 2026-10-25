"""Build refusals, unchanged inputs and deterministic source/input records."""
import copy
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from generic import main
from generic_build import build, build_plan, source_identities, validate_build_plan
from tests.test_generic import archive, native_fixture
from tests.test_generic_runtime import fixture


def stock_fixture():
    return archive(overrides=fixture())


class BuildTests(unittest.TestCase):
    def test_missing_kernel_and_invalid_stock_leave_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'not-created' / 'pair'
            for image, kernel in ((stock_fixture(), None), (b'bad image', b'bad kernel')):
                with self.subTest(kernel=kernel), self.assertRaises(ValueError):
                    build(image, kernel, output=output)
                self.assertFalse(output.parent.exists())

    def test_existing_output_refuses_without_touching_it_or_decoding(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'existing'
            output.mkdir()
            marker = output / 'keep.txt'
            marker.write_bytes(b'prior build')
            with patch('generic_build.unpack_driver') as decode, self.assertRaisesRegex(ValueError, 'existing'):
                build(stock_fixture(), b'kernel', output=output)
            decode.assert_not_called()
            self.assertEqual(marker.read_bytes(), b'prior build')

    def test_mismatched_supplied_native_refuses_before_runtime_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'not-created' / 'pair'
            with patch('generic_build.unpack_driver', return_value=(native_fixture(), {})), \
                 patch('generic_build.derive_runtime') as runtime, self.assertRaisesRegex(ValueError, 'differs'):
                build(stock_fixture(), b'kernel', driver=native_fixture(0x430000), output=output)
            runtime.assert_not_called()
            self.assertFalse(output.parent.exists())

    def test_build_record_detects_tampering_without_granting_generation(self):
        stock = dict(product='A15W', version='2026.01.02.0304', image_sha256='a' * 64)
        original, changed, manifest, runtime, sources = b'original', b'changed', {'hooks': []}, {'edits': []}, {'x.py': 'b' * 64}
        record = build_plan(stock, original, changed, manifest, runtime, sources)
        self.assertEqual(validate_build_plan(record, stock, original, changed, manifest, runtime, sources)['status'], 'PASS')
        self.assertNotIn('generation_allowed', record)
        for name in ('image_sha256', 'generated_native_sha256', 'source_sha256', 'native_manifest'):
            altered = copy.deepcopy(record)
            altered[name] = 'edited'
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Stale or edited'):
                validate_build_plan(altered, stock, original, changed, manifest, runtime, sources)

    def test_source_snapshot_includes_current_build_and_tests(self):
        identities = source_identities()
        self.assertIn('generic_build.py', identities)
        self.assertIn('tests/test_generic_build.py', identities)
        self.assertFalse(any(name.startswith(('dist/', 'inputs/', '.venv/')) for name in identities))

    def test_cli_build_requires_reproduction_and_shell_flag_is_build_only(self):
        with tempfile.TemporaryDirectory() as directory:
            stock, output = Path(directory) / 'stock.img', Path(directory) / 'pair'
            image = stock_fixture()
            stock.write_bytes(image)
            for command in (['build'], ['analyze', '--shell-tests']):
                argv = ['generic.py', *command, '--stock', str(stock), '--output', str(output)]
                with self.subTest(command=command), patch.object(sys, 'argv', argv), \
                     patch('sys.stdout', new_callable=io.StringIO), patch('sys.stderr', new_callable=io.StringIO):
                    with self.assertRaises(SystemExit) as error:
                        main()
                self.assertEqual(error.exception.code, 1)
                self.assertFalse(output.exists())
            self.assertEqual(stock.read_bytes(), image)


if __name__ == '__main__':
    unittest.main()
