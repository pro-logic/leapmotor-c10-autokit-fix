"""Saved-byte corruption and stale-source refusal, independent of PASS receipts."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from firmware import sha256
from generic_archive import assemble_pair
from generic_build import build_plan, source_identities
from generic_inventory import inventory
from generic_runtime import derive_runtime
from tests.test_generic import native_fixture
from tests.test_generic_build import stock_fixture
from verify_generic_saved import check_sources, read_json, verify_saved


class SavedBuildTests(unittest.TestCase):
    def saved(self, root):
        image, original = stock_fixture(), native_fixture()
        stock, files = inventory(image)
        _, runtime = derive_runtime(files)
        manifest = dict(generated_sha256=sha256(original), compatibility_contract={'limits': ['fixture only']})
        plan = build_plan(stock, original, original, manifest, runtime, source_identities())
        write = lambda path, value: path.write_text(json.dumps(value), encoding='utf-8')
        write(root / 'plan.json', plan)
        write(root / 'validation.json', dict(status='PASS', source_sha256=plan['source_sha256'],
                                            shell_tests={'status': 'PASS'}))
        (root / 'ARMadb-driver.patched').write_bytes(original)
        pair = assemble_pair(image, original, manifest)
        for role in ('patch', 'unpatch'):
            directory = root / role
            directory.mkdir()
            (directory / 'A15W_Update.img').write_bytes(pair[role]['image'])
            pair[role]['manifest']['native_build_plan_sha256'] = sha256((root / 'plan.json').read_bytes())
            write(directory / 'manifest.json', pair[role]['manifest'])
        return image, original

    def run_saved(self, root, image, original):
        # Only native generation/decoding are stood in. Actual saved archive
        # decrypt/inspection, stock derivation and all input/plan checks execute.
        return (patch('verify_generic_saved.unpack_driver', return_value=(original, {'fixture': True})),
                patch('verify_generic_saved.validate_native', return_value={'status': 'PASS'}),
                patch('verify_generic_saved.verify_generated_native', return_value={'status': 'PASS'}))

    def test_actual_archives_checked_without_modifying_saved_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, original = self.saved(root)
            before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            decode, structure, behavior = self.run_saved(root, image, original)
            with decode, structure, behavior as emulation:
                result = verify_saved(image, b'kernel', root)
            emulation.assert_called_once()
            self.assertEqual(emulation.call_args.args[1], before[Path('ARMadb-driver.patched')])
            self.assertEqual(result['archives']['status'], 'PASS')
            self.assertFalse(result['images_emitted'])
            self.assertFalse(result['saved_validation_used_as_proof'])
            self.assertEqual(result['shell_tests']['status'], 'not rerun')
            self.assertFalse(result['shell_tests']['historical_claim_trusted_as_evidence'])
            self.assertEqual(before, {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()})

    def test_corrupt_archive_wrong_plan_binding_and_wrong_native_fail_before_emulation(self):
        for change in ('archive', 'plan-binding', 'native'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                image, original = self.saved(root)
                if change == 'archive':
                    (root / 'unpatch/A15W_Update.img').write_bytes(b'corrupt image')
                elif change == 'native':
                    (root / 'ARMadb-driver.patched').write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                else:
                    path = root / 'patch/manifest.json'
                    manifest = json.loads(path.read_text())
                    manifest['native_build_plan_sha256'] = '0' * 64
                    path.write_text(json.dumps(manifest))
                decode, structure, behavior = self.run_saved(root, image, original)
                with decode, structure, behavior as emulation, self.assertRaises(ValueError):
                    verify_saved(image, b'kernel', root)
                emulation.assert_not_called()

    def test_saved_pass_does_not_hide_native_verifier_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, original = self.saved(root)
            decode, structure, behavior = self.run_saved(root, image, original)
            with decode, structure, behavior as emulation:
                emulation.side_effect = ValueError('native behavioral counterexample')
                with self.assertRaisesRegex(ValueError, 'counterexample'):
                    verify_saved(image, b'kernel', root)

    def test_sources_cannot_be_removed_edited_or_silently_extended(self):
        original = {'generic_native.py': 'a' * 64}
        for current in ({}, {'generic_native.py': 'b' * 64}, {**original, 'new_generator.py': 'c' * 64}):
            with self.subTest(current=current), self.assertRaises(ValueError):
                check_sources(original, current)
        result = check_sources(original, {**original, 'verify_generic_saved.py': 'c' * 64})
        self.assertTrue(result['recorded_files_unchanged'])
        self.assertFalse(result['identical_inventory'])
        self.assertEqual(result['added_audit_files'], ['verify_generic_saved.py'])

    def test_duplicate_json_fields_and_nonfinite_values_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            for body in ('{"status":"FAIL","status":"PASS"}', '{"value":NaN}', '[]'):
                with self.subTest(body=body):
                    path.write_text(body)
                    with self.assertRaises(ValueError):
                        read_json(path)


if __name__ == '__main__':
    unittest.main()
