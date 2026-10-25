"""Per-input paired installer identities and conservative payload scope."""
import json
import unittest

from firmware import sha256
from generic_package import derive_packages
from generic_runtime import START, DAEMON
from tests.test_generic import archive, native_fixture
from tests.test_generic_runtime import fixture


def stock(extra=b'fixture-original-packed-driver'):
    data = fixture()
    return archive(overrides={**data, 'usr/sbin/ARMadb-driver': extra})


class GenericPackageTests(unittest.TestCase):
    def test_pair_is_stock_specific_and_unpatch_restores_own_exact_inputs(self):
        original = stock()
        native = native_fixture()
        pair = derive_packages(original, native)
        self.assertFalse(pair['generation_allowed'])
        self.assertFalse(pair['installable_images_emitted'])
        patch = pair['patch']
        undo = pair['unpatch']
        self.assertEqual(undo['files']['./tmp/c10_native_driver'], b'fixture-original-packed-driver')
        self.assertEqual(patch['files']['./tmp/c10_native_driver'], native)
        self.assertEqual(undo['files']['./' + START], fixture()[START])
        self.assertEqual(undo['files']['./' + DAEMON], fixture()[DAEMON])
        self.assertEqual(set(undo['files']), {'./' + START, './' + DAEMON, './tmp/c10_native_driver', './tmp/once.sh', './tmp/finish.sh'})
        for result in (patch, undo):
            self.assertEqual(result['manifest']['requires_model'], 'A15W')
            self.assertEqual(result['manifest']['requires_version'], '2026.01.02.0304')
            self.assertEqual(result['manifest']['stock_baseline_image_sha256'], sha256(original))
            self.assertEqual(result['manifest']['members'], {n: sha256(b) for n, b in result['files'].items()})
            self.assertFalse(any(n.startswith('./usr/') or n.startswith('./etc/') for n in result['files']))
        provenance = patch['files']['./script/c10_autokit_fix.baseline']
        self.assertEqual(json.loads(provenance.splitlines()[1]), pair['identity'])
        self.assertEqual(pair['baseline_id'], sha256(provenance.splitlines()[1]))

    def test_different_original_or_native_content_changes_provenance_without_whitelist(self):
        baseline = derive_packages(stock(), native_fixture())
        for image, native in ((stock(b'another stock packed fixture'), native_fixture()), (stock(), native_fixture(0x430000))):
            changed = derive_packages(image, native)
            self.assertNotEqual(changed['baseline_id'], baseline['baseline_id'])
            self.assertNotEqual(changed['patch']['files']['./script/c10_autokit_fix.baseline'],
                                baseline['patch']['files']['./script/c10_autokit_fix.baseline'])

    def test_finish_commits_only_same_directory_pending_and_never_changes_running_process(self):
        pair = derive_packages(stock(), native_fixture())
        for result in (pair['patch'], pair['unpatch']):
            finish = result['files']['./tmp/finish.sh'].decode()
            self.assertIn('cp /tmp/c10_native_driver /usr/sbin/ARMadb-driver.c10.pending', finish)
            self.assertIn('mv -f /usr/sbin/ARMadb-driver.c10.pending /usr/sbin/ARMadb-driver', finish)
            self.assertLess(finish.index('Staged driver mismatch'), finish.index('Cannot commit driver'))
            self.assertLess(finish.index('Cannot flush staged driver'), finish.index('Cannot commit driver'))
            self.assertLess(finish.index('Final driver hash mismatch'), finish.index('INSTALLED.txt'))
            self.assertNotIn('kill', finish)
            self.assertNotIn('/tmp/bin/ARMadb-driver', finish)
            self.assertNotIn('rm -f /mnt/UPAN/AATestMode', finish)
            self.assertNotIn('riddle.conf', finish)
            self.assertIn('[ ! -L /usr/sbin/ARMadb-driver.c10.pending ]', finish)
        self.assertIn('Unknown baseline file: /script/c10_autokit_fix.baseline', pair['patch']['files']['./tmp/once.sh'].decode())

    def test_bad_native_or_stock_layout_cannot_derive_pair(self):
        for native in (b'', b'ELF-looking but unsupported', None):
            with self.subTest(native=native), self.assertRaises(ValueError):
                derive_packages(stock(), native)
        image = archive(overrides={START: b'spawn ARMadb-driver\n', DAEMON: fixture()[DAEMON]})
        with self.assertRaises(ValueError):
            derive_packages(image, native_fixture())


if __name__ == '__main__':
    unittest.main()
