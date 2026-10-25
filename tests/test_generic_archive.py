"""Real encrypted overlay roundtrips and adversarial archive/pair mutations."""
import copy
import gzip
import io
import tarfile
import unittest

from firmware import crypt, sha256
from generic_archive import assemble_pair, inspect_overlay, verify_pair
from tests.test_generic import native_fixture
from tests.test_generic_package import stock


def independent_image(files, *, mode=0o755, extra=None, duplicate=None, uid=0, uname='root', pax=False):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT if pax else tarfile.USTAR_FORMAT) as archive:
        for name in ('.', './script', './tmp'):
            item = tarfile.TarInfo(name)
            item.type, item.mode, item.uid, item.uname, item.gname = tarfile.DIRTYPE, 0o755, uid, uname, 'root'
            archive.addfile(item)
        for name, body in list(files.items()) + ([] if duplicate is None else [(duplicate, files[duplicate])]):
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.uid, item.uname, item.gname = len(body), mode, uid, uname, 'root'
            if pax:
                item.pax_headers = {'comment': 'undeclared extended metadata'}
            archive.addfile(item, io.BytesIO(body))
        if extra is not None:
            item = tarfile.TarInfo(extra)
            item.size, item.mode, item.uname, item.gname = 3, 0o755, 'root', 'root'
            archive.addfile(item, io.BytesIO(b'bad'))
    return crypt(gzip.compress(raw.getvalue(), mtime=0), decrypt=False)


class GenericArchiveTests(unittest.TestCase):
    def test_roundtrip_is_deterministic_bound_and_restores_exact_own_stock(self):
        image, native = stock(), native_fixture()
        native_manifest = dict(source_sha256='1' * 64, generated_sha256=sha256(native))
        pair = assemble_pair(image, native, native_manifest)
        again = assemble_pair(image, native, native_manifest)
        self.assertEqual(pair['patch']['image'], again['patch']['image'])
        self.assertEqual(pair['unpatch']['image'], again['unpatch']['image'])
        self.assertNotEqual(pair['patch']['image'], pair['unpatch']['image'])
        report = verify_pair(image, pair)
        self.assertEqual(report['status'], 'PASS')
        self.assertTrue(report['exact_packed_driver_and_scripts_rollback'])
        self.assertFalse(pair['generation_allowed'])
        for role in ('patch', 'unpatch'):
            item = pair[role]
            self.assertEqual(item['manifest']['output_sha256'], sha256(item['image']))
            self.assertEqual(report[role]['members'], item['manifest']['members'])
            self.assertEqual(report[role]['member_modes'], item['manifest']['member_modes'])
            self.assertEqual(report[role]['member_count'], len(item['files']) + 3)
        with self.assertRaisesRegex(ValueError, 'Native manifest'):
            assemble_pair(image, native, dict(generated_sha256='0' * 64))

    def test_archive_bytes_scope_type_modes_and_hidden_metadata_are_checked(self):
        pair = assemble_pair(stock(), native_fixture())
        files, modes = pair['patch']['files'], pair['patch']['manifest']['member_modes']
        name = next(iter(files))
        hostile = [independent_image(files, mode=0o644), independent_image(files, extra='./etc/shadow'),
                   independent_image(files, duplicate=name), independent_image(files, uid=7),
                   independent_image(files, uname='nobody'), independent_image(files, pax=True),
                   pair['patch']['image'][:20], b'bad image']
        for image in hostile:
            with self.subTest(image_bytes=len(image)), self.assertRaises(ValueError):
                inspect_overlay(image, files, modes)
        linked = dict(files)
        linked[name] = linked[name] + b'changed content'
        with self.assertRaises(ValueError):
            inspect_overlay(independent_image(linked), files, modes)

    def test_forged_maps_manifests_native_binding_and_cross_stock_pair_refuse(self):
        image = stock()
        pair = assemble_pair(image, native_fixture(), dict(generated_sha256=sha256(native_fixture())))
        for role in ('patch', 'unpatch'):
            changed = copy.deepcopy(pair)
            changed[role]['manifest']['output_sha256'] = '0' * 64
            with self.subTest(role=role), self.assertRaises(ValueError):
                verify_pair(image, changed)
            changed = copy.deepcopy(pair)
            path = './script/start_main_service.sh'
            changed[role]['files'][path] += b'\necho unapproved\n'
            changed[role]['manifest']['members'][path] = sha256(changed[role]['files'][path])
            with self.assertRaises(ValueError):
                verify_pair(image, changed)
        changed = copy.deepcopy(pair)
        changed['native_manifest']['generated_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            verify_pair(image, changed)
        changed = copy.deepcopy(pair)
        changed['unpatch'] = assemble_pair(stock(b'different original packed fixture'), native_fixture())['unpatch']
        with self.assertRaises(ValueError):
            verify_pair(image, changed)


if __name__ == '__main__':
    unittest.main()
