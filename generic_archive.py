"""Paired A15W overlay serialization and independent bounded inspection.

These are packaging mechanics. The caller must validate native generation before
writing either image; a well-formed ELF/archive alone grants no compatibility.
"""
from __future__ import annotations

import gzip
import io
import json
import tarfile
import zlib

from firmware import add_regular, crypt, sha256
from generic_inventory import inventory
from generic_package import derive_packages

DIRECTORIES = ('.', './script', './tmp')
MAX_OVERLAY = 32 * 1024 * 1024


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)


def _serialize(files, modes):
    stream = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name in DIRECTORIES:
                member = tarfile.TarInfo(name)
                member.type, member.mode = tarfile.DIRTYPE, 0o755
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = 'root'
                archive.addfile(member)
            for name, body in files.items():
                add_regular(archive, name, body, modes[name], 0)
    return crypt(stream.getvalue(), decrypt=False)


def inspect_overlay(image, expected_files, expected_modes):
    """Decrypt and check every archive record, not just declared manifest hashes."""
    _need(isinstance(image, bytes) and 0 < len(image) <= MAX_OVERLAY, 'Overlay image exceeds supported bounds')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(crypt(image, decrypt=True)), mode='rb') as compressed:
            plain = compressed.read(MAX_OVERLAY + 1)
        _need(len(plain) <= MAX_OVERLAY and len(plain) % 512 == 0, 'Overlay tar bounds/alignment differ')
        # USTAR here has exactly three directory headers, one header per payload,
        # two end blocks, and standard tarfile record padding.
        used = 512 * (len(DIRECTORIES) + len(expected_files) + 2)
        used += sum((len(body) + 511) // 512 * 512 for body in expected_files.values())
        expected_tar_bytes = (used + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE * tarfile.RECORDSIZE
        _need(len(plain) == expected_tar_bytes, 'Overlay tar contains undeclared/trailing extent')
        actual, modes, directory_modes, seen, end = {}, {}, {}, set(), 0
        with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
            for member in archive:
                _need(member.offset == end and member.offset_data == member.offset + 512,
                      'Overlay contains extended/hidden archive headers')
                _need(member.name not in seen, 'Duplicate overlay archive member')
                seen.add(member.name)
                _need(not member.pax_headers and not member.linkname and member.uid == member.gid == member.mtime == 0
                      and member.uname == member.gname == 'root' and member.sparse is None,
                      'Unsupported overlay archive metadata')
                if member.isdir():
                    _need(member.name in DIRECTORIES and member.size == 0, 'Unexpected overlay directory')
                    directory_modes[member.name] = member.mode
                else:
                    _need(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and member.name in expected_files,
                          'Unexpected overlay member path/type')
                    _need(member.size == len(expected_files[member.name]), 'Overlay member length differs')
                    body = archive.extractfile(member).read()
                    _need(body == expected_files[member.name], 'Overlay member bytes differ')
                    actual[member.name], modes[member.name] = body, member.mode
                end = max(end, member.offset_data + (member.size + 511) // 512 * 512)
        _need(actual == expected_files and modes == expected_modes, 'Overlay member scope/modes differ')
        _need(directory_modes == {name: 0o755 for name in DIRECTORIES}, 'Overlay directory scope/modes differ')
        _need(len(plain) - end >= 1024 and not any(plain[end:]), 'Overlay has undeclared trailing tar data')
    except (OSError, EOFError, tarfile.TarError, zlib.error) as error:
        raise ValueError('Invalid encrypted overlay archive') from error
    return dict(status='PASS', image_bytes=len(image), image_sha256=sha256(image),
                member_count=len(seen), members={name: sha256(body) for name, body in actual.items()},
                member_modes=modes, directories=directory_modes)


def assemble_pair(image, generated_driver, native_manifest=None):
    """Return encrypted patch/unpatch bytes and file maps, without writing files."""
    pair = derive_packages(image, generated_driver)
    binding = None
    if native_manifest is not None:
        _need(isinstance(native_manifest, dict) and native_manifest.get('generated_sha256') == sha256(generated_driver),
              'Native manifest does not bind the generated driver')
        try:
            binding = sha256(json.dumps(native_manifest, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())
        except (TypeError, ValueError) as error:
            raise ValueError('Native manifest is not canonical JSON metadata') from error
    for role in ('patch', 'unpatch'):
        item = pair[role]
        item['image'] = _serialize(item['files'], item['manifest']['member_modes'])
        item['manifest'].update(schema='c10-generic-package-v1', output='A15W_Update.img',
            output_bytes=len(item['image']), output_sha256=sha256(item['image']),
            native_manifest_sha256=binding, archive_serialized=True,
            native_generation_proof='caller must independently validate generated native bytes before exporting this pair')
    pair.update(schema='c10-generic-package-pair-v1', native_manifest_sha256=binding,
                native_manifest=native_manifest, archive_serialized=True)
    pair['archive_validation'] = verify_pair(image, pair)
    return pair


def verify_pair(image, pair):
    """Re-derive stock payloads and inspect both actual encrypted archives."""
    _need(isinstance(pair, dict) and pair.get('schema') == 'c10-generic-package-pair-v1', 'Unsupported package pair schema')
    try:
        generated = pair['patch']['files']['./tmp/c10_native_driver']
        expected = derive_packages(image, generated)
        _need(pair['identity'] == expected['identity'] and pair['baseline_id'] == expected['baseline_id'],
              'Package pair baseline/provenance differs')
        native_manifest = pair.get('native_manifest')
        binding = None
        if native_manifest is not None:
            _need(isinstance(native_manifest, dict), 'Malformed native manifest binding')
            _need(native_manifest.get('generated_sha256') == sha256(generated), 'Native binding output differs')
            binding = sha256(json.dumps(native_manifest, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())
        _need(pair.get('native_manifest_sha256') == binding, 'Native manifest digest differs')
        reports = {}
        for role in ('patch', 'unpatch'):
            item, wanted = pair[role], expected[role]
            _need(isinstance(item, dict) and isinstance(item.get('manifest'), dict), 'Malformed package metadata')
            _need(item['files'] == wanted['files'], 'Package payload differs from stock-specific derivation')
            for key, value in wanted['manifest'].items():
                if key not in ('schema', 'native_generation_proof', 'generation_allowed', 'installable_images_emitted'):
                    _need(item['manifest'].get(key) == value, 'Package manifest differs: ' + key)
            checked = inspect_overlay(item['image'], wanted['files'], wanted['manifest']['member_modes'])
            _need(item['manifest'].get('output_sha256') == checked['image_sha256'] and
                  item['manifest'].get('output_bytes') == checked['image_bytes'] and
                  item['manifest'].get('native_manifest_sha256') == binding, 'Archive manifest identity differs')
            reports[role] = checked
        stock, files = inventory(image)
        _need(pair['unpatch']['files']['./tmp/c10_native_driver'] == files['usr/sbin/ARMadb-driver'],
              'Rollback driver is not the original packed input')
        for name in ('script/start_main_service.sh', 'script/phone_link_deamon.sh'):
            _need(pair['unpatch']['files']['./' + name] == files[name], 'Rollback script is not its exact stock input')
    except (KeyError, TypeError) as error:
        raise ValueError('Malformed package pair') from error
    return dict(schema='c10-generic-pair-archive-validation-v1', status='PASS',
                image_sha256=stock['image_sha256'], baseline_id=pair['baseline_id'],
                native_manifest_sha256=binding, patch=reports['patch'], unpatch=reports['unpatch'],
                exact_packed_driver_and_scripts_rollback=True,
                scope='actual encrypted archive bytes and stock-specific payload identities; native semantics are caller validation',
                hardware_tested=False)
