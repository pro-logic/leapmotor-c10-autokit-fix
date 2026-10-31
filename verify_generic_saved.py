"""Recheck an existing generic build without exporting another driver or image.

Replays packed-input decoding, native structure/behavior and actual encrypted
archive checks. Saved PASS fields are historical claims, never proof inputs.
Optional Linux shell matrices use disposable paths outside the saved build.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from firmware import sha256
from generic import read_bounded
from generic_archive import verify_pair
from generic_build import source_identities, validate_build_plan, _runtime_checks
from generic_inventory import inventory
from generic_native import validate_native, verify_generated_native
from generic_package import derive_packages
from generic_runtime import derive_runtime
from generic_unpack import unpack_driver

# These additions can audit the earlier 65-file build without describing its
# source inventory as identical to the enlarged checkout. Other additions fail.
AUDIT_ADDITIONS = {'verify_generic_saved.py', 'tests/test_generic_saved.py'}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def _object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'Duplicate JSON field: ' + key)
        result[key] = value
    return result


def read_json(path):
    try:
        result = json.loads(read_bounded(path, 16 * 1024 * 1024), object_pairs_hook=_object,
                            parse_constant=lambda value: need(False, 'Invalid JSON constant: ' + value))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('Invalid saved JSON: ' + str(path)) from error
    need(isinstance(result, dict), 'Expected saved JSON object: ' + str(path))
    return result


def check_sources(recorded, current):
    need(isinstance(recorded, dict) and recorded, 'Missing saved source inventory')
    changed = sorted(name for name, digest in recorded.items() if current.get(name) != digest)
    added = sorted(set(current) - set(recorded))
    need(not changed, 'Saved build sources changed or disappeared: ' + ', '.join(changed))
    need(set(added) <= AUDIT_ADDITIONS, 'Unrecorded build sources: ' + ', '.join(added))
    return dict(recorded_files=len(recorded), recorded_files_unchanged=True,
                added_audit_files=added, identical_inventory=not added)


def verify_saved(image, kernel, directory, *, shell_output=None):
    need(not sys.flags.optimize, 'Native verification requires assertions; do not use -O')
    directory = Path(directory).resolve()
    need(directory.is_dir(), 'Missing saved build directory')
    sources = source_identities()
    plan_bytes = read_bounded(directory / 'plan.json', 16 * 1024 * 1024)
    plan = read_json(directory / 'plan.json')
    validation = read_json(directory / 'validation.json')
    source_check = check_sources(plan.get('source_sha256'), sources)
    need(validation.get('source_sha256') == plan['source_sha256'], 'Saved validation/source inventory differs')
    stock, files = inventory(image)
    need(plan.get('image_sha256') == stock['image_sha256'], 'Saved build belongs to another stock image')
    original, decoding = unpack_driver(files['usr/sbin/ARMadb-driver'], kernel)
    changed = read_bounded(directory / 'ARMadb-driver.patched', 16 * 1024 * 1024)
    scripts, runtime = derive_runtime(files)
    manifest = plan.get('native_manifest')
    plan_check = validate_build_plan(plan, stock, original, changed, manifest, runtime, plan['source_sha256'])
    structural = validate_native(original, changed, manifest)
    pair = derive_packages(image, changed)
    binding = sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())
    pair.update(schema='c10-generic-package-pair-v1', native_manifest=manifest,
                native_manifest_sha256=binding)
    for role in ('patch', 'unpatch'):
        item = pair[role]
        item['image'] = read_bounded(directory / role / 'A15W_Update.img', 32 * 1024 * 1024)
        item['manifest'] = read_json(directory / role / 'manifest.json')
        need(item['manifest'].get('native_build_plan_sha256') == sha256(plan_bytes),
             'Saved archive build-plan binding differs: ' + role)
    archives = verify_pair(image, pair)
    # Execute supplied saved bytes only after both archive payloads and rollback
    # have been checked; do not substitute freshly serialized candidate images.
    behavior = verify_generated_native(original, changed, manifest)
    shell = dict(status='not rerun', historical_claim=validation.get('shell_tests', {}).get('status'),
                 historical_claim_trusted_as_evidence=False)
    if shell_output is not None:
        output = Path(shell_output).resolve()
        need(output != directory and directory not in output.parents,
             'Shell evidence must be outside the read-only saved build')
        need(not output.exists(), 'Refusing existing shell evidence directory')
        from verify_generic_package import verify_package_pair
        package = verify_package_pair(image, pair, output / 'package-checks', shell_tests=True)
        runtime_check = _runtime_checks(scripts, output / 'runtime-checks')
        shell = dict(status='PASS', package=package, runtime=runtime_check)
    need(source_identities() == sources, 'Source changed during saved-build verification')
    return dict(schema='c10-saved-generic-validation-v1', status='PASS', saved_build=str(directory),
                image_sha256=stock['image_sha256'], version=stock['version'],
                decoding=decoding, plan_validation=plan_check, source_check=source_check,
                source_sha256=sources, native_structure=structural, native_behavior=behavior,
                archives=archives, shell_tests=shell,
                saved_validation_sha256=sha256(read_bounded(directory / 'validation.json', 16 * 1024 * 1024)),
                saved_validation_used_as_proof=False, images_emitted=False,
                installation_performed=False, hardware_tested=False,
                limits=manifest['compatibility_contract']['limits'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stock', 'kernel', 'build', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--shell-tests', action='store_true')
    args = parser.parse_args()
    output, saved = args.output.resolve(), args.build.resolve()
    need(not output.exists() and not output.is_symlink(), 'Refusing existing evidence directory')
    need(output != saved and saved not in output.parents, 'Evidence must be outside the read-only saved build')
    report = verify_saved(read_bounded(args.stock, 64 * 1024 * 1024),
                          read_bounded(args.kernel, 8 * 1024 * 1024), saved,
                          shell_output=output if args.shell_tests else None)
    output.mkdir(parents=True, exist_ok=args.shell_tests)
    with (output / 'validation.json').open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status=report['status'], output=str(output),
                         shell_tests=report['shell_tests']['status'], images_emitted=False), indent=2))


if __name__ == '__main__':
    main()
