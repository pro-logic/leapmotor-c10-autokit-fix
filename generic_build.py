"""Build paired experimental C10 overlays for structurally recognized A15W inputs.

Native generation and independent emulation operate on the exact host-decoded
stock member. Historical proof drafts are not accepted as build authority.
"""
from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

from firmware import sha256
from generic_inventory import inventory
from generic_plan import HERE
from generic_runtime import derive_runtime
from generic_unpack import unpack_driver


def source_identities():
    """Read the current source inventory, including files added after import."""
    return {p.relative_to(HERE).as_posix(): sha256(p.read_bytes())
            for p in sorted({p for pattern in ('*.py', 'tests/*.py', 'tools/*.py',
                         'runtime/*.sh', 'templates/*.in', 'requirements.txt')
                         for p in HERE.glob(pattern) if p.is_file()})}


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def build_plan(stock, original, changed, manifest, runtime, sources):
    """A reproducible build record with finite checks and explicit assumptions."""
    return dict(schema='c10-recognized-build-plan-v1', product=stock['product'], version=stock['version'],
        image_sha256=stock['image_sha256'], original_native_sha256=sha256(original),
        generated_native_sha256=sha256(changed), native_manifest=manifest,
        runtime_contract=runtime, source_sha256=sources,
        acceptance='replayed exact packed/native pairing; recognized native/runtime grammars; independent supplied-output validation',
        evidence_scope='restricted compatible layouts under normal native descriptor/allocator/ABI contracts',
        hardware_tested=False)


def validate_build_plan(plan, stock, original, changed, manifest, runtime, sources):
    expected = build_plan(stock, original, changed, manifest, runtime, sources)
    _need(plan == expected, 'Stale or edited recognized-layout build plan')
    return dict(status='PASS', schema=plan['schema'], recomputed=True)


def _write_json(path, data):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def _runtime_checks(scripts, output):
    """Run the stock-derived runtime with real shell/processes in disposable paths."""
    import base64
    from verify_generic_runtime import LINUX_HARNESS, linux_path
    output.mkdir(parents=True, exist_ok=False)
    payload = output / 'payload.json'
    _write_json(payload, {'./' + name: base64.b64encode(body).decode() for name, body in scripts.items()})
    harness = output / 'runtime_matrix.py'
    harness.write_text(LINUX_HARNESS, encoding='utf-8', newline='\n')
    command = ['python3', str(harness), str(payload), str(HERE)] if os.name != 'nt' else [
        'wsl', '--exec', 'python3', linux_path(harness), linux_path(payload), linux_path(HERE)]
    run = subprocess.run(command, capture_output=True, text=True, timeout=180)
    (output / 'stdout.log').write_text(run.stdout, encoding='utf-8')
    (output / 'stderr.log').write_text(run.stderr, encoding='utf-8')
    _need(run.returncode == 0, 'Runtime shell validation failed; inspect staging runtime-checks logs')
    result = json.loads(run.stdout)
    _need(result.get('status') == 'PASS', 'Runtime shell checks did not pass')
    _write_json(output / 'validation.json', result)
    return result


def build(image, kernel, *, driver=None, output=None, shell_tests=False, progress=None):
    """Validate, derive and atomically publish one new local patch/unpatch pair.

    No supplied JSON receipt or plan can bypass decoding or recognition. Output
    is published only after native and archive checks (and requested shell checks).
    Failed staging evidence is retained without publishing the requested output.
    """
    _need(not sys.flags.optimize, 'Native verification requires Python assertions; do not use -O')
    _need(kernel is not None, 'Generic build requires --kernel for reproduced packed-to-native pairing')
    sources = source_identities()
    stock, files = inventory(image)
    target = Path(output) if output is not None else HERE / 'dist/generic' / (
        stock['version'] + '-' + stock['image_sha256'][:12]) / 'build'
    _need(not target.exists() and not target.is_symlink(), 'Refusing existing build output: ' + str(target))
    emit = progress or (lambda message: None)
    emit('Reproducing exact stock driver decoding')
    original, decoding = unpack_driver(files['usr/sbin/ARMadb-driver'], kernel)
    _need(driver is None or driver == original, 'Supplied native driver differs from reproduced stock decoding')
    scripts, runtime = derive_runtime(files)
    from generic_native import generate_native, validate_native, verify_generated_native
    from generic_archive import assemble_pair, verify_pair
    emit('Recognizing native layout and generating C10 hooks')
    changed, manifest = generate_native(original)
    structural = validate_native(original, changed, manifest)
    _need(structural.get('status') == 'PASS', 'Generated native structure did not pass validation')
    emit('Emulating the actual generated native paths')
    native_checks = verify_generated_native(original, changed, manifest)
    _need(native_checks.get('status') == 'PASS', 'Generated native behavior did not pass validation')
    emit('Building and independently decrypting paired archives')
    pair = assemble_pair(image, changed, manifest)
    archives = verify_pair(image, pair)
    _need(archives.get('status') == 'PASS', 'Paired encrypted archives did not pass validation')
    plan = build_plan(stock, original, changed, manifest, runtime, sources)
    plan_check = validate_build_plan(plan, stock, original, changed, manifest, runtime, sources)
    _need(source_identities() == sources, 'Source changed during build; retry after source edits finish')
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.' + target.name + '.staging-', dir=target.parent)).resolve()
    try:
        shell = dict(status='not requested')
        if shell_tests:
            from verify_generic_package import verify_package_pair
            emit('Running actual paired installer and runtime shell matrices')
            package_checks = verify_package_pair(image, pair, staging / 'package-checks', shell_tests=True)
            runtime_checks = _runtime_checks(scripts, staging / 'runtime-checks')
            _need(package_checks.get('status') == 'PASS', 'Actual-pair installer checks did not pass')
            shell = dict(status='PASS', package=package_checks, runtime=runtime_checks)
        _need(source_identities() == sources, 'Source changed during shell validation; build withheld')
        validation = dict(schema='c10-generic-build-validation-v1', status='PASS', experimental=True,
            generation_allowed=True, installable_images_emitted=True,
            product=stock['product'], version=stock['version'], image_sha256=stock['image_sha256'],
            packed_driver_sha256=sha256(files['usr/sbin/ARMadb-driver']),
            original_native_sha256=sha256(original), generated_native_sha256=sha256(changed),
            decoding=decoding, native_structure=structural, native_behavior=native_checks,
            archives=archives, plan_validation=plan_check, shell_tests=shell,
            source_sha256=sources, python=sys.version, platform=platform.platform(),
            tool_versions={name: importlib.metadata.version(name) for name in
                ('capstone', 'keystone-engine', 'pyelftools', 'unicorn', 'cryptography')},
            hardware_tested=False, installation_performed=False,
            limits=['Restricted recognized A15W layouts and empirical C10 profile only',
                    'Emulation and disposable shell simulation; complete OS/vehicle behavior is not reproduced',
                    'See native manifest for descriptor, allocator, ABI and unwind contracts'])
        _write_json(staging / 'plan.json', plan)
        _write_json(staging / 'validation.json', validation)
        (staging / 'ARMadb-driver.patched').write_bytes(changed)
        for which in ('patch', 'unpatch'):
            directory = staging / which
            directory.mkdir()
            body = pair[which]['image']
            (directory / 'A15W_Update.img').write_bytes(body)
            package_manifest = dict(pair[which]['manifest'], output_sha256=sha256(body), output_bytes=len(body),
                native_build_plan_sha256=sha256((staging / 'plan.json').read_bytes()),
                native_generation_proof='PASS: exact decoded input, recognized layout and independent supplied-output native validation',
                generation_allowed=True, installable_images_emitted=True,
                validation_status='PASS', shell_validation=shell['status'], hardware_tested=False)
            _write_json(directory / 'manifest.json', package_manifest)
            _need((directory / 'A15W_Update.img').read_bytes() == body, 'Written archive differs from validated bytes')
        _need((staging / 'ARMadb-driver.patched').read_bytes() == changed, 'Written native payload differs')
        _need(source_identities() == sources, 'Source changed before output publication; build withheld')
        _need(not target.exists() and not target.is_symlink(), 'Build output appeared during validation')
        staging.rename(target)
    except BaseException as error:
        # Retain disposable diagnostics for review. No recursive cleanup or
        # promotion of a partial directory into the requested output occurs.
        if staging.exists():
            failure = staging / 'FAILED.json'
            if not failure.exists():
                _write_json(failure, dict(status='FAILED; requested output was not published', reason=str(error)))
        raise
    return dict(status='PASS', output=str(target.resolve()), product=stock['product'], version=stock['version'],
                patch=str((target / 'patch/A15W_Update.img').resolve()),
                unpatch=str((target / 'unpatch/A15W_Update.img').resolve()),
                generated_native_sha256=sha256(changed), shell_validation=shell['status'], hardware_tested=False)
