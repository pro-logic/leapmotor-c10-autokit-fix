"""Rebuild, inspect actual encrypted archives, optionally run Linux shell fixtures."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import build
from firmware import read_archive, sha256
from runtime_scripts import DRIVER_MEMBER, START, DAEMON, STAGED, LAUNCH


def encode(files):
    return {name: base64.b64encode(body).decode('ascii') for name, body in files.items()}


def linux_path(path):
    path = Path(path).resolve()
    return '/mnt/' + path.drive[0].lower() + path.as_posix()[2:]


def verify(stock_path, driver_path, output, shell_tests=False):
    report, stock, current, manifests = build.build(stock_path, driver_path, output)
    images = []
    for undo, manifest in zip((False, True), manifests):
        path = Path(output) / ('unpatch' if undo else 'patch') / 'A15W_Update.img'
        image = path.read_bytes()
        _, members, files = read_archive(image)
        assert sha256(image) == manifest['output_sha256']
        assert {n: sha256(b) for n, b in files.items()} == manifest['members']
        assert len(members) == len(files) + 3
        assert all(m.mode == 0o755 and m.uid == m.gid == 0 for m in members if m.isfile())
        assert all(n.startswith(('./script/', './tmp/')) for n in files)
        assert files[STAGED] == (stock[DRIVER_MEMBER] if undo else current[STAGED])
        if not undo:
            assert files[LAUNCH] == current[LAUNCH]
        images.append(dict(manifest=manifest, files=encode(files)))
    report['archive_checks'] = 'PASS: decrypted payload/member/mode/driver hashes and scope'
    report['shell_tests'] = 'Not requested; run with --shell-tests on Linux or Windows with WSL'
    if shell_tests:
        with tempfile.TemporaryDirectory(prefix='verify-', dir=Path(output).resolve()) as name:
            fixture = Path(name) / 'fixtures.json'
            fixture.write_text(json.dumps(dict(
                current=encode(current),
                stock=encode({n: stock[n] for n in (START, DAEMON, DRIVER_MEMBER)}),
                images=images,
            )), encoding='utf-8')
            harness = Path(__file__).resolve().parent / 'tests/shell_runtime.py'
            if sys.platform == 'linux':
                command = [sys.executable, str(harness), str(fixture)]
            elif sys.platform == 'win32':
                command = ['wsl', '--exec', 'python3', linux_path(harness), linux_path(fixture)]
            else:
                raise RuntimeError('--shell-tests requires Linux, or Windows with an existing WSL distribution')
            result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=240)
            if result.returncode:
                raise RuntimeError('Shell fixtures failed:\n' + result.stdout + '\n' + result.stderr)
            report['shell_tests'] = json.loads(result.stdout)
    (Path(output) / 'validation.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock', required=True, type=Path)
    parser.add_argument('--driver', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    parser.add_argument('--shell-tests', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.stock, args.driver, args.output, args.shell_tests), indent=2))
