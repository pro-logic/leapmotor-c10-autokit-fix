"""Build the v13 community patch/unpatch from explicit user-supplied originals."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import driver_patch
from firmware import read_archive, sha256
from package_overlay import package
from runtime_scripts import (STOCK_SHA, PACKED_SHA, PATCHED_SHA, DRIVER_MEMBER,
                             STAGED, START, DAEMON, LAUNCH, runtime)
from verify_driver import verify as verify_driver


def read_pinned(path, expected, label):
    data = Path(path).read_bytes()
    actual = sha256(data)
    if actual != expected:
        raise ValueError(f'{label} SHA-256 mismatch: expected {expected}, got {actual}')
    return data


def inputs(stock_path, driver_path):
    image = read_pinned(stock_path, STOCK_SHA, 'Stock firmware')
    original = read_pinned(driver_path, driver_patch.base.SOURCE_SHA, 'Unpacked original driver')
    _, _, stock = read_archive(image)
    if stock.get('./etc/software_version') != b'2025.10.15.1127':
        raise ValueError('Stock software version differs')
    if sha256(stock[DRIVER_MEMBER]) != PACKED_SHA:
        raise ValueError('Original packed driver differs')
    patched, blob, sources, chunks, hooks = driver_patch.patch(original)
    if sha256(patched) != PATCHED_SHA:
        raise ValueError('Patched driver differs from the exact stage12/v13 reference')
    current = {**runtime(stock), STAGED: patched}
    return original, stock, current


def build(stock_path, driver_path, output):
    if not __debug__:
        raise RuntimeError('Do not run Python with -O: verification assertions must be enabled')
    output = Path(output).resolve()
    if output in (Path(stock_path).resolve(), Path(driver_path).resolve()):
        raise ValueError('Output must be a separate directory')
    original, stock, current = inputs(stock_path, driver_path)
    # Emulate the actual driver before writing either installable image.
    report = verify_driver(original, current[STAGED])
    manifests = [package(current, stock, undo, output) for undo in (False, True)]
    report.update(
        inputs={'stock_sha256': STOCK_SHA, 'unpacked_driver_sha256': sha256(original)},
        functional_guard_sha256=sha256(current[LAUNCH]),
        images={m['output']: m['output_sha256'] for m in manifests},
        hardware_evidence='Existing dongle upgrade reported working 2026-10-25; fresh-stock installer untested',
    )
    (output / 'validation.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report, stock, current, manifests


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock', required=True, type=Path, help='Original A15W 2025.10.15.1127 update image')
    parser.add_argument('--driver', required=True, type=Path, help='Exact hardware-unpacked original ARMadb-driver')
    parser.add_argument('--output', type=Path, default=Path('dist'), help='Generated outputs; default: dist')
    return parser.parse_args()


def main():
    args = arguments()
    try:
        report, _, _, _ = build(args.stock, args.driver, args.output)
    except (ValueError, OSError, RuntimeError) as error:
        raise SystemExit(str(error)) from error
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
