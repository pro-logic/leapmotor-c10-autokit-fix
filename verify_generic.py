"""Independent real-input annotations for the analysis-only experiment.

These identities and October landmarks are test oracles, never discovery rules.
This checks static candidates, not new native generation or hardware behavior.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from firmware import read_archive, sha256
from generic import analyze, read_bounded


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(october_stock, february_stock, october_driver, reference):
    october = read_bounded(october_stock, 64 * 1024 * 1024)
    february = read_bounded(february_stock, 64 * 1024 * 1024)
    driver = read_bounded(october_driver, 16 * 1024 * 1024)
    require(sha256(october) == '24589f1b71b95d87379ee2a10e130e939cd45c28bcd3ec328499f5bbd2bc477e', 'October fixture differs')
    require(sha256(february) == '5c00b2e47aca6efc15625a1887ed857b1dceac691ff9dde96ac7de2f00adf8f8', 'February fixture differs')
    require(sha256(driver) == '0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee', 'October unpacked fixture differs')
    reports = [analyze(october, driver)[0], analyze(february)[0]]
    native = reports[0]['native']
    require(native['unique_candidates'], 'October needs unique candidates')
    op, touch = native['open_candidates'][0], native['touch_candidates'][0]
    for actual, expected in (
        (op['hook']['va'], 0x1df00), (op['hook']['file_offset'], 0xdf00),
        (op['hook']['original_bytes'], 'd6f810e0'), (op['validation_va'], 0x1def8),
        (op['original_open_va'], 0x11f40c), (op['effective_open_va'], 0x11f3d4),
        (op['format_xref']['format_va'], 0x6e67f), (touch['hook']['va'], 0x1fae2),
        (touch['hook']['original_bytes'], '94ed027a'), (touch['divisor_va'], 0x1fc60),
    ):
        require(actual == expected, f'October annotated landmark differs: {actual!r} != {expected!r}')
    require(reports[1]['packed_driver']['sha256'] == 'baaa1ee60d43ee6a67264bb05dfcb7da9948c386c05a9e7c6be4568408e957cd', 'February packed input differs')
    wrong, _ = analyze(february, driver)
    require(wrong['pairing']['status'] == 'unverified' and not wrong['patchable'], 'Cross-firmware pairing accepted')
    references = {}
    for kind, expected in (
        ('patch', 'fbfa6226cf8e364f2bda352cd9ef255f2e0ecfd5b61a7e2ee532ad3b82d354fb'),
        ('unpatch', '6de11c46e740945c4e0cc93f340409cc358ba84380914bdf71893dd034cad0cf'),
    ):
        data = (Path(reference) / kind / 'A15W_Update.img').read_bytes()
        require(sha256(data) == expected, f'{kind} reference image differs')
        _, _, files = read_archive(data)
        manifest = json.loads((Path(reference) / kind / 'manifest.json').read_text())
        require({n: sha256(b) for n, b in files.items()} == manifest['members'], f'{kind} payload manifest differs')
        references[kind] = dict(sha256=sha256(data), payload_members=len(files))
    return dict(
        status='PASS', level='static input inventory and candidate discovery',
        generic_installable_images_emitted=False, generic_hardware_tested=False,
        october=dict(image_sha256=reports[0]['inventory']['image_sha256'],
                     unpacked_driver_sha256=sha256(driver), open_hook_va=op['hook']['va'], touch_hook_va=touch['hook']['va']),
        february=dict(image_sha256=reports[1]['inventory']['image_sha256'],
                      packed_driver_sha256=reports[1]['packed_driver']['sha256'],
                      native_validation='incomplete: exact verified unpacked input missing'),
        cross_firmware_pairing='unverified, installable output refused', stable_reference_images=references,
    )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--october-stock', required=True, type=Path)
    parser.add_argument('--february-stock', required=True, type=Path)
    parser.add_argument('--october-driver', required=True, type=Path)
    parser.add_argument('--reference', type=Path, default=Path('dist/reference'))
    args = parser.parse_args()
    print(json.dumps(verify(args.october_stock, args.february_stock, args.october_driver, args.reference), indent=2))
