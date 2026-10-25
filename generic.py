"""Experimental A15W inventory and native candidate analysis; no image emission."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from firmware import sha256
from generic_analysis import analyze_driver
from generic_inventory import MAX_IMAGE, inventory
from generic_packing import inspect_packed
from generic_plan import draft_plan
from runtime_scripts import STOCK_SHA, PACKED_SHA, START, DAEMON
from driver_layout import SOURCE_SHA

C10_PROFILE = dict(
    raw_open=[2560, 1440], effective_open=[2560, 1296],
    aa_content=[1920, 972], aa_dpi=220,
    aa_touch=dict(integer_range=[0, 10000], subtract_y=500, clamp_min=0),
    calibration='empirical C10 HD setup; need on another firmware has not been established',
)


def read_bounded(path, limit):
    with Path(path).open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f'Input exceeds supported size limit: {path}')
    return data


def pairing(stock, packed, driver, receipt=None):
    identity = dict(image_sha256=stock['image_sha256'], packed_driver_sha256=sha256(packed),
                    unpacked_driver_sha256=sha256(driver))
    known = (identity['image_sha256'], identity['packed_driver_sha256'], identity['unpacked_driver_sha256']) == (
        STOCK_SHA, PACKED_SHA, SOURCE_SHA)
    result = dict(**identity, status='documented-reference' if known else 'unverified',
                  method='previous October hardware export; stable reference pins' if known else None)
    if receipt is not None:
        if not isinstance(receipt, dict) or receipt.get('schema') != 'c10-unpack-attestation-v1':
            raise ValueError('Unsupported unpack attestation schema')
        for key, expected in identity.items():
            if receipt.get(key) != expected:
                raise ValueError(f'Unpack attestation does not match input: {key}')
        if not isinstance(receipt.get('method'), str) or not receipt['method'].strip():
            raise ValueError('Unpack attestation must describe its method')
        result.update(attestation=receipt,
                      attestation_limit='Hash binding records a claim; it does not independently prove unpacking')
        if not known:
            result.update(status='matching-attestation-unverified', method=receipt['method'])
    return result


def analyze(image, driver=None, receipt=None):
    stock, files = inventory(image)
    packed = files['usr/sbin/ARMadb-driver']
    report = dict(
        schema='c10-generic-analysis-v1', experimental=True, mode='analysis-only',
        inventory=stock, c10_profile=C10_PROFILE, patchable=False, hardware_tested=False,
        packed_driver=dict(bytes=len(packed), sha256=sha256(packed),
                           upx_marker_present=b'UPX!' in packed,
                           decoding='complete native decoding not performed; see bounded structure inspection'),
        startup_analysis=dict(
            start_custom_init_anchor_count=files[START[2:]].count(b'#run custom init shell\n'),
            start_logging_anchor_count=files[START[2:]].count(b'\tif [ -e /etc/log_com ]; then'),
            daemon_launch_anchor_count=files[DAEMON[2:]].count(b'\t\t\tARMAndroidAuto\n'),
            status='inventory only; unique text anchors do not prove launch/control-flow semantics',
        ),
        blockers=[],
    )
    try:
        report['packed_driver']['structure'] = inspect_packed(packed)
    except ValueError as error:
        report['packed_driver']['structure'] = dict(status='unsupported', reason=str(error),
                                                    complete_native_input=False, patchable=False)
    if driver is None:
        if receipt is not None:
            raise ValueError('--provenance requires --driver')
        report['blockers'].append('exact unpacked driver and verified packed-to-unpacked provenance required')
    else:
        report['pairing'] = pairing(stock, packed, driver, receipt)
        if report['pairing']['status'] != 'documented-reference':
            report['blockers'].append('packed-to-unpacked pairing has not been independently verified')
        try:
            report['native'] = analyze_driver(driver)
        except ValueError as error:
            report['native'] = dict(sha256=sha256(driver), bytes=len(driver), unsupported=str(error), patchable=False)
        if not report['native'].get('unique_candidates'):
            report['blockers'].append('need exactly one supported Open candidate and one touch candidate')
        report['blockers'].append('complete control/data-flow, channel, ABI, insertion and independent emulation proof pending')
    report['blockers'].append('stock-derived runtime and paired installer validation pending for generic packaging')
    report['status'] = 'incomplete-analysis; installable output refused'
    return report, files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('analyze', 'extract-driver', 'draft-plan'))
    parser.add_argument('--stock', required=True, type=Path)
    parser.add_argument('--driver', type=Path, help='Candidate exact unpacked ELF; never substitutes another input')
    parser.add_argument('--provenance', type=Path, help='Optional unpack attestation; hash binding is not verification')
    parser.add_argument('--output', type=Path, help='New report/draft file, or NEW directory for extract-driver')
    args = parser.parse_args()
    try:
        if args.command == 'extract-driver' and (args.driver or args.provenance):
            raise ValueError('extract-driver accepts only --stock and --output')
        image = read_bounded(args.stock, MAX_IMAGE)
        driver = read_bounded(args.driver, 16 * 1024 * 1024) if args.driver else None
        receipt = json.loads(read_bounded(args.provenance, 65536)) if args.provenance else None
        report, files = analyze(image, driver, receipt)
        stock = report['inventory']
        base = Path('dist/generic') / f'{stock["version"]}-{stock["image_sha256"][:12]}'
        if args.command == 'extract-driver':
            output = args.output or base / 'unpack-input'
            # A new directory prevents accidental loss of any previous export.
            output.mkdir(parents=True, exist_ok=False)
            (output / 'ARMadb-driver.packed').write_bytes(files['usr/sbin/ARMadb-driver'])
            request = dict(schema='c10-unpack-request-v1', product=stock['product'], version=stock['version'],
                           image_sha256=stock['image_sha256'], **report['packed_driver'],
                           packed_driver_sha256=report['packed_driver']['sha256'],
                           status='packed bytes extracted only; unpacking and provenance still required')
            (output / 'request.json').write_text(json.dumps(request, indent=2) + '\n', encoding='utf-8')
            print(json.dumps(request, indent=2))
        else:
            artifact = draft_plan(report, files, driver) if args.command == 'draft-plan' else report
            output = args.output or base / ('proof-draft.json' if args.command == 'draft-plan' else 'analysis.json')
            output.parent.mkdir(parents=True, exist_ok=True)
            # Refuse overwrite, including --output pointing at either input.
            with output.open('x', encoding='utf-8') as stream:
                stream.write(json.dumps(artifact, indent=2) + '\n')
            print(json.dumps(dict(report=str(output.resolve()), status=report['status'],
                                  patchable=False, blockers=report['blockers']), indent=2))
    except (ValueError, OSError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
