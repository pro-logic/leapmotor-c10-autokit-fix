"""Per-input installer/unpatch payload derivation, entirely in memory.

This does not audit native generation, serialize an archive, write an ELF or
approve installation. A future builder must independently satisfy those gates.
"""
from __future__ import annotations

import json
import math

from firmware import md5, sha256
from generic_analysis import Driver
from generic_inventory import inventory
from generic_runtime import START, DAEMON, INIT, LAUNCH, LOGGER, derive_runtime

PROVENANCE = 'script/c10_autokit_fix.baseline'
STAGED = 'tmp/c10_native_driver'
DRIVER = '/usr/sbin/ARMadb-driver'
DRIVER_MEMBER = 'usr/sbin/ARMadb-driver'
OWNED = (INIT, LAUNCH, LOGGER, PROVENANCE)


def _regular(path):
    return f"[ -f {path} ] && [ ! -L {path} ] || fail 'Expected regular project/baseline file: {path}'"


def _check(path, bodies, optional=False):
    allowed = '|'.join(sorted({md5(body) for body in bodies}))
    body = _regular(path) + f'''
current=$(md5sum {path} | awk '{{print $1}}')
case "$current" in {allowed}) ;; *) fail 'Unknown baseline file: {path}' ;; esac'''
    return f'if [ -e {path} ] || [ -L {path} ]; then\n{body}\nfi' if optional else body


def _once(product, version, baseline, allowed, drivers, minimum):
    checks = [_check('/' + name, bodies, optional=name not in (START, DAEMON))
              for name, bodies in allowed.items()]
    checks += [_check(DRIVER, drivers), _check(DRIVER + '.c10.pending', drivers, optional=True)]
    checks += [f'''available=$(df -k /usr/sbin | awk 'NR==2 {{print $4}}')
case "$available" in ''|*[!0-9]*) fail 'Cannot establish root space';; esac
[ "$available" -ge {minimum} ] || fail 'Insufficient free root space'
[ ! -e /script/c10_aa_resolution.enabled ] || fail 'Old geometry experiment still enabled'
[ ! -e /script/c10_bottom_bar_fix ] || fail 'Different geometry experiment is enabled' ''']
    return f'''#!/bin/sh
mkdir -p /mnt/UPAN/C10_LOGS || exit 1
exec >> /mnt/UPAN/C10_LOGS/install.log 2>&1
fail() {{ echo "FAILED: $*"; sync; exit 1; }}
echo 'C10 AutoKit Fix generic baseline {baseline}'
date
[ "$(cat /etc/box_product_type)" = {product} ] || fail 'Requires {product}'
[ "$(cat /etc/software_version)" = {version} ] || fail 'Requires firmware {version}'
[ -x /usr/sbin/riddleBoxCfg ] || fail 'Missing riddleBoxCfg'
{chr(10).join(checks)}
echo 'Baseline checks passed; persistent driver is unchanged until verified finish commit'
grep -E 'AndroidAutoWidth|AndroidAutoHeight' /etc/riddle.conf
echo 6 > /tmp/update_progress
sync || fail 'Cannot flush preflight'
exit 0
'''.encode()


def _finish(payload, target, undo, baseline, image_sha, version, member_modes, driver_mode):
    checks = []
    for member, body in payload.items():
        path = '/' + member
        checks += [_regular(path), f'''[ "$(md5sum {path} | awk '{{print $1}}')" = {md5(body)} ] || fail 'Copy verification failed: {path}' ''']
    chmod_scripts = '\n'.join(f"chmod {member_modes[name]:o} /{name} || fail 'Cannot set script permissions'"
                              for name in payload if name.endswith('.sh'))
    action = 'restore stock files' if undo else 'install from stock'
    used = 'A15W_C10_AutoKit_Generic_Unpatch.used' if undo else 'A15W_C10_AutoKit_Generic_Fix.used'
    cleanup = ''
    if undo:
        paths = ' '.join('/' + name for name in OWNED)
        cleanup = f"rm -f {paths} || fail 'Cannot remove owned C10 helpers'\n"
        for name in OWNED:
            cleanup += f"[ ! -e /{name} ] && [ ! -L /{name} ] || fail 'Owned helper remains: /{name}'\n"
    return f'''#!/bin/sh
exec >> /mnt/UPAN/C10_LOGS/install.log 2>&1
fail() {{ echo "FAILED: $*"; sync; exit 1; }}
[ "$1" = 0 ] || fail "Updater copy failed: $1"
{chr(10).join(checks)}
{chmod_scripts}
[ ! -L {DRIVER}.c10.pending ] || fail 'Pending driver is a symbolic link'
cp /tmp/c10_native_driver {DRIVER}.c10.pending || fail 'Cannot stage persistent driver'
{_regular(DRIVER + '.c10.pending')}
[ "$(md5sum {DRIVER}.c10.pending | awk '{{print $1}}')" = {md5(target)} ] || fail 'Staged driver mismatch'
chmod {driver_mode:o} {DRIVER}.c10.pending || fail 'Cannot set driver permissions'
sync || fail 'Cannot flush staged driver'
mv -f {DRIVER}.c10.pending {DRIVER} || fail 'Cannot commit driver'
sync || fail 'Cannot flush committed driver'
{_regular(DRIVER)}
[ "$(md5sum {DRIVER} | awk '{{print $1}}')" = {md5(target)} ] || fail 'Final driver hash mismatch'
{cleanup}echo 'Driver committed for next boot; reboot before runtime mode is evaluated'
if [ -e /mnt/UPAN/A15W_Update.img ]; then
    mv /mnt/UPAN/A15W_Update.img /mnt/UPAN/{used} || fail 'Cannot rename update image'
fi
printf '%s\\n' 'C10 AutoKit Fix generic: {action}' 'baseline={baseline}' 'stock_image_sha256={image_sha}' 'firmware={version}' 'expected_driver_sha256={sha256(target)}' 'reboot_required=yes' > /mnt/UPAN/C10_LOGS/INSTALLED.txt || fail 'Cannot write installation receipt'
sync || fail 'Cannot flush installation receipt'
echo 'SUCCESS: C10 AutoKit Fix generic {action}; baseline {baseline}'
exit 0
'''.encode(), used


def derive_packages(image, generated_driver):
    """Derive both in-memory file maps from their own exact stock archive.

    A valid ELF is necessary for staging but is not evidence of an audited patch.
    The returned manifest therefore always withholds generation authority.
    """
    if not isinstance(generated_driver, bytes) or not 0 < len(generated_driver) <= 16 * 1024 * 1024:
        raise ValueError('Unsupported generated-driver bounds')
    Driver(generated_driver)
    stock, files = inventory(image)
    original_modes = {name: int(stock['members'][name]['mode'], 8) for name in (START, DAEMON, DRIVER_MEMBER)}
    if any(mode not in (0o755, 0o775) for mode in original_modes.values()):
        raise ValueError('Unsupported stock executable mode; expected755 or775 for exact rollback')
    scripts, script_contract = derive_runtime(files)
    identity = dict(schema='c10-generic-baseline-v1', product=stock['product'], version=stock['version'],
        stock_image_sha256=stock['image_sha256'], packed_driver_sha256=sha256(files[DRIVER_MEMBER]),
        generated_driver_sha256=sha256(generated_driver),
        stock_script_sha256={name: sha256(files[name]) for name in (START, DAEMON)},
        stock_file_modes=original_modes,
        derived_runtime_sha256={name: sha256(body) for name, body in scripts.items()},
        vehicle_profile='C10 raw2560x1440 effective2560x1296 AA1920x972 DPI220 conditionalAA-Y500')
    identity_text = json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()
    baseline = sha256(identity_text)
    provenance = b'c10-autokit-fix:generic-baseline-v1\n' + identity_text + b'\n'
    desired = dict(scripts, **{PROVENANCE: provenance})
    originals = {name: files[name] for name in (START, DAEMON)}
    drivers = (files[DRIVER_MEMBER], generated_driver)
    allowed = {name: [mapping[name] for mapping in (originals, desired) if name in mapping]
               for name in (START, DAEMON, INIT, LAUNCH, LOGGER, PROVENANCE)}
    minimum = max(640, math.ceil(max(map(len, drivers)) / 1024) + 128)
    once = _once(stock['product'], stock['version'], baseline, allowed, drivers, minimum)
    result = {}
    for undo in (False, True):
        target = files[DRIVER_MEMBER] if undo else generated_driver
        payload = dict(originals if undo else desired, **{STAGED: target})
        member_modes = {name: original_modes.get(name, original_modes[DRIVER_MEMBER] if name == STAGED else 0o755)
                        for name in payload}
        finish, used = _finish(payload, target, undo, baseline, stock['image_sha256'], stock['version'],
                               member_modes, original_modes[DRIVER_MEMBER])
        payload.update({'tmp/once.sh': once, 'tmp/finish.sh': finish})
        member_modes.update({'tmp/once.sh': 0o755, 'tmp/finish.sh': 0o755})
        # Archive-style names are returned only as in-memory records.
        members = {'./' + name: body for name, body in payload.items()}
        result['unpatch' if undo else 'patch'] = dict(files=members, manifest=dict(
            schema='c10-generic-package-draft-v1', profile='stock', rollback=undo, baseline_id=baseline,
            requires_model=stock['product'], requires_version=stock['version'],
            stock_baseline_image_sha256=stock['image_sha256'], original_driver_sha256=sha256(files[DRIVER_MEMBER]),
            driver_sha256=sha256(target), driver_md5=md5(target), used_name=used,
            members={name: sha256(body) for name, body in members.items()},
            member_modes={'./' + name: mode for name, mode in member_modes.items()},
            stock_file_modes=original_modes, persistent_driver_mode=original_modes[DRIVER_MEMBER],
            minimum_free_root_kib=minimum, requires_reboot=True, one_time_installation_receipt=True,
            installer_preserves_AATestMode=True, preserves_settings_logs_and_unrelated_files=True,
            runtime_digest='md5sum for stock utility compatibility; SHA256 identities in host manifest/provenance',
            diagnostics='stock defaults' if undo else 'mounted USB plus regular AATestMode at boot; fixed until reboot',
            script_contract=script_contract, native_generation_proof='not evaluated by installer derivation',
            generation_allowed=False, installable_images_emitted=False, hardware_tested=False))
    return dict(schema='c10-generic-package-pair-draft-v1', identity=identity, baseline_id=baseline, **result,
                generation_allowed=False, installable_images_emitted=False, hardware_tested=False)
