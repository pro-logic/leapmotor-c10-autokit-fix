"""Stock-to-fixed C10 AutoKit overlay and its paired stock-file unpatch."""
import json

from firmware import md5, sha256, write_package
from runtime_scripts import (
    BASELINE, DAEMON, DRIVER, DRIVER_MEMBER, INIT, LAUNCH, LOGGER, PACKED_SHA,
    PROVENANCE, START, STAGED, STOCK_SHA, runtime,
)


def check_file(name, allowed, optional=False):
    hashes = '|'.join(sorted({md5(body) for body in allowed}))
    check = f'''current=$(md5sum {name} | awk '{{print $1}}')
case "$current" in {hashes}) ;; *) fail 'Unknown baseline file: {name}' ;; esac'''
    return f'if [ -e {name} ]; then\n{check}\nfi' if optional else check


def package(current, stock, undo, output):
    desired = {**runtime(stock), PROVENANCE: BASELINE}
    originals = {START: stock[START], DAEMON: stock[DAEMON]}
    final_driver = stock[DRIVER_MEMBER] if undo else current[STAGED]
    payload = {**(originals if undo else desired), STAGED: final_driver}

    # Permit known files for reinstall and partial-copy recovery, never another
    # project's modified baseline. There is no development-build upgrade path.
    checks = []
    for name in (START, DAEMON, LAUNCH, INIT, LOGGER, PROVENANCE):
        allowed = [d[name] for d in (originals, desired) if name in d]
        checks.append(check_file(name[1:], allowed, optional=name not in originals))
    drivers = [stock[DRIVER_MEMBER], current[STAGED]]
    checks.append(check_file(DRIVER, drivers))
    checks.append(f'''if [ -e {DRIVER}.c10.pending ]; then
    pending=$(md5sum {DRIVER}.c10.pending | awk '{{print $1}}')
    case "$pending" in {'|'.join(md5(b) for b in drivers)}) ;; *) fail 'Unknown pending driver; preserve for inspection' ;; esac
fi''')
    checks.append('''available=$(df -k /usr/sbin | awk 'NR==2 {print $4}')
case "$available" in ''|*[!0-9]*) fail 'Cannot establish root space';; esac
[ "$available" -ge 640 ] || fail 'Insufficient free root space'
''')
    checks.append("[ ! -e /script/c10_aa_resolution.enabled ] || fail 'Old geometry experiment still enabled'")

    driver_md5 = md5(final_driver)
    steps = f'''cp /tmp/c10_native_driver {DRIVER}.c10.pending || fail 'Cannot stage persistent driver'
[ "$(md5sum {DRIVER}.c10.pending | awk '{{print $1}}')" = {driver_md5} ] || fail 'Staged driver mismatch'
chmod 755 {DRIVER}.c10.pending || fail 'Cannot set driver permissions'
sync || fail 'Cannot flush staged driver'
mv -f {DRIVER}.c10.pending {DRIVER} || fail 'Cannot commit driver'
sync || fail 'Cannot flush committed driver'
[ "$(md5sum {DRIVER} | awk '{{print $1}}')" = {driver_md5} ] || fail 'Final driver hash mismatch'
echo 'Driver MD5: {driver_md5}; reboot before runtime mode is evaluated'
'''
    if undo:
        paths = ' '.join(n[1:] for n in (PROVENANCE, INIT, LOGGER, LAUNCH))
        steps += f"rm -f {paths} || fail 'Cannot remove C10 AutoKit Fix helpers'\n"

    directory = output / ('unpatch' if undo else 'patch')
    action = 'C10 AutoKit Fix: restore stock files' if undo else 'C10 AutoKit Fix: install from stock'
    used = 'A15W_C10_AutoKit_Unpatch.used' if undo else 'A15W_C10_AutoKit_Fix.used'
    manifest = write_package(
        payload, '\n'.join(checks), False, output_directory=directory,
        action_label=action, used_name=used,
        enforcement_description='Original stock behavior' if undo else 'Conditional Open/touch fix, 1920x972 session guard and AA DPI220',
        finish_steps=steps,
    )
    manifest.update(
        project='c10-autokit-fix', profile='stock', rollback=undo, used_name=used,
        diagnostics='stock defaults' if undo else 'USB mounted plus regular AATestMode at boot; mode fixed until reboot',
        driver_sha256=sha256(final_driver), driver_md5=driver_md5,
        original_driver_sha256=PACKED_SHA, driver_replaced=True,
        projection_binaries_modified=True, open_handling_modified=not undo,
        touch_coordinates_modified=not undo, input_channel_modified=False,
        dpi_modified=False, forced_aa_dpi=None if undo else 220,
        runtime_guard_sha256=None if undo else sha256(current[LAUNCH]),
        installer_preserves_AATestMode=True, one_time_installation_receipt=True,
        requires_reboot=True, minimum_free_root_kib=640,
        stock_baseline_image_sha256=STOCK_SHA, hardware_tested=False,
    )
    if undo:
        manifest['aa_content_size'] = None
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest
