"""Exact stage13 community installer and its paired stock rollback."""
import json

from firmware import FINISH, md5, sha256, write_package
from runtime_scripts import *

def check_file(name,allowed,optional=False):
    hashes='|'.join(sorted({md5(body) for body in allowed}))
    check=f'''current=$(md5sum {name} | awk '{{print $1}}')
case "$current" in {hashes}) ;; *) fail 'Unknown baseline file: {name}' ;; esac'''
    return f'if [ -e {name} ]; then\n{check}\nfi' if optional else check

def package(current,stock,undo,output):
    profile="fresh-stock"
    fresh=profile=='fresh-stock'
    desired=runtime(stock)
    desired[PROVENANCE]=b'stock\n' if fresh else b'upgrade12\n'
    before={START:stock[START],DAEMON:stock[DAEMON]} if fresh else {
        n:b for n,b in current.items() if n.startswith('./script/')}
    payload=dict(before if undo else desired)
    if fresh: payload[STAGED]=stock[DRIVER_MEMBER] if undo else current[STAGED]
    checks=[]
    for name in (START,DAEMON,LAUNCH,INIT,LOGGER,PROVENANCE):
        allowed=[d[name] for d in (before,desired) if name in d]
        checks.append(check_file(name[1:],allowed,optional=name not in before))
    drivers=[stock[DRIVER_MEMBER],current[STAGED]] if fresh else [current[STAGED]]
    checks.append(check_file(DRIVER,drivers))
    if fresh:
        checks.append(f'''if [ -e {DRIVER}.c10.pending ]; then
    pending=$(md5sum {DRIVER}.c10.pending | awk '{{print $1}}')
    case "$pending" in {'|'.join(md5(b) for b in drivers)}) ;; *) fail 'Unknown pending driver; preserve for inspection' ;; esac
fi''')
    space=640 if fresh else 64
    checks.append(f'''available=$(df -k /usr/sbin | awk 'NR==2 {{print $4}}')
case "$available" in ''|*[!0-9]*) fail 'Cannot establish root space';; esac
[ "$available" -ge {space} ] || fail 'Insufficient free root space'
''')
    checks.append("[ ! -e /script/c10_aa_resolution.enabled ] || fail 'Old geometry experiment still enabled'")
    # Preserve the user's AATestMode choice. Installation receipts remain one-time USB output.
    template=FINISH.replace("echo 'SUCCESS: @ACTION@ installed'\n",'').replace(
        'touch /mnt/UPAN/AATestMode',': # Preserve existing AATestMode; never create it automatically').replace(
        "echo '@ACTION@ installed; reboot before testing.' > /mnt/UPAN/C10_LOGS/INSTALLED.txt\nsync\n",
        "echo '@ACTION@ installed; reboot before testing.' > /mnt/UPAN/C10_LOGS/INSTALLED.txt || fail 'Cannot write installation receipt'\nsync || fail 'Cannot flush installation receipt'\necho 'SUCCESS: @ACTION@ installed'\n")
    template=template.replace("rm -f /script/c10_aa_resolution.sh /script/c10_aa_resolution.enabled /script/c10_restore_host_geometry.pending || fail 'Cannot remove obsolete experiment files'",
                              ': # Preserve unrelated retired experiment files')
    steps=''
    if fresh:
        staged_md5=md5(payload[STAGED])
        steps=f'''cp /tmp/c10_native_driver {DRIVER}.c10.pending || fail 'Cannot stage persistent driver'
[ "$(md5sum {DRIVER}.c10.pending | awk '{{print $1}}')" = {staged_md5} ] || fail 'Staged driver mismatch'
chmod 755 {DRIVER}.c10.pending || fail 'Cannot set driver permissions'
sync || fail 'Cannot flush staged driver'
mv -f {DRIVER}.c10.pending {DRIVER} || fail 'Cannot commit driver'
sync || fail 'Cannot flush committed driver'
'''
    final_driver=stock[DRIVER_MEMBER] if fresh and undo else current[STAGED]
    steps+=f'''[ "$(md5sum {DRIVER} | awk '{{print $1}}')" = {md5(final_driver)} ] || fail 'Final driver hash mismatch'
echo 'Driver MD5: {md5(final_driver)}; reboot before runtime mode is evaluated'
'''
    if undo:
        remove=[PROVENANCE]+([INIT,LOGGER,LAUNCH] if fresh else [])
        steps+='rm -f '+' '.join(n[1:] for n in remove)+" || fail 'Cannot remove known stage13 files'\n"
    directory=output/('unpatch' if undo else 'patch')
    action=f'stage13 {profile} '+('rollback to '+('stock' if fresh else 'stage12') if undo else 'USB boot logging')
    used='A15W_C10_13_'+('Stock' if fresh else 'Upgrade')+('_Rollback' if undo else '')+'.used'
    manifest=write_package(payload,'\n'.join(checks),False,output_directory=directory,action_label=action,
        used_name=used,enforcement_description='Original stock behavior' if fresh and undo else 'Exact stage12 touch ELF and unchanged V2/AA220 guard',
        finish_steps=steps,finish_template=template)
    manifest.update(dict(profile=profile,rollback=undo,used_name=used,
        diagnostics='unconditional stage12' if undo and not fresh else 'stock defaults' if undo else 'USB mounted plus regular AATestMode at boot; mode fixed until reboot',
        driver_sha256=sha256(final_driver),driver_md5=md5(final_driver),
        driver_replaced=fresh,stage12_driver_retained=not(fresh and undo),
        projection_binaries_modified=fresh,open_handling_modified=not(fresh and undo),
        touch_coordinates_modified=not(fresh and undo),input_channel_modified=False,dpi_modified=False,
        forced_aa_dpi=None if fresh and undo else 220,
        runtime_guard_sha256=None if fresh and undo else sha256(current[LAUNCH]),
        installer_preserves_AATestMode=True,one_time_installation_receipt=True,requires_reboot=True,
        stock_baseline_image_sha256=STOCK_SHA,
        hardware_tested=False))
    if fresh and undo: manifest['aa_content_size']=None
    (directory/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest
