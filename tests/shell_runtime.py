"""Linux-only disposable shell harness used by verify_usb_boot_logging.py."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

START='./script/start_main_service.sh'
DAEMON='./script/phone_link_deamon.sh'
LAUNCH='./script/c10_start_androidauto_972.sh'
INIT='./script/c10_capture_init.sh'
LOGGER='./script/c10_usb_capture.sh'
PROV='./script/c10_usb_boot_logging.baseline'
STAGED='./tmp/c10_native_driver'
DRIVER='./usr/sbin/ARMadb-driver'


def decode(files): return {name:base64.b64decode(body) for name,body in files.items()}


class FS:
    def __init__(self,root):
        self.root=root
        for name in ('script','usr/sbin','etc/RiddleBoxData','tmp/bin','proc','sys/block','dev','mnt/UPAN/C10_LOGS','mockbin'):
            (root/name).mkdir(parents=True,exist_ok=True)
        self.env=os.environ.copy()
        self.env['PATH']=f'{root}/tmp/bin:{root}/mockbin:'+self.env['PATH']
        self.write('etc/box_product_type',b'A15W')
        self.write('etc/software_version',b'2025.10.15.1127')
        self.write('etc/riddle.conf',b'{"AndroidAutoWidth":1920,"AndroidAutoHeight":972}')
        self.write('proc/mounts',b'')
        self.write('proc/uptime',b'20.00 0.00\n')
        self.write('proc/cmdline',b'mock\n')
        self.mock('sleep','exit 0\n')
        self.mock('pidof','exit 0\n')
        self.mock('df',f'''value=1700
[ ! -e '{root}/low-space' ] || value=0
echo 'Filesystem 1K-blocks Used Available Use% Mounted on'
echo "/dev/root 10000 8000 $value 80% /"
''')
        self.mock('sync',f'''echo flush >> '{root}/flush.log'
[ ! -e '{root}/fail-sync' ]
''')
        self.mock('cp',f'''[ ! -e '{root}/fail-copy' ] || exit 1
if [ -e '{root}/corrupt-copy' ]; then echo corrupt > "$2"; exit 0; fi
exec /usr/bin/cp "$@"
''')
        self.mock('mv',f'''[ ! -e '{root}/fail-move' ] || exit 1
exec /usr/bin/mv "$@"
''')
        self.mock('chmod',f'''[ ! -e '{root}/fail-chmod' ] || exit 1
exec /usr/bin/chmod "$@"
''')
        self.write('usr/sbin/riddleBoxCfg',b'#!/bin/sh\nexit 0\n')

    def path(self,name): return self.root/name.removeprefix('./').lstrip('/')
    def write(self,name,body):
        path=self.path(name)
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o755)
        return path
    def mock(self,name,body): self.write('mockbin/'+name,('#!/bin/sh\n'+body).encode())
    def relocate(self,data):
        text=data.decode()
        for prefix in ('/usr/sbin/','/script/','/mnt/UPAN','/etc/','/tmp/','/proc/','/sys/','/dev/sda1'):
            text=text.replace(prefix,str(self.root)+prefix)
        return text.encode()
    def run(self,data,*args):
        return subprocess.run(['/bin/sh','-s','--',*args],input=self.relocate(data),env=self.env,capture_output=True,timeout=20)
    def copy(self,files):
        for name,body in files.items():
            if name in ('./tmp/once.sh','./tmp/finish.sh'): continue
            self.write(name,body)
    def mounted(self,yes=True):
        self.write('proc/mounts',(f'/dev/sda1 {self.root}/mnt/UPAN vfat rw 0 0\n' if yes else '').encode())


def wait_for(path,timeout=10):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if path.exists(): return
        time.sleep(.02)
    raise AssertionError(f'Missing {path}')


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid,signal.SIGTERM)
        process.wait(timeout=10)


def install_tests(parent,current,stock,images):
    checks=[]
    for profile in ('fresh-stock',):
        candidate=next(i for i in images if i['manifest']['profile']==profile and not i['manifest']['rollback'])
        rollback=next(i for i in images if i['manifest']['profile']==profile and i['manifest']['rollback'])
        fs=FS(parent/('install-'+profile))
        baseline={START:stock[START],DAEMON:stock[DAEMON]} if profile=='fresh-stock' else {n:b for n,b in current.items() if n.startswith('./script/')}
        for name,body in baseline.items(): fs.write(name,body)
        driver_before=stock[DRIVER] if profile=='fresh-stock' else current[STAGED]
        driver=fs.write(DRIVER,driver_before)
        fs.write('mnt/UPAN/C10_LOGS/historical.txt',b'preserve evidence')
        fs.write('script/c10_aa_resolution.sh',b'dormant historical artifact')
        fs.write('script/c10_restore_host_geometry.pending',b'preserve dormant artifact')
        marker=fs.path('mnt/UPAN/AATestMode')
        if profile=='upgrade12': marker.write_bytes(b'preserve marker content')
        marker_before=marker.read_bytes() if marker.exists() else None
        once=candidate['files']['./tmp/once.sh']; finish=candidate['files']['./tmp/finish.sh']
        for name,bad,good in (('etc/box_product_type',b'other',b'A15W'),('etc/software_version',b'other',b'2025.10.15.1127')):
            fs.write(name,bad); assert fs.run(once).returncode!=0
            fs.write(name,good)
        fs.write(DRIVER,b'unknown'); assert fs.run(once).returncode!=0; fs.write(DRIVER,driver_before)
        original_start=fs.path(START).read_bytes()
        fs.write(START,b'unknown startup script')
        assert fs.run(once).returncode!=0,'Wrong profile accepted'
        fs.write(START,original_start)
        fs.write('low-space',b''); assert fs.run(once).returncode!=0; fs.path('low-space').unlink()
        assert fs.run(once).returncode==0
        configuration=fs.path('etc/riddle.conf').read_bytes()
        fs.copy(candidate['files'])
        image=fs.write('mnt/UPAN/A15W_Update.img',b'mock image')
        assert fs.run(finish,'1').returncode!=0
        first=next(n for n in candidate['files'] if n.startswith('./script/'))
        fs.write(first,b'corrupt'); assert fs.run(finish,'0').returncode!=0; fs.write(first,candidate['files'][first])
        fs.write('fail-chmod',b''); assert fs.run(finish,'0').returncode!=0; fs.path('fail-chmod').unlink()
        if profile=='fresh-stock':
            for failure in ('fail-copy','corrupt-copy','fail-sync','fail-move'):
                fs.write(failure,b'')
                assert fs.run(finish,'0').returncode!=0,failure
                assert driver.read_bytes()==driver_before,failure
                assert image.exists(),failure
                fs.path(failure).unlink()
                pending=fs.path(DRIVER+'.c10.pending')
                if pending.exists(): pending.unlink()
        result=fs.run(finish,'0')
        assert result.returncode==0,result.stderr
        assert driver.read_bytes()==current[STAGED]
        assert not image.exists() and fs.path('mnt/UPAN/'+candidate['manifest']['used_name']).exists()
        assert (marker.read_bytes() if marker.exists() else None)==marker_before
        assert fs.path('etc/riddle.conf').read_bytes()==configuration
        assert fs.run(once).returncode==0 and fs.run(rollback['files']['./tmp/once.sh']).returncode==0
        fs.write(PROV,b'upgrade12\n')
        assert fs.run(rollback['files']['./tmp/once.sh']).returncode!=0,'Wrong rollback provenance accepted'
        fs.write(PROV,b'stock\n')
        if profile=='upgrade12': assert STAGED not in candidate['files']
        fs.copy(rollback['files']); image.write_bytes(b'mock rollback')
        result=fs.run(rollback['files']['./tmp/finish.sh'],'0')
        assert result.returncode==0,result.stderr
        assert driver.read_bytes()==driver_before
        for name,body in baseline.items(): assert fs.path(name).read_bytes()==body
        assert not fs.path(PROV).exists()
        if profile=='fresh-stock':
            assert not any(fs.path(n).exists() for n in (LAUNCH,INIT,LOGGER))
        assert fs.path('script/c10_aa_resolution.sh').read_bytes()==b'dormant historical artifact'
        assert fs.path('script/c10_restore_host_geometry.pending').read_bytes()==b'preserve dormant artifact'
        assert fs.path('mnt/UPAN/C10_LOGS/historical.txt').read_bytes()==b'preserve evidence'
        assert (marker.read_bytes() if marker.exists() else None)==marker_before
        assert fs.run(once).returncode==0
        checks.append(profile+': install/reinstall/rollback/reapply, exact driver/scripts, wrong profile and provenance rejected, marker/config/history preserved')
    return checks


def runtime_fs(root,payload):
    fs=FS(root)
    for name,body in payload.items():
        if name.startswith('./script/') and name.endswith('.sh'): fs.write(name,fs.relocate(body))
    fs.write('script/c10_usb_capture.sh',b'#!/bin/sh\necho started > '+str(fs.root/'sampler.started').encode()+b'\n')
    fs.write('usr/sbin/ARMadb-driver',f'''#!/bin/sh
echo driver >> '{fs.root}/app-runs.txt'
echo DRIVER_OUTPUT
'''.encode())
    fs.mock('ARMAndroidAuto',f'''echo $$ > '{fs.root}/aa.pid'
echo AA_OUTPUT
trap 'echo stopped > "{fs.root}/aa-stopped"; exit 23' TERM
if [ -e '{fs.root}/hold-aa' ]; then while :; do /bin/sleep 0.05; done; fi
/bin/sleep 0.25
exit 7
''')
    fs.write('usr/sbin/riddleBoxCfg',f'''#!/bin/sh
/usr/bin/python3 - "$2" "$3" <<'PY'
import json,sys
from pathlib import Path
p=Path('{fs.root}/etc/riddle.conf')
d=json.loads(p.read_text());d[sys.argv[1]]=int(sys.argv[2]);p.write_text(json.dumps(d))
PY
'''.encode())
    fs.mock('sleep',f'''if [ "$1" = 12 ]; then exit 0; fi
if [ "$1" = 0.1 ] && [ -e '{fs.root}/boot-wait-test' ]; then
    echo wait >> '{fs.root}/boot-waits'
    if [ -e '{fs.root}/mount-on-wait' ]; then
        echo '/dev/sda1 {fs.root}/mnt/UPAN vfat rw 0 0' > '{fs.root}/proc/mounts'
    fi
    exit 0
fi
exec /bin/sleep "$@"
''')
    return fs


def exercise_apps(fs,payload,debug):
    start=re.search(rb'runMainProcess\(\) \{.*?\n\}',payload[START],re.S).group()
    result=fs.run(start+b'\nrunMainProcess ARMadb-driver\nwait\n')
    assert result.returncode==0,result.stderr
    assert fs.path('app-runs.txt').exists(),'Driver failed to run'
    assert fs.path('tmp/c10_driver.log').exists()==debug
    if debug: assert b'DRIVER_OUTPUT' in fs.path('tmp/c10_driver.log').read_bytes()
    aa=re.search(rb'RunLinkProcess\(\) \{.*?\n\}',payload[DAEMON],re.S).group()
    result=fs.run(aa+b'\nlinktype=AndroidAuto\nRunLinkProcess\n')
    assert result.returncode==7,(result.returncode,result.stderr)
    assert fs.path('tmp/c10_androidauto.log').exists()==debug
    if debug: assert b'AA_OUTPUT' in fs.path('tmp/c10_androidauto.log').read_bytes()
    assert json.loads(fs.path('etc/riddle.conf').read_text())=={'AndroidAutoWidth':1920,'AndroidAutoHeight':972}
    assert fs.path('tmp/screen_dpi').read_bytes()==bytes([220,0,0,0])


def runtime_tests(parent,payload):
    checks=[]
    for mode in ('no-usb','usb-no-marker','marker-without-mount','marker-directory','enabled','settles','never-mounts'):
        fs=runtime_fs(parent/('runtime-'+mode),payload)
        debug=mode in ('enabled','settles')
        if mode in ('usb-no-marker','marker-directory','enabled'): fs.mounted()
        if mode in ('enabled','settles','never-mounts','marker-without-mount'): fs.write('mnt/UPAN/AATestMode',b'')
        if mode=='marker-directory': fs.path('mnt/UPAN/AATestMode').mkdir()
        if mode in ('settles','never-mounts'):
            fs.path('sys/block/sda').mkdir()
            fs.write('boot-wait-test',b'')
            if mode=='settles': fs.write('mount-on-wait',b'')
        assert fs.run(payload[INIT]).returncode==0
        assert fs.path('tmp/c10_usb_diagnostics.enabled').exists()==debug
        assert fs.path('tmp/c10_usb_diagnostics.decided').exists()
        if debug: wait_for(fs.path('sampler.started'))
        else:
            assert not fs.path('sampler.started').exists()
            assert not list(fs.path('tmp').glob('c10*.log'))
            assert not fs.path('tmp/c10_capture').exists()
            assert fs.run(payload[LOGGER],'1').returncode==0
            assert not fs.path('tmp/c10_capture').exists()
        if mode=='no-usb':
            assert not fs.path('boot-waits').exists()
            fs.mounted();fs.write('mnt/UPAN/AATestMode',b'')
            assert fs.run(payload[INIT]).returncode==0
            assert not fs.path('tmp/c10_usb_diagnostics.enabled').exists(),'Hot plug changed quiet boot'
        if mode=='enabled':
            fs.mounted(False);fs.path('mnt/UPAN/AATestMode').unlink()
            assert fs.run(payload[INIT]).returncode==0
            assert fs.path('tmp/c10_usb_diagnostics.enabled').exists(),'Removal changed fixed boot mode'
        if mode=='never-mounts': assert len(fs.path('boot-waits').read_text().splitlines())==30
        exercise_apps(fs,payload,debug)
        checks.append(mode+': boot decision and actual driver/AA redirection correct; guard/exit status retained')
    # Verify actual guard signal forwarding in the quiet production path.
    fs=runtime_fs(parent/'runtime-signals',payload)
    fs.write('hold-aa',b'')
    process=subprocess.Popen(['/bin/sh',str(fs.path(LAUNCH))],env=fs.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    try:
        wait_for(fs.path('aa.pid'))
        process.terminate(); assert process.wait(timeout=10)==143
        wait_for(fs.path('aa-stopped'))
    finally: stop(process)
    checks.append('quiet guard forwards TERM to AA child and preserves exit143')
    # Real capture worker: publish durable snapshots and retain old evidence.
    fs=runtime_fs(parent/'runtime-capture',payload)
    fs.write('tmp/c10_usb_diagnostics.enabled',b'')
    fs.write('mnt/UPAN/AATestMode',b'');fs.mounted()
    fs.write('mnt/UPAN/C10_LOGS/historical.txt',b'keep')
    fs.write('tmp/c10_driver.log',b'C10-touch ACTIVE\nOpen 2560x1296\n')
    fs.write('tmp/c10_androidauto.log',b'1920x972 DPI220 margin108\n')
    for name in ('ps','dmesg','uname'): fs.mock(name,'echo mock\n')
    fs.mock('od','echo "0000000 000334 000000"\n')
    fast=payload[LOGGER].replace(b'elapsed % 5',b'elapsed % 1')
    assert fs.run(fast,'5').returncode==0
    dest=fs.path('mnt/UPAN/C10_LOGS/capture-1')
    snapshots=list(dest.glob('snapshot-*'));assert 1<=len(snapshots)<=3
    latest=dest/(dest/'LATEST.txt').read_text().strip()
    assert (latest/'SNAPSHOT_READY.txt').exists()
    assert b'C10-touch ACTIVE' in (latest/'c10_driver.log').read_bytes()
    assert fs.path('mnt/UPAN/C10_LOGS/historical.txt').read_bytes()==b'keep'
    # New RAM workspace for independent failed-flush run, without deleting any evidence.
    failed=payload[LOGGER].replace(b'WORK=/tmp/c10_capture',b'WORK=/tmp/c10_capture_failed')
    fs.write('fail-sync',b'')
    assert fs.run(failed,'1').returncode==0
    dest2=fs.path('mnt/UPAN/C10_LOGS/capture-2')
    assert not (dest2/'LATEST.txt').exists() and not list(dest2.glob('snapshot-*'))
    fs.path('fail-sync').unlink()
    checks.append('diagnostic worker: synced publication, three-snapshot retention, failed-flush withholding and history preserved')
    # Default unlimited mode continues bounding logs beyond the old1800 limit.
    fs.mounted(False)
    fs.write('tmp/c10_driver.log',b'x'*3145728)
    beyond=payload[LOGGER].replace(b'WORK=/tmp/c10_capture',b'WORK=/tmp/c10_capture_long').replace(b'elapsed=0\n',b'elapsed=1801\n')
    process=subprocess.Popen(['/bin/sh','-s','--','0'],stdin=subprocess.PIPE,env=fs.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    try:
        process.stdin.write(fs.relocate(beyond));process.stdin.close()
        wait_for(fs.path('tmp/c10_capture_long/limits.txt'))
        assert process.poll() is None
        assert fs.path('tmp/c10_driver.log').stat().st_size<=2097152
    finally: stop(process)
    checks.append('debug boot: continuous size bounding past1800 iterations, including after USB removal')
    return checks


def main():
    fixture=Path(sys.argv[1]).resolve()
    parent=fixture.parent
    data=json.loads(fixture.read_text())
    current,stock=decode(data['current']),decode(data['stock'])
    images=[dict(manifest=item['manifest'],files=decode(item['files'])) for item in data['images']]
    for image in images:
        for name,body in image['files'].items():
            if name.endswith('.sh'): subprocess.run(['/bin/sh','-n'],input=body,check=True,capture_output=True)
    payload=next(i['files'] for i in images if i['manifest']['profile']=='fresh-stock' and not i['manifest']['rollback'])
    results=install_tests(parent,current,stock,images)+runtime_tests(parent,payload)
    print(json.dumps(dict(environment='Linux, real /bin/sh processes and signals; all paths relocated into disposable workspace',checks=results)))


if __name__=='__main__': main()
