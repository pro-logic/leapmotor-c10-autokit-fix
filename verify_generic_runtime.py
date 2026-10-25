"""Independent two-stock script-preservation and disposable Linux runtime checks."""
import argparse
import base64
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from firmware import sha256
from generic_inventory import inventory
from generic_runtime import START, DAEMON, derive_runtime
from generic_plan import SOURCES

HERE = Path(__file__).resolve().parent
ORACLES = {
    'february': dict(image='5c00b2e47aca6efc15625a1887ed857b1dceac691ff9dde96ac7de2f00adf8f8',
        main='850e929a062b35d6187a8db16ffd846a2750f5c5659901b8fc0baf482ef682a9',
        daemon='351410363d9a66cba6619833b6b97d0652e8b0f21c8ec5acd2fac919dedf1403',
        bluetooth='unconditional vendor prelude', cancel_exit=False),
    'october': dict(image='24589f1b71b95d87379ee2a10e130e939cd45c28bcd3ec328499f5bbd2bc477e',
        main='8fa516e8160cba1b73d31e57d1934d1022a27f03a729bf57dd7980257fa4643e',
        daemon='58c53417e908c2e73cc9f9b7ffb10857b8b127f68be0f86a4880926def7dc656',
        bluetooth='readiness-marker gated', cancel_exit=True),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def preservation(original, modified, edits):
    """Independently account for every original and modified source byte."""
    source_position = result_position = 0
    for edit in sorted(edits, key=lambda e: e['source_range']):
        lo, hi = edit['source_range']
        require(source_position <= lo <= hi <= len(original), 'Overlapping or out-of-bounds shell edit')
        unchanged = original[source_position:lo]
        require(modified[result_position:result_position + len(unchanged)] == unchanged, 'Undeclared shell bytes changed')
        result_position += len(unchanged)
        require(sha256(original[lo:hi]) == edit['before_sha256'], 'Shell edit before identity differs')
        length = edit['after_bytes']
        require(sha256(modified[result_position:result_position + length]) == edit['after_sha256'], 'Shell edit after identity differs')
        source_position = hi
        result_position += length
    require(modified[result_position:] == original[source_position:], 'Undeclared trailing shell bytes changed')


LINUX_HARNESS = r'''
import base64,json,re,subprocess,sys
from pathlib import Path
sys.path.insert(0,sys.argv[2])
from tests.shell_runtime import runtime_tests,runtime_fs,wait_for
fixture=Path(sys.argv[1])
payload={k:base64.b64decode(v) for k,v in json.loads(fixture.read_text()).items()}
for body in payload.values():subprocess.run(['/bin/sh','-n'],input=body,check=True,capture_output=True)
checks=runtime_tests(fixture.parent,payload)
for diagnostics in (False,True):
 for bluetooth in (False,True):
  fs=runtime_fs(fixture.parent/('full-daemon-'+str(diagnostics)+'-'+str(bluetooth)),payload)
  fs.path('tmp/lib').mkdir(parents=True,exist_ok=True)
  fs.write('usr/lib/libssl.so.fixture',b'fixture library')
  if diagnostics:
   fs.mounted();fs.write('mnt/UPAN/AATestMode',b'')
  if bluetooth:fs.write('tmp/.bluetoothDaemon_init_done',b'')
  assert fs.run(payload['./script/c10_capture_init.sh']).returncode==0
  fs.mock('hfpd','echo hfpd >> '+str(fs.root/'hfpd-runs')+'\n')
  child=fs.path('mockbin/ARMAndroidAuto').read_bytes().replace(b'exit 7\n',
    b'touch '+str(fs.root/'tmp/.AndroidAuto_daemon_exited').encode()+b'\nexit 7\n')
  fs.write('usr/sbin/ARMAndroidAuto',child)
  run=fs.run(payload['./script/phone_link_deamon.sh'],'AndroidAuto','start')
  assert run.returncode==0,(run.returncode,run.stderr)
  assert fs.path('aa.pid').exists()
  assert not fs.path('tmp/.AndroidAuto_daemon_started').exists()
  assert not fs.path('tmp/.AndroidAuto_daemon_exited').exists()
  assert fs.path('tmp/c10_androidauto.log').exists()==diagnostics
  assert fs.path('tmp/bin/ARMAndroidAuto').read_bytes()==child
  checks.append('full daemon AndroidAuto/start: RAM copy, wait/update path, guard launch, lock/exit cleanup; diagnostics='+str(diagnostics)+' Bluetooth='+str(bluetooth))
 fs=runtime_fs(fixture.parent/('passthrough-'+str(diagnostics)),payload)
 fs.write('tmp/UDiskPassThroughMode',b'')
 main=re.search(rb'runMainProcess\(\) \{.*?\n\}',payload['./script/start_main_service.sh'],re.S).group()
 result=fs.run(main+b'\nrunMainProcess ARMadb-driver\nwait\n')
 assert result.returncode==0,result.stderr
 assert fs.path('tmp/bin/ARMadb-driver').exists()
 assert not fs.path('app-runs.txt').exists()
 checks.append('native-driver passthrough preserves RAM-copy ordering and returns without launch')
print(json.dumps(dict(status='PASS',level='Linux real /bin/sh, processes and signals; disposable paths; mocked projection/hardware boundaries',checks=checks)))
'''


def linux_path(path):
    path = Path(path).resolve()
    if os.name != 'nt':
        return str(path)
    return '/mnt/' + path.drive[0].lower() + '/' + path.as_posix()[3:]


def verify(path, fixture, output, shell_tests=False):
    image = Path(path).read_bytes()
    oracle = ORACLES[fixture]
    require(sha256(image) == oracle['image'], 'Independent runtime verifier requires selected exact stock fixture')
    inv, files = inventory(image)
    require(sha256(files[START]) == oracle['main'] and sha256(files[DAEMON]) == oracle['daemon'], 'Independent original script identities differ')
    scripts, evidence = derive_runtime(files)
    require(evidence['android_auto']['bluetooth'] == oracle['bluetooth'] and
            evidence['android_auto']['cancels_pending_exit_on_start'] == oracle['cancel_exit'], 'Stock-specific daemon behavior differs')
    require(len(evidence['edits']) == 3, 'Unexpected shell edit count')
    for member in (START, DAEMON):
        preservation(files[member], scripts[member], [e for e in evidence['edits'] if e['member'] == member])
    result = dict(status='PASS', fixture=fixture, image_sha256=sha256(image), product=inv['product'], version=inv['version'],
        evidence=evidence, source_sha256={name: sha256((HERE/name).read_bytes()) for name in SOURCES},
        python=sys.version, platform=platform.platform(), shell_tests=dict(status='not requested'),
        limits=['Restricted recognized shell grammar only; other layouts refuse',
                'External vendor program contracts and boot/caller serialization are assumptions',
                'No installer/atomic commit/failure matrix or native-driver generation in this verifier'],
        generation_allowed=False, installable_images_emitted=False, hardware_tested=False)
    if shell_tests:
        output.mkdir(parents=True, exist_ok=False)
        data=output/'payload.json'
        data.write_text(json.dumps({'./'+k: base64.b64encode(v).decode() for k,v in scripts.items()}),encoding='utf-8')
        harness=output/'runtime_matrix.py'
        harness.write_text(LINUX_HARNESS,encoding='utf-8',newline='\n')
        command=['python3', str(harness), str(data), str(HERE)] if os.name!='nt' else [
            'wsl', '--exec', 'python3', linux_path(harness), linux_path(data), linux_path(HERE)]
        process=subprocess.run(command,capture_output=True,text=True,timeout=180)
        (output/'shell.stdout.log').write_text(process.stdout,encoding='utf-8')
        (output/'shell.stderr.log').write_text(process.stderr,encoding='utf-8')
        require(process.returncode==0, 'Linux runtime matrix failed; inspect saved shell logs')
        result['shell_tests']=json.loads(process.stdout)
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock',required=True,type=Path)
    parser.add_argument('--fixture',required=True,choices=tuple(ORACLES))
    parser.add_argument('--output',required=True,type=Path,help='NEW evidence directory')
    parser.add_argument('--shell-tests',action='store_true')
    args=parser.parse_args()
    if args.output.exists():parser.error('Refusing to overwrite evidence directory')
    report=verify(args.stock,args.fixture,args.output,args.shell_tests)
    args.output.mkdir(parents=True,exist_ok=True)
    with (args.output/'runtime-validation.json').open('x',encoding='utf-8') as stream:
        json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(status=report['status'],fixture=args.fixture,shell_tests=report['shell_tests'],output=str(args.output.resolve())),indent=2))
