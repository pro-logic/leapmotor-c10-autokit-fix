"""Actual paired-archive checks and disposable Linux installer/failure simulation.

The reusable API takes the generated pair. The legacy CLI uses a source-generated
ELF stand-in to exercise packaging mechanics without authorizing native behavior.
"""
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
from generic_archive import assemble_pair, verify_pair
from generic_plan import SOURCES
from tests.test_generic import native_fixture
from verify_generic_runtime import ORACLES, linux_path

HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


LINUX_HARNESS = r'''
import base64,inspect,json,re,sys,tempfile
from pathlib import Path
sys.path.insert(0,sys.argv[2])
from tests import shell_runtime as stable
fixture=Path(sys.argv[1]);data=json.loads(fixture.read_text())
workspace=tempfile.TemporaryDirectory(prefix='c10-package-matrix-')
work=Path(workspace.name)
decode=lambda files:{k:base64.b64decode(v) for k,v in files.items()}
stock=decode(data['stock']);current=decode(data['current'])
images=[dict(manifest=i['manifest'],files=decode(i['files'])) for i in data['images']]
version=data['version'].encode()
class FS(stable.FS):
 def __init__(self,root):
  super().__init__(root);self.write('etc/software_version',version)
 def relocate(self,data):
  prefixes=('/usr/sbin/','/script/','/mnt/UPAN','/etc/','/tmp/','/proc/','/sys/','/dev/sda1')
  return re.sub('|'.join(re.escape(prefix) for prefix in prefixes),lambda match:str(self.root)+match.group(),data.decode()).encode()
namespace=dict(stable.__dict__);namespace['FS']=FS
test_source=inspect.getsource(stable.install_tests)
assert test_source.count("b'2025.10.15.1127'")==1
test_source=test_source.replace("b'2025.10.15.1127'",repr(version))
exec(test_source,namespace)
checks=namespace['install_tests'](work,current,stock,images)
patch=next(i['files'] for i in images if not i['manifest']['rollback'])
rollback=next(i['files'] for i in images if i['manifest']['rollback'])
def base(name):
 fs=FS(work/name)
 for p in (stable.START,stable.DAEMON,stable.DRIVER):fs.write(p,stock[p])
 return fs
once=patch['./tmp/once.sh'];finish=patch['./tmp/finish.sh']
for mode in ('foreign-provenance','unknown-pending','pending-link','helper-directory','malformed-space'):
 fs=base(mode)
 if mode=='foreign-provenance':fs.write(stable.PROV,b'foreign')
 elif mode=='unknown-pending':fs.write(stable.DRIVER+'.c10.pending',b'unknown')
 elif mode=='pending-link':fs.path(stable.DRIVER+'.c10.pending').symlink_to(fs.path(stable.DRIVER))
 elif mode=='helper-directory':fs.path(stable.LOGGER).mkdir()
 elif mode=='malformed-space':fs.mock('df',"printf 'Filesystem Available\n/dev/root invalid\n'\n")
 assert fs.run(once).returncode!=0,mode
 assert fs.path(stable.DRIVER).read_bytes()==stock[stable.DRIVER]
 checks.append(mode+': refuses before persistent-driver changes')
fs=base('known-partial')
fs.write(stable.START,patch[stable.START]);fs.write(stable.INIT,patch[stable.INIT])
assert fs.run(once).returncode==0
fs.copy(patch);fs.write('mnt/UPAN/A15W_Update.img',b'fixture update')
assert fs.run(finish,'0').returncode==0
checks.append('known partial original/desired script/helper mixture recovers without accepting unknown bytes')
fs=base('postcommit-flush-failure')
assert fs.run(once).returncode==0
fs.copy(patch);fs.write('mnt/UPAN/A15W_Update.img',b'fixture update')
counter=str(fs.root/'sync-count')
fs.mock('sync',f"n=$(cat '{counter}' 2>/dev/null || echo 0)\nn=$((n+1))\necho $n > '{counter}'\n[ $n -ne 2 ]\n")
assert fs.run(finish,'0').returncode!=0
assert fs.path(stable.DRIVER).read_bytes()==current[stable.STAGED]
assert fs.path('mnt/UPAN/A15W_Update.img').exists()
assert not fs.path('mnt/UPAN/C10_LOGS/INSTALLED.txt').exists()
fs.mock('sync','exit 0\n')
assert fs.run(once).returncode==0
assert fs.run(finish,'0').returncode==0
checks.append('postcommit flush failure withholds receipt; known committed bytes allow retry')
fs=base('exact-file-modes')
for candidate in images:
 assert fs.run(candidate['files']['./tmp/once.sh']).returncode==0
 fs.copy(candidate['files']);fs.write('mnt/UPAN/A15W_Update.img',b'fixture update')
 assert fs.run(candidate['files']['./tmp/finish.sh'],'0').returncode==0
 for name in (stable.START,stable.DAEMON):
  assert fs.path(name).stat().st_mode&0o777==candidate['manifest']['member_modes'][name],(name,oct(fs.path(name).stat().st_mode&0o777))
 assert fs.path(stable.DRIVER).stat().st_mode&0o777==candidate['manifest']['persistent_driver_mode']
checks.append('install and rollback preserve each stock driver/startup executable mode exactly')
print(json.dumps(dict(status='PASS',level='Linux real /bin/sh installer/failure simulation; disposable paths; '+data['native_payload'],checks=checks)))
'''


def verify_package_pair(image, pair, output, shell_tests=True, *, native_payload='supplied generated native driver bytes; payload is not executed'):
    """Verify both actual images and simulate installation of their exact bytes.

    This checks archive/installer behavior; the caller independently validates
    native behavior before exporting or describing the pair as compatible.
    """
    output = Path(output)
    stock, files = inventory(image)
    archives = verify_pair(image, pair)
    require(pair['unpatch']['files']['./tmp/c10_native_driver'] == files['usr/sbin/ARMadb-driver'], 'Rollback packed driver differs')
    for member in ('script/start_main_service.sh', 'script/phone_link_deamon.sh'):
        require(pair['unpatch']['files']['./' + member] == files[member], 'Rollback script differs')
    for which in ('patch', 'unpatch'):
        item = pair[which]
        require(item['manifest']['members'] == {n: sha256(b) for n, b in item['files'].items()}, 'Package member hash differs')
    result=dict(status='PASS',image_sha256=sha256(image),version=stock['version'], archive_validation=archives,
        baseline_id=pair['baseline_id'],identity=pair['identity'],patch_manifest=pair['patch']['manifest'],unpatch_manifest=pair['unpatch']['manifest'],
        source_sha256={name:sha256((HERE/name).read_bytes()) for name in SOURCES},python=sys.version,platform=platform.platform(),
        native_payload=native_payload,shell_tests=dict(status='not requested'),
        validation_scope='actual encrypted pair, exact stock rollback and installer mechanics; native execution is validated separately',
        native_generation_authorized_by_this_check=False, hardware_tested=False)
    if shell_tests:
        output.mkdir(parents=True,exist_ok=False)
        encode=lambda mapping:{k:base64.b64encode(v).decode() for k,v in mapping.items()}
        payload=dict(stock=encode({'./'+k:v for k,v in files.items() if k in ('script/start_main_service.sh','script/phone_link_deamon.sh','usr/sbin/ARMadb-driver')}),
            current=encode(pair['patch']['files']),version=stock['version'],native_payload=native_payload,
            images=[dict(manifest=pair[k]['manifest'],files=encode(pair[k]['files'])) for k in ('patch','unpatch')])
        data=output/'payload.json';data.write_text(json.dumps(payload),encoding='utf-8')
        harness=output/'package_matrix.py';harness.write_text(LINUX_HARNESS,encoding='utf-8',newline='\n')
        command=['python3',str(harness),str(data),str(HERE)] if os.name!='nt' else ['wsl','--exec','python3',linux_path(harness),linux_path(data),linux_path(HERE)]
        process=subprocess.run(command,capture_output=True,text=True,timeout=180)
        (output/'shell.stdout.log').write_text(process.stdout,encoding='utf-8')
        (output/'shell.stderr.log').write_text(process.stderr,encoding='utf-8')
        require(process.returncode==0,'Linux installer matrix failed; inspect saved shell logs')
        result['shell_tests']=json.loads(process.stdout)
    return result


def verify(path, fixture, output, shell_tests=False):
    image = Path(path).read_bytes()
    require(sha256(image) == ORACLES[fixture]['image'], 'Independent package verifier requires exact selected stock fixture')
    pair = assemble_pair(image, native_fixture())
    result = verify_package_pair(image, pair, output, shell_tests,
        native_payload='source-generated ELF test fixture only; not a native fix or modified vendor ELF')
    result.update(fixture=fixture, generation_allowed=False, installable_images_emitted=False)
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock',required=True,type=Path)
    parser.add_argument('--fixture',required=True,choices=tuple(ORACLES))
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--shell-tests',action='store_true')
    args=parser.parse_args()
    if args.output.exists():parser.error('Refusing to overwrite evidence directory')
    report=verify(args.stock,args.fixture,args.output,args.shell_tests)
    args.output.mkdir(parents=True,exist_ok=True)
    with (args.output/'package-validation.json').open('x',encoding='utf-8') as stream:
        json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(status=report['status'],fixture=args.fixture,shell_tests=report['shell_tests'],output=str(args.output.resolve())),indent=2))
