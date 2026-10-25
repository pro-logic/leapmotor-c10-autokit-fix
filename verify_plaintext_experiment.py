"""Independent plaintext-boundary, CFB relay and hook preservation experiment.

Only in-memory ELF bytes are generated. Actual native preprocessing executes,
with explicit host primitive/diagnostic contracts; no updater image is exported.
"""
import argparse
import json
from pathlib import Path
import struct

from unicorn import arm_const as regs

from firmware import sha256
from generic_analysis import analyze_driver
from generic_plan import HERE, SOURCES
from tests.generic_arm import Machine
from tests.native_experiment import experiment
from verify_message_crypto import case, MARKER, ORACLES
from verify_native_experiment import INTEGER, VFP, seed_machine, verify as verify_hooks
from verify_semantics import require


def relay_checks(original, changed, native, state):
    contract = native['semantic_evidence']['open'][0]['preprocessing'][0]['open_cfb_contract']
    site = contract['cfb_call']['va']
    total = 0
    # Check post-import flags/control state independently of the call's allowed
    # caller clobbers. The stub must preserve exactly what the primitive returned.
    vectors = ((0,1,28,MARKER,2560,1440), (0,1,28,MARKER,2560,1296),
               (0,1,28,MARKER,1920,1080), (1,1,28,MARKER,2560,1440),
               (0,2,28,MARKER,2560,1440), (0,1,27,MARKER,2560,1440),
               (0,1,28,0x55aa55aa,2560,1440), (0,1,29,MARKER,2560,1440))
    for seed in range(32):
        for direction,kind,length,marker,width,height in vectors:
            old,new = Machine(original),Machine(changed)
            for m in (old,new):
                seed_machine(m,seed)
                m.word(m.message,marker)
                m.word(m.message+4,length)
                m.word(m.message+8,kind)
                m.word(m.message+16,m.payload)
                m.write(m.payload,struct.pack('<7I',width,height,30,5,0x4000,11,5))
                m.reg(regs.UC_ARM_REG_R0,m.payload)
                m.reg(regs.UC_ARM_REG_R1,m.payload)
                m.reg(regs.UC_ARM_REG_R2,length)
                m.reg(regs.UC_ARM_REG_R3,m.payload+0x200)
                m.reg(regs.UC_ARM_REG_R4,m.message)
                m.word(m.stack,m.payload+0x300)
                m.word(m.stack+4,m.payload+0x400)
                m.word(m.stack+8,direction)
            new.word(state,seed & 1)
            before = new.rw_snapshot()
            stack = new.read(new.stack-128,256)
            descriptor = new.read(new.message,32)
            def primitive(m):
                require([m.reg(r) for r in (regs.UC_ARM_REG_R0,regs.UC_ARM_REG_R1,regs.UC_ARM_REG_R2,regs.UC_ARM_REG_R3)] ==
                    [m.payload,m.payload,length,m.payload+0x200],'Observer changed CFB register arguments')
                require(struct.unpack('<3I',m.read(m.reg(regs.UC_ARM_REG_SP),12)) ==
                    (m.payload+0x300,m.payload+0x400,direction),'Observer changed CFB stack arguments')
                require(m.reg(regs.UC_ARM_REG_SP) % 8 == 0,'Observer violated import stack alignment')
                result={r:0x12345678+index*0x100+seed for index,r in enumerate(INTEGER[:4]+[regs.UC_ARM_REG_R12])}
                result[regs.UC_ARM_REG_CPSR]=(m.reg(regs.UC_ARM_REG_CPSR)&0x0000ffff)|((seed&31)<<27)|((seed&15)<<16)
                result[regs.UC_ARM_REG_FPSCR]=((seed&31)<<27)|((seed&3)<<22)|(seed&31)
                result[regs.UC_ARM_REG_FPEXC]=(seed&1)<<30
                for index,r in enumerate(VFP):result[r]=(0x12345678abcdef00+index*0x10001+seed)&0xffffffffffffffff
                return result
            for m in (old,new):
                m.run(site,(site+4,),import_handlers={'AES_cfb128_encrypt':primitive})
            require([old.reg(r) for r in INTEGER] == [new.reg(r) for r in INTEGER],'Observer changed returned integer/flags/GE/SP/LR state')
            require([old.reg(r) for r in VFP] == [new.reg(r) for r in VFP],'Observer changed returned VFP state')
            for r in (regs.UC_ARM_REG_FPSCR,regs.UC_ARM_REG_FPEXC):
                require(old.reg(r)==new.reg(r),'Observer changed returned VFP control state')
            admitted=direction==0 and kind==1 and length==28 and marker==MARKER
            matching=admitted and (width,height)==(2560,1440)
            require(new.word(state)==(int(matching) if admitted else seed&1),'Observer gate differs')
            require(new.word(new.payload+4)==(1296 if matching else height),'Observer profile differs')
            require(new.read(new.message,32)==descriptor,'Observer changed descriptor')
            expected=[bytearray(body) for body in before]
            if admitted:
                for index,(va,size) in enumerate(new.writable):
                    if va <= state < state+12 <= va+size:
                        struct.pack_into('<3I',expected[index],state-va,int(matching),width,height)
            require(new.rw_snapshot()==[bytes(body) for body in expected],'Observer changed undeclared writable state')
            after=bytearray(new.read(new.stack-128,256));after[72:128]=stack[72:128]
            require(after==stack,'Observer wrote outside bounded 56-byte scratch')
            total+=1
    return total


def verify(path, fixture):
    original=Path(path).read_bytes();oracle=ORACLES[fixture]
    require(sha256(original)==oracle['sha'],'Independent plaintext experiment needs exact selected fixture')
    native=analyze_driver(original)
    changed,manifest=experiment(original,native,plaintext_safe=True)
    relay=relay_checks(original,changed,native,manifest['state_va'])
    print(f'{fixture}: {relay} CFB relay/preservation cases PASS',flush=True)
    helpers=dispatches=0
    for seed in (0,1,15,0x01020304,0x7fffffff,0x80000000,0xffffffff):
        for active in (-1,0,1,2147483647):
            for marker in (MARKER,0x55aa55aa,MARKER^1):
                for length in (0,1,15,16,17,28,29):
                    case(original,oracle,seed,active,marker,length,machine_data=changed,
                         patch_state=(manifest['state_va'],helpers&1))
                    helpers+=1
    for width,height in ((2560,1440),(2560,1296),(1920,1080),(0,0)):
        for active in (-1,0,1,2147483647):
            for marker in (MARKER,0x55aa55aa,MARKER^1):
                for initial in (0,1):
                    case(original,oracle,active&0xffffffff,active,marker,28,dispatch=True,machine_data=changed,
                         patch_state=(manifest['state_va'],initial),fields=(width,height,30,5,0x4000,11,5))
                    dispatches+=1
    print(f'{fixture}: {helpers} helper and {dispatches} guarded Open-dispatch cases PASS',flush=True)
    hooks=verify_hooks(path,fixture,plaintext_safe=True)
    return dict(status='PASS',fixture=fixture,driver_sha256=sha256(original),manifest=manifest,
                cfb_relay_cases=relay,helper_cases=helpers,guarded_open_dispatch_cases=dispatches,
                hook_checks=hooks,source_sha256={n:sha256((HERE/n).read_bytes()) for n in SOURCES},
                evidence_level='in-memory three-hook experiment plus native preprocessing/dispatch emulation',
                mocks=['native CFB contract via host cryptography; explicit diagnostic/memset mocks',
                       'differential import return-state mock for relay ABI/control preservation',
                       'existing native packet allocator and external I/O mocks'],
                limits=['Unwind, outside-entry and production audited-plan acceptance require independent checks',
                        'No firmware installer, shell matrix or hardware test in this verifier'],
                generation_allowed=False,installable_images_emitted=False,hardware_tested=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--driver',required=True,type=Path)
    p.add_argument('--fixture',required=True,choices=tuple(ORACLES))
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args()
    if a.output.exists():p.error('Refusing existing evidence output')
    result=verify(a.driver,a.fixture)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({k:result[k] for k in ('status','fixture','cfb_relay_cases','helper_cases','guarded_open_dispatch_cases')},indent=2))
