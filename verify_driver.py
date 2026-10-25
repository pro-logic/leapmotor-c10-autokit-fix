"""Independent ELF inspection and Unicorn state/gesture/log-ABI validation."""
from __future__ import annotations

import io
import json
import random
import struct
import sys

sys.dont_write_bytecode=True
import driver_patch as build
from tests import arm_harness as harness
from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *

REGS=harness.REGS
DREGS=[getattr(sys.modules[__name__],f'UC_ARM_REG_D{i}') for i in range(16)]


def elf_check(original,patched,manifest):
    a,b=ELFFile(io.BytesIO(original)),ELFFile(io.BytesIO(patched))
    assert a.num_segments()==b.num_segments()==8 and a.num_sections()==b.num_sections()==29
    for key,value in a.header.items():
        expected=value+build.base.GAP if key=='e_shoff' else value
        assert b.header[key]==expected,key
    for x,y in zip(a.iter_segments(),b.iter_segments()):
        for key,value in x.header.items():
            expected=value
            if key=='p_offset' and value>=build.base.INSERT: expected+=build.base.GAP
            if x['p_type']=='PT_LOAD' and x['p_offset']==0 and key in ('p_filesz','p_memsz'):
                expected+=manifest['added_rx_bytes']
            if x['p_type']=='PT_LOAD' and x['p_flags']==6 and key=='p_memsz': expected+=32
            assert y[key]==expected,(key,x.header,y.header)
        if y['p_type']=='PT_LOAD':
            assert y['p_offset']%y['p_align']==y['p_vaddr']%y['p_align']
            assert y['p_filesz']<=y['p_memsz'] and y['p_offset']+y['p_filesz']<=len(patched)
            if y['p_flags']==6:
                assert x.data()==y.data()
                assert x['p_vaddr']+x['p_memsz']==build.STATE
                assert y['p_vaddr']+y['p_memsz']==build.STATE+32
    for x,y in zip(a.iter_sections(),b.iter_sections()):
        assert x.name==y.name
        for key,value in x.header.items():
            expected=value+build.base.GAP if key=='sh_offset' and value>=build.base.INSERT else value
            assert y[key]==expected,(x.name,key)
        if x['sh_type']!='SHT_NOBITS':
            expected=bytearray(x.data())
            if x.name=='.text':
                for va,hook in manifest['hooks'].items():
                    offset=int(va,16)-x['sh_addr']
                    expected[offset:offset+4]=bytes.fromhex(hook['after'])
            assert y.data()==expected,x.name
    loads=[p for p in b.iter_segments() if p['p_type']=='PT_LOAD']
    assert loads[0]['p_vaddr']+loads[0]['p_memsz']<loads[1]['p_vaddr']
    assert loads[0]['p_vaddr']<=build.OPEN<build.STRINGS<loads[0]['p_vaddr']+loads[0]['p_filesz']
    assert loads[0]['p_flags']==5 and loads[1]['p_flags']==6


def machine(data,seed=0):
    uc,areas=harness.machine(data,(2560,1440,30,5,0x4000,11,5),28,seed)
    if len(data)>478664:
        # Only the combined touch fix has these bytes inside PT_LOAD memsz. The page itself
        # is mapped for both images, but stock initial state must not be reused.
        uc.mem_write(build.STATE,bytes(32))
    uc.reg_write(UC_ARM_REG_C1_C0_2,0x00f00000)
    uc.reg_write(UC_ARM_REG_FPEXC,0x40000000)
    for index,reg in enumerate(DREGS): uc.reg_write(reg,0x1234567800000000+index)
    return uc,areas


def run_to(uc,start,stops,count=300):
    def stop(uc,address,size,ctx):
        if address in stops: uc.emu_stop()
    hook=uc.hook_add(UC_HOOK_CODE,stop)
    uc.emu_start(start|1,0,count=count)
    uc.hook_del(hook)
    assert uc.reg_read(UC_ARM_REG_PC) in stops,(hex(start),hex(uc.reg_read(UC_ARM_REG_PC)))


def do_open(uc,width,height,length=28):
    uc.mem_write(harness.PAYLOAD,struct.pack('<7I',width,height,30,5,0x4000,11,5))
    uc.mem_write(harness.MSG+4,struct.pack('<I',length))
    uc.reg_write(UC_ARM_REG_R6,harness.MSG)
    run_to(uc,0x1def8,(0x1df38,0x1f7d6))


def do_touch(uc,x,y,channel=9,phase=0,pointer=0,seed=0,direct=False):
    uc.mem_write(harness.PAYLOAD+4,struct.pack('<ii',x,y))
    uc.reg_write(UC_ARM_REG_SP,harness.STACK+0x2000)
    uc.mem_write(harness.STACK+0x2088,struct.pack('<I',channel))
    uc.mem_write(harness.STACK+0x2090,struct.pack('<I',harness.MSG+0x200))
    uc.reg_write(UC_ARM_REG_R3,harness.MSG+0x200)
    uc.reg_write(UC_ARM_REG_R4,harness.PAYLOAD)
    uc.reg_write(UC_ARM_REG_R5,pointer)
    uc.reg_write(UC_ARM_REG_R10,phase)
    uc.reg_write(UC_ARM_REG_CPSR,((seed&31)<<27)|0x30)
    before_regs=[uc.reg_read(reg) for reg in REGS]
    before_vfp=[uc.reg_read(reg) for reg in DREGS]
    before_payload=bytes(uc.mem_read(harness.MSG,0x4000))
    before_stack=bytes(uc.mem_read(harness.STACK,0x4000))
    before_rw=bytes(uc.mem_read(0x932e0,577600))
    run_to(uc,build.TOUCH_HOOK if direct else 0x1fad2,(build.TOUCH_RETURN if direct else 0x1fb08,))
    after_regs=[uc.reg_read(reg) for reg in REGS]
    after_vfp=[uc.reg_read(reg) for reg in DREGS]
    assert bytes(uc.mem_read(harness.PAYLOAD+4,8))==struct.pack('<ii',x,y)
    assert bytes(uc.mem_read(0x932e0,577600))==before_rw,'Original writable state changed'
    after_stack=bytearray(uc.mem_read(harness.STACK,0x4000))
    after_stack[0x2000-20:0x2000]=before_stack[0x2000-20:0x2000]
    assert after_stack==before_stack,'Stack changed outside saved-register scratch'
    if direct:
        assert before_regs==after_regs,'Direct touch hook changed integer registers/APSR'
        for index,(old,new) in enumerate(zip(before_vfp,after_vfp)):
            if index!=7: assert old==new,('VFP corruption',index)
        assert before_vfp[7]>>32==after_vfp[7]>>32,'Touch X bits in S15 changed'
        after_payload=bytes(uc.mem_read(harness.MSG,0x4000))
        assert after_payload==before_payload
        bits=uc.reg_read(UC_ARM_REG_S14)
        return struct.unpack('<i',struct.pack('<I',bits))[0]
    value=bytes(uc.mem_read(harness.MSG+0x200,28))
    assert struct.unpack_from('<2I',value)==(24,11)
    assert struct.unpack_from('<I',value,24)[0]==phase|(pointer<<8)
    assert struct.unpack_from('<d',value,8)[0]==x/10000.0
    return struct.unpack_from('<d',value,16)[0]


def log_check(uc,active):
    rng=random.Random(103)
    for reg in REGS[:13]: uc.reg_write(reg,rng.getrandbits(32))
    uc.reg_write(UC_ARM_REG_SP,harness.STACK+0x2000)
    saved={reg:uc.reg_read(reg) for reg in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_SP)}
    stack=bytes(uc.mem_read(harness.STACK,0x4000))
    run_to(uc,build.LOG_HOOK,(0x688d4,))
    assert all(uc.reg_read(reg)==value for reg,value in saved.items())
    assert uc.reg_read(UC_ARM_REG_LR)==(build.LOG_HOOK+4)|1
    assert bytes(uc.mem_read(harness.STACK,0x4000))==stack
    ptr=uc.reg_read(UC_ARM_REG_R2)
    fmt=bytes(uc.mem_read(ptr,200)).split(b'\0',1)[0]
    assert (b'C10-touch ACTIVE' if active else b'C10-touch BYPASS') in fmt
    assert fmt.count(b'%')==7


def verify(original,patched):
    result,blob,sources,chunks,patches=build.patch(original)
    manifest=dict(output_sha256=build.base.sha(result),added_rx_bytes=len(blob),
        hooks={hex(va):dict(after=code.hex()) for va,code in patches.items()})
    assert build.base.sha(patched)==manifest['output_sha256']
    assert build.patch(original)[0]==patched
    elf_check(original,patched,manifest)
    try: build.patch(original[:-1]+bytes([original[-1]^1]))
    except ValueError: pass
    else: raise AssertionError('Unknown source accepted')
    open_only=build.base.patch(original)[0]
    assert build.base.sha(open_only)=='13c930235120c5bb1e36df5c6fa8bad46b8feb4e21bb17c52500ee18f33a0d0a'
    open_cases=0
    for seed in range(32):
        for width,height,length in ((2560,1440,28),(2560,1296,28),(1920,1440,28),(2560,1080,28),(0,0,28),(2560,1440,0),(2560,1440,27),(2560,1440,29)):
            old,oldareas=machine(open_only,seed)
            new,newareas=machine(patched,seed)
            do_open(old,width,height,length); do_open(new,width,height,length)
            assert [old.reg_read(r) for r in REGS]==[new.reg_read(r) for r in REGS]
            assert bytes(old.mem_read(0x932e0,577600))==bytes(new.mem_read(0x932e0,577600))
            for address in (harness.MSG,harness.STACK):
                assert bytes(old.mem_read(address,0x4000))==bytes(new.mem_read(address,0x4000))
            state=struct.unpack('<8I',bytes(new.mem_read(build.STATE,32)))
            assert state[:3]==((int((width,height)==(2560,1440)),width,height) if length==28 else (0,0,0))
            open_cases+=1
    touch_cases=0
    for seed in range(32):
        for active,channel in ((0,9),(1,9),(1,6),(1,11),(1,13),(1,15),(1,161)):
            for y in (-1,0,1,499,500,501,5000,9500,10000,10001):
                uc,_=machine(patched,seed)
                uc.mem_write(build.STATE,struct.pack('<I',active))
                expected=max(0,y-500) if active and channel==9 and 0<=y<=10000 else y
                actual=do_touch(uc,3456,y,channel,seed=seed,direct=True)
                assert actual==expected,(active,channel,y,actual,expected)
                touch_cases+=1
    full_cases=0
    for active in (0,1):
        for phase in (0,1,2):
            for pointer in (0,1,7):
                for y in (0,500,5000,10000,-1,10001):
                    uc,_=machine(patched,17)
                    uc.mem_write(build.STATE,struct.pack('<I',active))
                    expected=max(0,y-500) if active and 0<=y<=10000 else y
                    actual=do_touch(uc,9123,y,phase=phase,pointer=pointer,seed=17)
                    assert actual==expected/10000.0
                    full_cases+=1
    # One process: boot -> bad startup -> repeated gesture -> Show -> startup
    # -> malformed Open -> other dimensions. No accumulated or double shifts.
    uc,_=machine(patched,3)
    assert do_touch(uc,5000,6000)==.6
    for width,height,expected in ((2560,1440,.55),(2560,1440,.55),(2560,1296,.6),(2560,1440,.55),(1920,1440,.6)):
        do_open(uc,width,height)
        assert do_touch(uc,5000,6000)==expected
        assert do_touch(uc,5000,6000)==expected
        log_check(uc,expected==.55)
    do_open(uc,2560,1440)
    do_open(uc,2560,1296,27)
    assert do_touch(uc,5000,6000)==.55
    log_check(uc,True)
    do_open(uc,2560,1296)
    assert do_touch(uc,5000,6000)==.6
    log_check(uc,False)
    report=dict(status='PASS',hardware_tested=False,patched_sha256=build.base.sha(patched),
        differential_open_cases=open_cases,direct_touch_cases=touch_cases,full_normalization_gesture_cases=full_cases,
        all_nzcvq_combinations=True,non_aa_channels_pass_through=True,original_payload_coordinates_unchanged=True,
        original_rw_bytes_unchanged=True,registers_vfp_and_stack_checked=True,
        state_sequence='boot / startup / repeated touches / Show / malformed Open / non-C10 / Show',
        log_abi='original logger arguments, stack and return address preserved; ACTIVE/BYPASS verified',
        elf='independent program/section inspection; original RW data unchanged; new zero BSS32 only')
    return report
