"""Gated AA touch shift, preserving the validated Open correction.

Empirical correction, not a measured 72-pixel calibration. Only raw host Open
2560x1440 arms the shift. A raw 2560x1296 Open (Show profile) disarms it.
"""
from __future__ import annotations

import json
import struct

import driver_layout as base
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

STATE = 0x120320
STATE_SIZE = 32
OPEN = base.SHIM
TOUCH = 0x83380
LOG = 0x83480
STRINGS = 0x83500
TOUCH_HOOK, TOUCH_RETURN = 0x1fae2, 0x1fae6
LOG_HOOK = 0x1df82
SHIFT = 500
HOOKS = {base.HOOK:base.DISPLACED, TOUCH_HOOK:bytes.fromhex('94ed027a'),
         LOG_HOOK:bytes.fromhex('4af0a7fc')}


def address(reg,value):
    return f'movw {reg}, #{value & 65535}\nmovt {reg}, #{value >> 16}\n'


def make_code(data):
    stock_format = data[0x6e67f-0x10000:].split(b'\0',1)[0]
    expected = b'%s : w(%d) h(%d) frameRate(%d) iBoxversion(%02x) iPhoneWorkMode(%s) VideoType(%s)\n'
    if stock_format != expected: raise ValueError('Unexpected Open log format')
    active = b'C10-touch ACTIVE y=-500/10000 rawOpen=2560x1440; '+stock_format+b'\0'
    bypass = b'C10-touch BYPASS; '+stock_format+b'\0'
    bypass_va = (STRINGS+len(active)+3)&~3
    open_source = 'ldr.w lr, [r6, #0x10]\nmrs r2, apsr\n'+address('r3',STATE)+'''
ldr.w r0, [lr]
str r0, [r3, #4]
ldr.w r1, [lr, #4]
str r1, [r3, #8]
movw r1, #2560
cmp r0, r1
bne disable
ldr.w r0, [lr, #4]
movw r1, #1440
cmp r0, r1
bne disable
movw r0, #1296
str.w r0, [lr, #4]
movs r0, #1
b store
disable:
movs r0, #0
store:
str r0, [r3]
msr apsr_nzcvq, r2
b.w 0x1df04
'''
    touch_source = 'push.w {r0, r1, r2, r3, ip}\nmrs r2, apsr\n'+address('r3',STATE)+f'''
ldr r0, [sp, #0x9c]
cmp r0, #9
bne bypass
ldr r0, [r3]
cmp r0, #1
bne bypass
ldr r0, [r4, #8]
movw r1, #10000
cmp r0, r1
bhi bypass
str r0, [r3, #16]
subs.w r0, r0, #{SHIFT}
bcs nonnegative
movs r0, #0
nonnegative:
str r0, [r3, #20]
ldr r1, [r3, #12]
add.w r1, r1, #1
str r1, [r3, #12]
vmov s14, r0
b done
bypass:
vldr s14, [r4, #8]
ldr r1, [r3, #24]
add.w r1, r1, #1
str r1, [r3, #24]
done:
msr apsr_nzcvq, r2
pop.w {{r0, r1, r2, r3, ip}}
b.w {TOUCH_RETURN:#x}
'''
    # Tail-call the original logger with unchanged r0/r1/r3/stack/return address.
    # Only r2 (format) and caller-saved ip/flags change before the existing call.
    log_source = address('ip',STATE)+'''
ldr.w ip, [ip]
cmp.w ip, #1
bne bypass
'''+address('r2',STRINGS)+'''b.w 0x688d4
bypass:
'''+address('r2',bypass_va)+'''b.w 0x688d4
'''
    chunks = [(OPEN,open_source),(TOUCH,touch_source),(LOG,log_source)]
    assembled = [(va,base.assemble(source,va)) for va,source in chunks]
    limits = (TOUCH,LOG,STRINGS)
    for (va,code),limit in zip(assembled,limits):
        if va+len(code)>limit: raise ValueError('Code slot overflow')
        ins=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB).disasm(code,va))
        if sum(i.size for i in ins)!=len(code): raise ValueError('Incomplete disassembly')
    size = (bypass_va+len(bypass)-OPEN+3)&~3
    blob = bytearray(size)
    for va,code in assembled: blob[va-OPEN:va-OPEN+len(code)]=code
    blob[STRINGS-OPEN:STRINGS-OPEN+len(active)]=active
    blob[bypass_va-OPEN:bypass_va-OPEN+len(bypass)]=bypass
    return bytes(blob),chunks,assembled


def patch(data):
    # Reuse the original source pin/layout validation, without changing the reference Open algorithm.
    open_only,_,_=base.patch(data)
    h,ph,sections=base.headers(data)
    rw=[p for p in ph if p[0]==1 and p[6]==6][0]
    if rw[2]+rw[5]!=STATE: raise ValueError('Unexpected original BSS end')
    for va,before in HOOKS.items():
        if data[va-0x10000:va-0x10000+4]!=before:
            raise ValueError(f'Unexpected hook bytes at {va:#x}')
    blob,sources,chunks=make_code(data)
    result=bytearray(open_only)
    result[base.INSERT:base.INSERT+base.GAP]=blob+bytes(base.GAP-len(blob))
    patches={base.HOOK:base.assemble(f'b.w {OPEN:#x}',base.HOOK),
             TOUCH_HOOK:base.assemble(f'b.w {TOUCH:#x}',TOUCH_HOOK),
             LOG_HOOK:base.assemble(f'bl {LOG:#x}',LOG_HOOK)}
    for va,code in patches.items():
        ins=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB).disasm(code,va))
        target={base.HOOK:OPEN,TOUCH_HOOK:TOUCH,LOG_HOOK:LOG}[va]
        if len(code)!=4 or len(ins)!=1 or int(ins[0].op_str[1:],0)!=target:
            raise ValueError('Hook branch range verification failed')
        result[va-0x10000:va-0x10000+4]=code
    _,newph,_=base.headers(result)
    for index,p in enumerate(newph):
        if p[0]==1 and p[1]==0:
            p[4]=p[5]=base.INSERT+len(blob)
        if p[0]==1 and p[6]==6: p[5]+=STATE_SIZE
        struct.pack_into('<8I',result,h[5]+index*h[9],*p)
    restored=bytearray(result[:base.INSERT]+result[base.INSERT+base.GAP:])
    for va,before in HOOKS.items(): restored[va-0x10000:va-0x10000+4]=before
    restored[32:36]=data[32:36]
    restored[h[5]:h[5]+h[9]*h[10]]=data[h[5]:h[5]+h[9]*h[10]]
    restored[h[6]:h[6]+h[11]*h[12]]=data[h[6]:h[6]+h[11]*h[12]]
    if restored!=data: raise ValueError('Unexpected original-byte mutation')
    return bytes(result),blob,sources,chunks,patches
