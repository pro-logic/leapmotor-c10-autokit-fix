"""Hash-pinned Thumb Open shim for the exact hardware-exported A15W driver.

No compiler, repacking, guessed code caves, virtual-address changes or OS hooks.
The added code is mapped by RX PT_LOAD but deliberately has no named section.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

SOURCE_SHA = '0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee'
HOOK, RETURN, INSERT, SHIM, GAP = 0x1df00, 0x1df04, 0x732e0, 0x832e0, 0x10000
DISPLACED = bytes.fromhex('d6f810e0')
ASSEMBLY = '''ldr.w lr, [r6, #0x10]
mrs r2, apsr
ldr.w r0, [lr]
movw r1, #2560
cmp r0, r1
bne done
ldr.w r0, [lr, #4]
movw r1, #1440
cmp r0, r1
bne done
movw r0, #1296
str.w r0, [lr, #4]
done:
msr apsr_nzcvq, r2
b.w 0x1df04
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def headers(data):
    h = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
    ph = [list(struct.unpack_from('<8I', data, h[5] + i * h[9])) for i in range(h[10])]
    sh = [list(struct.unpack_from('<10I', data, h[6] + i * h[11])) for i in range(h[12])]
    return h, ph, sh


def assemble(source, address):
    return bytes(Ks(KS_ARCH_ARM, KS_MODE_THUMB).asm(source, address)[0])


def patch(data):
    if sha(data) != SOURCE_SHA:
        raise ValueError('Unknown exact-driver SHA-256; refusing to patch')
    h, ph, sections = headers(data)
    if not (len(data) == 478664 and h[1:4] == (2, 40, 1) and h[5:7] == (52, 477504)
            and h[8:] == (52, 32, 8, 40, 29, 28)):
        raise ValueError('Unsupported ELF header')
    loads = [p for p in ph if p[0] == 1]
    if loads != [[1, 0, 0x10000, 0x10000, INSERT, INSERT, 5, GAP],
                 [1, INSERT, 0x932e0, 0x932e0, 5404, 577600, 6, GAP]]:
        raise ValueError('Unsupported ELF load layout')
    if data[HOOK-0x10000:RETURN-0x10000] != DISPLACED:
        raise ValueError('Unexpected displaced instruction')
    code = assemble(ASSEMBLY, SHIM)
    branch = assemble(f'b.w {SHIM:#x}', HOOK)
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    ins = list(cs.disasm(branch, HOOK))
    tail = list(cs.disasm(code, SHIM))
    if (len(branch) != 4 or len(ins) != 1 or ins[0].mnemonic != 'b.w'
            or int(ins[0].op_str[1:], 0) != SHIM
            or tail[-1].mnemonic != 'b.w' or int(tail[-1].op_str[1:], 0) != RETURN
            or sum(i.size for i in tail) != len(code) or len(code) >= GAP):
        raise ValueError('Branch range or assembly verification failed')
    result = bytearray(data[:INSERT] + code + bytes(GAP-len(code)) + data[INSERT:])
    result[HOOK-0x10000:RETURN-0x10000] = branch
    struct.pack_into('<I', result, 32, h[6]+GAP)
    for i, p in enumerate(ph):
        if p[0] == 1 and p[1] == 0:
            p[4] += len(code)
            p[5] += len(code)
        elif p[1] >= INSERT:
            p[1] += GAP
        struct.pack_into('<8I', result, h[5]+i*h[9], *p)
    for i, s in enumerate(sections):
        if s[4] >= INSERT:
            s[4] += GAP
        struct.pack_into('<10I', result, h[6]+GAP+i*h[11], *s)
    # Lossless audit of every preexisting byte after undoing documented edits.
    restored = bytearray(result[:INSERT] + result[INSERT+GAP:])
    restored[HOOK-0x10000:RETURN-0x10000] = DISPLACED
    restored[32:36] = data[32:36]
    restored[h[5]:h[5]+h[9]*h[10]] = data[h[5]:h[5]+h[9]*h[10]]
    restored[h[6]:h[6]+h[11]*h[12]] = data[h[6]:h[6]+h[11]*h[12]]
    if bytes(restored) != data:
        raise ValueError('Unexpected original-byte change')
    return bytes(result), code, branch
