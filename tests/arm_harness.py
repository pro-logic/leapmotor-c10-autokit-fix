"""Independent PT_LOAD mapping and register fixtures (adapted from upstream work)."""
import io
import random
import struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import *

REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
        UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_CPSR]
MSG, PAYLOAD, STACK = 0x200000, 0x201000, 0x300000
ORIGINAL, EFFECTIVE = 0x11f40c, 0x11f3d4


def machine(data, fields, length, seed):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    elf = ELFFile(io.BytesIO(data))
    areas = []
    for seg in elf.iter_segments():
        if seg['p_type'] != 'PT_LOAD': continue
        lo = seg['p_vaddr'] & ~4095
        hi = (seg['p_vaddr']+seg['p_memsz']+4095) & ~4095
        uc.mem_map(lo, hi-lo, (1 if seg['p_flags']&4 else 0) | (2 if seg['p_flags']&2 else 0) | (4 if seg['p_flags']&1 else 0))
        uc.mem_write(seg['p_vaddr'], seg.data())
        if seg['p_flags'] & 2:
            # Nonzero writable state exposes unintended stores and BSS assumptions.
            uc.mem_write(seg['p_vaddr'], bytes([0xa7])*seg['p_memsz'])
            areas.append((seg['p_vaddr'], seg['p_memsz']))
    uc.mem_map(MSG, 0x4000)
    uc.mem_map(STACK, 0x4000)
    uc.mem_write(MSG, b'\x6b'*0x4000)
    uc.mem_write(STACK, b'\x93'*0x4000)
    uc.mem_write(MSG+4, struct.pack('<I', length))
    uc.mem_write(MSG+0x10, struct.pack('<I', PAYLOAD))
    uc.mem_write(PAYLOAD, struct.pack('<7I', *fields))
    rng = random.Random(seed)
    uc.reg_write(UC_ARM_REG_CPSR, ((seed & 31) << 27) | 0x30)
    for reg in REGS[:-1]: uc.reg_write(reg, rng.getrandbits(32))
    uc.reg_write(UC_ARM_REG_R6, MSG)
    uc.reg_write(UC_ARM_REG_SP, STACK+0x2000)
    areas += [(MSG, 0x4000), (STACK, 0x4000)]
    return uc, areas
