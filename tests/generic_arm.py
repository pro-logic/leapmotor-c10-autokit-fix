"""ELF-derived ARM test machine for unmodified discovered semantic slices.

Only malloc/free/realloc and explicitly supplied I/O targets are mocked. Actual
packet object code executes. This is neither OS emulation nor hardware evidence.
No generation code, October layout constants, or stock hashes are imported here.
"""
import io
import struct
from functools import lru_cache

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                               UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC, UC_ARM_REG_CPSR, UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC)

from generic_analysis import Driver
from generic_flow import plt_import


@lru_cache(maxsize=4)
def imported_veneers(data):
    driver = Driver(data)
    section = driver.elf.get_section_by_name('.plt')
    imports = {}
    if section:
        for va in range(section['sh_addr'], section['sh_addr'] + section['sh_size'] - 11, 4):
            item = plt_import(driver, va)
            if item:
                imports[va] = item['symbol']
    return imports


class Machine:
    def __init__(self, data):
        self.driver = Driver(data)
        self.imports = imported_veneers(data)
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.writable = []
        mapped, high = set(), 0
        for segment in ELFFile(io.BytesIO(data)).iter_segments():
            if segment['p_type'] != 'PT_LOAD':
                continue
            lo = segment['p_vaddr'] & ~4095
            hi = (segment['p_vaddr'] + segment['p_memsz'] + 4095) & ~4095
            pages = set(range(lo, hi, 4096))
            if mapped & pages:
                raise ValueError('Emulator rejects overlapping LOAD pages')
            mapped |= pages
            flags = segment['p_flags']
            permissions = (1 if flags & 4 else 0) | (2 if flags & 2 else 0) | (4 if flags & 1 else 0)
            self.uc.mem_map(lo, hi - lo, permissions)
            self.uc.mem_write(segment['p_vaddr'], segment.data())
            high = max(high, hi)
            if flags & 2:
                self.writable.append((segment['p_vaddr'], segment['p_memsz']))
        self.scratch = (high + 65535) & ~65535
        if self.scratch + 0x20000 >= 2**32:
            raise ValueError('Emulator scratch address overflow')
        self.uc.mem_map(self.scratch, 0x20000)
        self.stack = self.scratch + 0x10000
        self.payload = self.scratch + 0x1000
        self.message = self.scratch + 0x2000
        self.heap = self.scratch + 0x4000
        self.stop = self.scratch + 0x1f000
        self.reg(UC_ARM_REG_SP, self.stack)
        self.reg(UC_ARM_REG_C1_C0_2, 0x00f00000)
        self.reg(UC_ARM_REG_FPEXC, 0x40000000)
        self.reg(UC_ARM_REG_LR, self.stop | 1)
        self.allocations, self.events = {}, []

    def reg(self, name, value=None):
        if value is None:
            return self.uc.reg_read(name)
        self.uc.reg_write(name, value)

    def write(self, va, data):
        self.uc.mem_write(va, bytes(data))

    def read(self, va, size):
        return bytes(self.uc.mem_read(va, size))

    def word(self, va, value=None):
        if value is None:
            return struct.unpack('<I', self.read(va, 4))[0]
        self.write(va, struct.pack('<I', value & 0xffffffff))

    def allocate(self, size):
        if not 0 < size <= 4096 or self.heap + size > self.scratch + 0xb000:
            raise ValueError('Emulator allocation budget exceeded')
        result = self.heap
        self.heap += (size + 15) & ~15
        self.allocations[result] = size
        return result

    def rw_snapshot(self):
        return [self.read(va, size) for va, size in self.writable]

    def run(self, start, stops, mocked_returns=(), limit=6000):
        stops = set(stops)
        mocked = set(mocked_returns)
        self.visited = []
        # Resolve imported ARM veneers once, using only actual relocation data.
        imports = self.imports

        def caller_clobbers():
            for reg, value in ((UC_ARM_REG_R1, 0x11223344), (UC_ARM_REG_R2, 0x55667788),
                               (UC_ARM_REG_R3, 0x99aabbcc), (UC_ARM_REG_R12, 0xddeeff00)):
                self.reg(reg, value)
            self.reg(UC_ARM_REG_CPSR, (self.reg(UC_ARM_REG_CPSR) & 0x07ffffff) | 0x88000000)

        def execute(uc, address, size, context):
            self.visited.append(address)
            if address in stops:
                uc.emu_stop()
                return
            if address in mocked:
                self.events.append(dict(target=address, mock='explicit I/O return'))
                self.reg(UC_ARM_REG_R0, 0)
                caller_clobbers()
                self.reg(UC_ARM_REG_PC, self.reg(UC_ARM_REG_LR))
                return
            if address in imports:
                symbol = imports[address]
                if symbol == 'malloc':
                    self.reg(UC_ARM_REG_R0, self.allocate(self.reg(UC_ARM_REG_R0)))
                elif symbol == 'free':
                    pointer = self.reg(UC_ARM_REG_R0)
                    if pointer and pointer not in self.allocations:
                        raise ValueError('Unknown emulator free input')
                    self.allocations.pop(pointer, None)
                    self.reg(UC_ARM_REG_R0, 0)
                elif symbol == 'realloc':
                    old, size = self.reg(UC_ARM_REG_R0), self.reg(UC_ARM_REG_R1)
                    new = self.allocate(size)
                    if old:
                        if old not in self.allocations:
                            raise ValueError('Unknown emulator realloc input')
                        self.write(new, self.read(old, min(self.allocations[old], size)))
                    self.reg(UC_ARM_REG_R0, new)
                else:
                    raise ValueError(f'Unmocked import in semantic slice: {symbol}')
                self.events.append(dict(target=address, mock='host allocator', symbol=symbol))
                caller_clobbers()
                self.reg(UC_ARM_REG_PC, self.reg(UC_ARM_REG_LR))

        hook = self.uc.hook_add(UC_HOOK_CODE, execute)
        try:
            self.uc.emu_start(start | 1, 0, count=limit)
        finally:
            self.uc.hook_del(hook)
        if self.reg(UC_ARM_REG_PC) not in stops:
            raise ValueError(f'Semantic slice did not reach stop: {self.reg(UC_ARM_REG_PC):#x}')

    def packet(self, object_va):
        size, kind = self.word(object_va + 4), self.word(object_va + 8)
        if size > 4096:
            raise ValueError('Emulated packet exceeds fixture bound')
        ptr = self.word(object_va + 16)
        return dict(size=size, type=kind, payload=self.read(ptr, size) if size else b'')


def open_copy(data, candidate, fields, length):
    m = Machine(data)
    payload = struct.pack('<7I', *fields)
    m.write(m.payload, payload)
    m.word(m.message + 4, length)
    m.word(m.message + 16, m.payload)
    m.reg(UC_ARM_REG_R6, m.message)
    before = m.rw_snapshot()
    m.run(candidate['validation_va'], (candidate['copy_end_va'], candidate['malformed_branch_va']))
    return m, before


def touch_dispatch(data, candidate, evidence, selector, raw_action, pointer, x, y, initializer):
    routing = evidence['routing']
    variable = next(e['variable_va'] for r in routing['routes'] for e in r['selector_edges'] if e['variable_va'] is not None)
    if routing['selector_setup_va'] is None:
        raise ValueError('No unique touch selector setup')
    m = Machine(data)
    m.reg(UC_ARM_REG_R0, m.stack + routing['output_pointer_stack_offset'] - 16)
    m.run(initializer, (m.stop,))  # execute actual packet initializer
    m.reg(UC_ARM_REG_SP, m.stack)
    m.word(variable, selector)
    m.write(m.payload, bytes(4) + struct.pack('<ii', x, y) + bytes(4))
    m.reg(UC_ARM_REG_R4, m.payload)
    m.reg(UC_ARM_REG_R5, pointer)
    m.reg(UC_ARM_REG_R10, raw_action)
    # Change flags without switching register banks (especially the saved SP).
    m.reg(UC_ARM_REG_CPSR, (m.reg(UC_ARM_REG_CPSR) & 0x07ffffff) | 0xa8000000)
    m.initial_rw = m.rw_snapshot()
    m.run(routing['selector_setup_va'], (candidate['normalization_end_va'],))
    packet = m.packet(m.stack + routing['output_pointer_stack_offset'] - 16)
    return m, packet
