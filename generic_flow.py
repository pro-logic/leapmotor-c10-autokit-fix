"""Read-only bounded Thumb control flow and ELF-backed ARM PLT resolution.

An unwind range is a traversal boundary, not a complete function/type proof.
Unresolved indirect transfers, outside edges, and overlapping decodes prevent
closed-graph claims. Calls are overapproximated as returning; callees are separate.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm_const import ARM_CC_AL, ARM_OP_IMM, ARM_OP_REG, ARM_REG_PC, ARM_REG_LR


def linear(graph, start, count):
    items, va = [], start
    for index in range(count):
        if va not in graph.nodes:
            return []
        ins = graph.nodes[va]
        items.append(ins)
        following = va + ins.size
        if index + 1 < count and following not in graph.edges[va]:
            return []
        va = following
    return items


def preceding(graph, va, count):
    items = []
    for _ in range(count):
        preds = graph.predecessors[va]
        if len(preds) != 1:
            return []
        prior = next(iter(preds))
        if prior not in graph.nodes or prior + graph.nodes[prior].size != va:
            return []
        items.insert(0, graph.nodes[prior])
        va = prior
    return items


def unwind_ranges(driver):
    section = driver.elf.get_section_by_name('.ARM.exidx')
    if (section is None or section['sh_type'] != 'SHT_ARM_EXIDX' or not section['sh_flags'] & 2
            or section['sh_size'] % 8 or section['sh_size'] > 65536):
        raise ValueError('Missing or unsupported ARM unwind range index')
    if driver.offset(section['sh_addr'], section['sh_size']) != section['sh_offset']:
        raise ValueError('Unwind section does not match LOAD mapping')
    starts = []
    for off in range(0, section['sh_size'], 8):
        word = struct.unpack_from('<I', section.data(), off)[0]
        if word & 0x80000000:
            raise ValueError('Unsupported unwind function offset')
        relative = word - (0x80000000 if word & 0x40000000 else 0)
        address = section['sh_addr'] + off + relative
        if address & 1 or not 0 <= address < 2**32:
            raise ValueError('Invalid unwind function address')
        starts.append(address)
    if starts != sorted(set(starts)):
        raise ValueError('Unwind function ranges are not strictly ordered')
    return list(zip(starts, starts[1:]))


def enclosing_range(driver, address):
    ranges = [(lo, hi) for lo, hi in unwind_ranges(driver) if lo <= address < hi]
    if len(ranges) != 1:
        raise ValueError('Site has no unique bounded unwind range')
    lo, hi = ranges[0]
    begin, end = driver.text['sh_addr'], driver.text['sh_addr'] + driver.text['sh_size']
    if not begin <= lo < hi <= end or hi - lo > 65536:
        raise ValueError('Unsupported unwind range extent')
    return lo, hi


def plt_import(driver, target):
    """Resolve only the observed three-instruction ARM veneer via GOT relocation."""
    section = driver.elf.get_section_by_name('.plt')
    rel = driver.elf.get_section_by_name('.rel.plt')
    if section is None or rel is None or not section['sh_addr'] <= target < section['sh_addr'] + section['sh_size']:
        return None
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    cs.detail = True
    ins = list(cs.disasm(driver.read(target, 12), target))
    if len(ins) != 3 or [i.mnemonic for i in ins] != ['add', 'add', 'ldr']:
        return None
    a, b, c = ins
    if (a.op_str.split(', ')[:2] != ['ip', 'pc'] or b.op_str.split(', ')[:2] != ['ip', 'ip']
            or len(a.operands) not in (3, 4) or len(b.operands) not in (3, 4)
            or a.operands[2].type != ARM_OP_IMM or b.operands[2].type != ARM_OP_IMM
            or c.operands[0].type != ARM_OP_REG or c.operands[0].reg != ARM_REG_PC
            or cs.reg_name(c.operands[1].mem.base) != 'ip' or c.operands[1].mem.index):
        return None
    def immediate(item):
        word = int.from_bytes(item.bytes, 'little')
        if word >> 28 != 14 or word & 0x0ff00000 != 0x02800000:
            raise ValueError('Unsupported ARM PLT immediate encoding')
        value, rotate = word & 255, ((word >> 8) & 15) * 2
        return ((value >> rotate) | (value << (32 - rotate))) & 0xffffffff
    got = a.address + 8 + immediate(a) + immediate(b) + c.operands[1].mem.disp
    symbols = driver.elf.get_section(rel['sh_link'])
    matches = [symbols.get_symbol(r['r_info_sym']).name for r in rel.iter_relocations()
               if r['r_offset'] == got and r['r_info_type'] == 22]  # R_ARM_JUMP_SLOT
    if len(matches) != 1:
        return None
    return dict(symbol=matches[0], plt_va=target, got_va=got)


class ThumbGraph:
    def __init__(self, driver, start, end, max_nodes=16000):
        if start & 1 or end & 1 or not 0 < end - start <= 65536:
            raise ValueError('Unsupported control-flow interval')
        driver.offset(start, end - start, executable=True)
        self.driver, self.start, self.end = driver, start, end
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.cs.detail = True
        self.nodes, self.edges, self.calls, self.issues = {}, defaultdict(set), [], []
        self.predicated, self.it_interiors = {}, set()
        self.tables = []
        pending = [start]
        while pending:
            va = pending.pop()
            if va in self.nodes:
                continue
            if len(self.nodes) >= max_nodes:
                raise ValueError('Control-flow node budget exceeded')
            if not start <= va < end or va & 1:
                self.issues.append(dict(va=va, reason='edge leaves bounded Thumb interval'))
                continue
            if any(t['data_start'] <= va < t['data_end'] for t in self.tables):
                self.issues.append(dict(va=va, reason='control flow enters table data'))
                continue
            ins = next(self.cs.disasm(driver.read(va, min(4, end - va)), va, count=1), None)
            if ins is None or ins.address + ins.size > end:
                self.issues.append(dict(va=va, reason='undecodable/truncated instruction'))
                continue
            if any(other < va < other + i.size or va < other < va + ins.size
                   for other, i in self.nodes.items()):
                self.issues.append(dict(va=va, reason='overlapping instruction boundaries'))
                continue
            self.nodes[va] = ins
            following = va + ins.size
            mnemonic = ins.mnemonic.split('.')[0]
            conditional = ins.cc not in (0, ARM_CC_AL) or va in self.predicated
            if mnemonic.startswith('it') and set(mnemonic[1:]) <= {'t', 'e'}:
                count = len(mnemonic) - 1
                seq = list(self.cs.disasm(driver.read(va, min(18, end - va)), va, count=count + 1))
                if len(seq) != count + 1:
                    self.issues.append(dict(va=va, reason='truncated IT block'))
                for item in seq[1:]:
                    self.predicated[item.address] = item.cc
                    self.it_interiors.add(item.address)
            if mnemonic in ('bl', 'blx'):
                target = ins.operands[0].imm if ins.operands[0].type == ARM_OP_IMM else None
                self.calls.append(dict(va=va, target=target, mode='ARM' if mnemonic == 'blx' else 'Thumb',
                                       imported=plt_import(driver, target) if target is not None and mnemonic == 'blx' else None))
                if target is None:
                    self.issues.append(dict(va=va, reason='indirect call target unresolved'))
                else:
                    try:
                        driver.offset(target, 4 if mnemonic == 'blx' else 2, executable=True)
                        if mnemonic == 'blx' and target & 3 or mnemonic == 'bl' and target & 1:
                            raise ValueError('Unaligned call target')
                    except ValueError:
                        self.issues.append(dict(va=va, reason='call target is not supported executable mapping'))
                successors = [following]
            elif mnemonic in ('tbb', 'tbh'):
                # Only an immediately adjacent unsigned CMP/BHI bound qualifies.
                guard = next((i for a, i in self.nodes.items() if a + i.size == va), None)
                compare = next((i for a, i in self.nodes.items() if guard and a + i.size == guard.address), None)
                memory = ins.operands[0].mem
                if (guard is None or compare is None or guard.mnemonic not in ('bhi', 'bhi.w')
                        or va in self.predicated or guard.address in self.predicated or compare.address in self.predicated
                        or compare.mnemonic not in ('cmp', 'cmp.w') or len(compare.operands) != 2
                        or compare.operands[0].type != ARM_OP_REG or compare.operands[1].type != ARM_OP_IMM
                        or compare.operands[0].reg != memory.index or memory.base != ARM_REG_PC
                        or memory.disp or not 0 <= compare.operands[1].imm <= 127):
                    self.issues.append(dict(va=va, reason='table branch lacks supported adjacent bound'))
                    successors = []
                else:
                    count, width = compare.operands[1].imm + 1, 1 if mnemonic == 'tbb' else 2
                    data_start, data_end = va + 4, va + 4 + count * width
                    if data_end > end:
                        self.issues.append(dict(va=va, reason='table data exceeds interval'))
                        successors = []
                    else:
                        raw = driver.read(data_start, count * width)
                        offsets = list(raw) if width == 1 else struct.unpack('<' + 'H' * count, raw)
                        successors = [va + 4 + 2 * offset for offset in offsets]
                        self.tables.append(dict(va=va, guard_va=guard.address, compare_va=compare.address,
                                                data_start=data_start, data_end=data_end,
                                                entries=count, width=width, targets=successors))
            elif mnemonic in ('b', 'cbz', 'cbnz') or (ins.mnemonic.startswith('b') and
                    ins.mnemonic.split('.')[0] in ('beq', 'bne', 'bhs', 'blo', 'bmi', 'bpl',
                    'bvs', 'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble')):
                target = ins.operands[-1].imm if ins.operands[-1].type == ARM_OP_IMM else None
                if target is None:
                    self.issues.append(dict(va=va, reason='branch target unresolved'))
                successors = ([target] if target is not None else [])
                if mnemonic != 'b' or conditional:
                    successors.append(following)
            elif mnemonic == 'bx' and ins.operands[0].type == ARM_OP_REG and ins.operands[0].reg == ARM_REG_LR:
                successors = [following] if conditional else []
            else:
                _, writes = ins.regs_access()
                if ARM_REG_PC in writes:
                    # Only architectural stack restores qualify as bounded returns.
                    returning = ('pc' in ins.op_str and (mnemonic == 'pop' or
                                 mnemonic.startswith('ldm') and ins.op_str.startswith('sp!,')))
                    if not returning:
                        self.issues.append(dict(va=va, reason='indirect PC write unresolved', instruction=ins.op_str))
                    successors = [following] if conditional else []
                elif mnemonic in ('tbb', 'tbh', 'svc', 'udf', 'bkpt'):
                    self.issues.append(dict(va=va, reason='unsupported table/system transfer'))
                    successors = []
                else:
                    successors = [following]
            for dest in successors:
                self.edges[va].add(dest)
                pending.append(dest)
        self.predecessors = defaultdict(set)
        for src, targets in self.edges.items():
            for dest in targets:
                self.predecessors[dest].add(src)
        for va in self.it_interiors:
            for src in self.predecessors[va]:
                if src in self.nodes and src + self.nodes[src].size != va:
                    self.issues.append(dict(va=va, reason='branch enters IT block interior', source=src))
        for table in self.tables:
            if self.predecessors[table['va']] != {table['guard_va']} or self.predecessors[table['guard_va']] != {table['compare_va']}:
                self.issues.append(dict(va=table['va'], reason='table bound can be bypassed'))
            for va, ins in self.nodes.items():
                if va < table['data_end'] and va + ins.size > table['data_start']:
                    self.issues.append(dict(va=va, reason='decoded instruction overlaps table data'))

    def reachable_from(self, start, blocked=None):
        seen, pending = set(), [start]
        while pending:
            va = pending.pop()
            if va == blocked or va in seen or va not in self.nodes:
                continue
            seen.add(va)
            pending.extend(self.edges[va])
        return seen

    def dominates(self, gate, site):
        return site in self.nodes and gate in self.nodes and site not in self.reachable_from(self.start, gate)

    def reaching(self, site):
        seen, pending = set(), [site]
        while pending:
            va = pending.pop()
            if va in seen or va not in self.nodes:
                continue
            seen.add(va)
            pending.extend(self.predecessors[va])
        return seen

    def site(self, address):
        return self.driver.site(self.nodes[address])

    def summary(self, sites=()):
        encoded = [(va, i.bytes.hex(), sorted(self.edges[va])) for va, i in sorted(self.nodes.items())]
        return dict(entry=self.start, end=self.end, nodes=len(self.nodes),
                    graph_sha256=hashlib.sha256(json.dumps(dict(nodes=encoded, tables=self.tables)).encode()).hexdigest(),
                    closed_within_range=not self.issues, issues=self.issues, calls=self.calls,
                    tables=self.tables,
                    selected_sites={str(va): dict(reachable=va in self.nodes,
                        predecessors=sorted(self.predecessors[va])) for va in sites},
                    assumptions=['Thumb decode from unwind-range start',
                                 'direct calls may return; external callee behavior unproved',
                                 'outside entries and indirect callers are not enumerated'])
