"""Independent validation of in-memory native hook experiments on both inputs.

No native ELF or installable image is written. Tests establish pending patch ABI
evidence; they do not authorize production generation or installer packaging.
"""
import argparse
import io
import json
from pathlib import Path
import random
import struct

from elftools.elf.elffile import ELFFile
from unicorn import arm_const as regs

from firmware import sha256
from generic_analysis import analyze_driver
from generic_plan import SOURCES, HERE
from tests.generic_arm import Machine, touch_dispatch
from tests.native_experiment import experiment
from verify_semantics import ORACLES, annotations, require
from generic_abi import verify_unwind_tail_extension
from generic_analysis import Driver

INTEGER = [getattr(regs, f'UC_ARM_REG_R{i}') for i in range(13)] + [regs.UC_ARM_REG_SP, regs.UC_ARM_REG_LR, regs.UC_ARM_REG_CPSR]
VFP = [getattr(regs, f'UC_ARM_REG_D{i}') for i in range(32)]


def elf_check(original, changed, manifest):
    old, new = ELFFile(io.BytesIO(original)), ELFFile(io.BytesIO(changed))
    loads = [s for s in old.iter_segments() if s['p_type'] == 'PT_LOAD']
    rx, rw = sorted(loads, key=lambda p: p['p_vaddr'])
    cut = rx['p_offset'] + rx['p_filesz']
    gap = len(changed) - len(original)
    unwind = manifest.get('cfb_observer_unwind')
    if unwind:
        verify_unwind_tail_extension(Driver(original),Driver(changed),unwind)
    require(cut == manifest['layout']['insertion_file_offset'] and gap > 0, 'Independent insertion boundary differs')
    require(old.num_segments() == new.num_segments() and old.num_sections() == new.num_sections(), 'ELF table count drift')
    for key, value in old.header.items():
        expected = value + gap if key == 'e_shoff' and value >= cut else value
        require(new[key] == expected, f'ELF header field changed unexpectedly: {key}')
    for a, b in zip(old.iter_segments(), new.iter_segments()):
        for key, value in a.header.items():
            expected = value
            if key == 'p_offset' and value >= cut:
                expected += gap
            if a['p_type'] == 'PT_LOAD' and a['p_flags'] == 5 and key in ('p_filesz', 'p_memsz'):
                expected += manifest['code_bytes']
            if a['p_type'] == 'PT_LOAD' and a['p_flags'] == 6 and key == 'p_memsz':
                expected += manifest['layout']['rw_memsz_extension']
            if unwind and a['p_type'] == 'PT_ARM_EXIDX' and key in ('p_filesz','p_memsz'):
                expected = unwind['new_index_bytes']
            require(b[key] == expected, f'ELF program field changed unexpectedly: {key}')
        if a['p_type'] == 'PT_LOAD' and a['p_flags'] == 6:
            require(a.data() == b.data(), 'Original writable file bytes changed')
        if b['p_type'] == 'PT_LOAD':
            require(b['p_offset'] % b['p_align'] == b['p_vaddr'] % b['p_align'], 'LOAD alignment changed')
    for a, b in zip(old.iter_sections(), new.iter_sections()):
        for key, value in a.header.items():
            expected = value + gap if key == 'sh_offset' and value >= cut else value
            if unwind and a.name == '.ARM.exidx' and key == 'sh_size':
                expected = unwind['new_index_bytes']
            if unwind and a.name == '.eh_frame' and key == 'sh_size':
                expected = unwind['empty_eh_frame_section']['replacement_size']
            require(b[key] == expected, f'Section metadata drift: {a.name}/{key}')
        if a['sh_type'] != 'SHT_NOBITS':
            expected = bytearray(a.data())
            if a.name == '.text':
                for hook in manifest['hooks']:
                    off = hook['va'] - a['sh_addr']
                    expected[off:off + 4] = bytes.fromhex(hook['replacement'])
            if unwind and a.name == '.ARM.exidx':
                expected += bytes.fromhex(unwind['appended_bytes'])
            if unwind and a.name == '.eh_frame':
                require(a.data()==bytes(4),'Expected empty DWARF terminator')
                require(Driver(changed).read(a['sh_addr'],4)==a.data(),'Original empty DWARF terminator changed')
                expected=bytearray()
            require(b.data() == expected, f'Original section bytes changed: {a.name}')
    require(manifest['state_va'] >= rw['p_vaddr'] + rw['p_memsz'], 'State overlaps original writable memory')
    return 'PASS: all program/section metadata, original mappings/RW/dynamic/GOT/unwind bytes and declared hook edits'


def seed_machine(machine, seed):
    rng = random.Random(seed)
    for reg in INTEGER:
        if reg not in (regs.UC_ARM_REG_SP, regs.UC_ARM_REG_CPSR):
            machine.reg(reg, rng.getrandbits(32))
    # Preserve the current execution mode/register bank; vary NZCVQ and GE.
    machine.reg(regs.UC_ARM_REG_CPSR, (machine.reg(regs.UC_ARM_REG_CPSR) & 0x0000ffff)
                | ((seed & 31) << 27) | ((seed & 15) << 16))
    for reg in VFP:
        machine.reg(reg, rng.getrandbits(64))
    machine.reg(regs.UC_ARM_REG_FPSCR,((seed & 31) << 27) | ((seed & 3) << 22) | (seed & 31))
    machine.reg(regs.UC_ARM_REG_FPEXC,0x40000000)


def direct_open(original, changed, op, state, plain_marker=None):
    count = 0
    for seed in range(32):
        for width, height, length, kind in ((2560,1440,28,1), (2560,1296,28,1), (1920,1080,28,1),
                                          (2560,1440,27,1), (2560,1440,28,2)):
            old, new = Machine(original), Machine(changed)
            for m in (old, new):
                seed_machine(m, seed)
                if plain_marker is not None:
                    m.word(m.message, plain_marker)
                m.word(m.message + 4, length)
                m.word(m.message + 8, kind)
                m.word(m.message + 16, m.payload)
                m.write(m.payload, struct.pack('<7I', width,height,30,5,0x4000,11,5))
                m.reg(regs.UC_ARM_REG_R6, m.message)
            new.word(state, seed & 1)
            prior_rw = [(va, old.read(va, size)) for va, size in old.writable]
            stack = new.read(new.stack - 256, 512)
            old.run(op['hook']['va'], (op['hook']['return_va'],))
            new.run(op['hook']['va'], (op['hook']['return_va'],))
            require([old.reg(r) for r in INTEGER] == [new.reg(r) for r in INTEGER], 'Open hook integer/flags/GE/SP/LR drift')
            require([old.reg(r) for r in VFP] == [new.reg(r) for r in VFP], 'Open hook VFP drift')
            for r in (regs.UC_ARM_REG_FPSCR,regs.UC_ARM_REG_FPEXC):
                require(old.reg(r)==new.reg(r),'Open hook VFP control drift')
            matching = length == 28 and kind == 1 and (width,height) == (2560,1440)
            expected_flag = int(matching) if length == 28 and kind == 1 else seed & 1
            require(new.word(state) == expected_flag, 'Open gate/raw profile state differs')
            require(new.word(new.payload + 4) == (1296 if matching else height), 'Open height rewrite differs')
            require(all(new.read(va,len(body)) == body for va,body in prior_rw), 'Open hook changed original writable mapping')
            after = bytearray(new.read(new.stack - 256,512))
            after[232:256] = stack[232:256]
            require(after == stack, 'Open hook wrote outside 24-byte saved-register stack area')
            count += 1
    return count


def direct_touch(original, changed, touch, state, stack_offset, aa_channel=9):
    count = 0
    for seed in range(32):
        for active in (0,1):
            for channel in (aa_channel, aa_channel + 1, aa_channel + 4):
                for y in (-2147483648,-1,0,499,500,501,5000,10000,10001,2147483647):
                    old, new = Machine(original), Machine(changed)
                    for m in (old,new):
                        seed_machine(m,seed)
                        m.reg(regs.UC_ARM_REG_R4,m.payload)
                        m.write(m.payload, struct.pack('<3i', 77, -1234, y))
                        m.word(m.stack + stack_offset,channel)
                    new.word(state,active)
                    rw = new.rw_snapshot()
                    stack = new.read(new.stack - 256,512)
                    old.run(touch['hook']['va'],(touch['hook']['return_va'],))
                    new.run(touch['hook']['va'],(touch['hook']['return_va'],))
                    require([old.reg(r) for r in INTEGER] == [new.reg(r) for r in INTEGER], 'Touch hook integer/flags/GE/SP/LR drift')
                    expected = max(0,y-500) if active and channel == aa_channel and 0 <= y <= 10000 else y
                    for i,r in enumerate(VFP):
                        if i != 7:
                            require(old.reg(r) == new.reg(r),'Touch hook changed other VFP registers')
                    require(old.reg(VFP[7]) >> 32 == new.reg(VFP[7]) >> 32,'Touch hook changed S15/X bits')
                    require(new.reg(VFP[7]) & 0xffffffff == expected & 0xffffffff,'Touch hook signed Y correction differs')
                    require(new.read(new.payload,12) == old.read(old.payload,12),'Touch hook changed source payload')
                    for r in (regs.UC_ARM_REG_FPSCR,regs.UC_ARM_REG_FPEXC):
                        require(old.reg(r)==new.reg(r),'Touch hook VFP control drift')
                    require(new.rw_snapshot() == rw,'Touch hook changed writable state')
                    after = bytearray(new.read(new.stack - 256,512))
                    after[236:256] = stack[236:256]
                    require(after == stack,'Touch hook wrote outside 20-byte saved-register stack area')
                    count += 1
    return count


def verify_generated_hooks(original, changed, manifest, native):
    """Verify actual supplied bytes using byte-derived execution locations.

    Behavioral expectations and original-versus-generated comparisons remain
    independent of the production materializer. Exact fixture APIs below retain
    their separately pinned address/shape controls.
    """
    require(native['sha256'] == sha256(original) and native['unique_candidates'], 'Native verifier input differs')
    op, touch = native['open_candidates'][0], native['touch_candidates'][0]
    sem = native['semantic_evidence']
    roles = {key: value[0] for key, value in sem['geometry_consumers'].items()}
    routes = sem['touch'][0]['routing']['routes']
    channels = {edge['value']: route['channel'] for route in routes for edge in route['selector_edges']}
    defaults = [route['channel'] for route in routes if not route['selector_edges']]
    require(len(defaults) == 1, 'Need one native fallback touch channel')
    unknown = 20
    while unknown in channels:
        unknown += 1
    channels[unknown] = defaults[0]
    aa_selector = native['channel_storage_evidence']['channel']['selector_value']
    plaintext_safe = bool(manifest['plaintext_safe'])
    checked = elf_check(original,changed,manifest)
    plain_marker = manifest['plain_packet_marker']['marker'] if plaintext_safe else None
    opened = direct_open(original,changed,op,manifest['state_va'],plain_marker)
    touched = direct_touch(original,changed,touch,manifest['state_va'],sem['touch'][0]['routing']['channel_stack_offset'],manifest['aa_channel'])
    full = 0
    for active in (0,1):
        for selector,channel in channels.items():
            for action in (14,15,16):
                for y in (0,500,5000,10000):
                    m,packet = touch_dispatch(changed,touch,sem['touch'][0],selector,action,7,9123,y,
                                             roles['type1_response']['initializer_target'],(manifest['state_va'],active))
                    expect = max(0,y-500) if active and channel == manifest['aa_channel'] else y
                    require(struct.unpack_from('<2d',packet['payload'],8) == (0.9123,expect/10000.0), 'Experimental full normalization differs')
                    expected_action = 1 if action == 14 or action == 15 and selector == 3 else 2 if action == 15 else 0
                    require(struct.unpack_from('<I',packet['payload'],24)[0] == expected_action | 7 << 8, 'Experimental gesture packing differs')
                    require(m.rw_snapshot() == m.initial_rw,'Experimental touch changed original/new writable state')
                    full += 1
    m = Machine(changed)
    state = manifest['state_va']
    require(m.word(state) == 0, 'New process gate was not zero-initialized')
    sequences = 0
    def touch_y():
        _, packet = touch_dispatch(changed,touch,sem['touch'][0],aa_selector,14,7,9123,6000,
                                   roles['type1_response']['initializer_target'],machine=m)
        return struct.unpack_from('<d',packet['payload'],16)[0]
    require(touch_y() == .6, 'Touch correction enabled before valid raw Open')
    for width,height,length,expected in ((2560,1440,28,.55), (2560,1440,28,.55),
            (2560,1296,28,.6), (2560,1440,27,.6), (2560,1440,28,.55),
            (2560,1296,27,.55), (1920,1440,28,.6)):
        m.word(m.message+4,length)
        if plain_marker is not None:
            m.word(m.message,plain_marker)
        m.word(m.message+8,1)
        m.word(m.message+16,m.payload)
        m.write(m.payload,struct.pack('<7I',width,height,30,5,0x4000,11,5))
        m.reg(regs.UC_ARM_REG_R6,m.message)
        m.run(op['validation_va'],(op['copy_end_va'],op['malformed_branch_va']))
        if length == 28:
            require((m.word(state+4),m.word(state+8)) == (width,height), 'Gate lost raw geometry before rewrite')
            require(m.word(op['effective_open_va']+4) == (1296 if (width,height)==(2560,1440) else height),
                    'Effective geometry did not follow profile rewrite')
        require(touch_y() == expected and touch_y() == expected, 'Open/Show/malformed sequence accumulated or doubled correction')
        sequences += 1
    return dict(status='PASS',manifest=manifest,elf_check=checked,
                source_sha256={n:sha256((HERE/n).read_bytes()) for n in SOURCES},
                direct_open_cases=opened,direct_touch_cases=touched,full_dispatch_cases=full,
                open_show_state_sequences=sequences,
                all_nzcvq_and_ge_patterns=True,all_integer_and_32_vfp_registers_checked=True,
                fpscr_fpexc_checked=True,
                evidence_level='actual supplied generated hook/ELF bytes and Unicorn emulation',
                generation_allowed=False,installable_images_emitted=False,hardware_tested=False,
                remaining=['paired archive/installer validation and hardware evaluation are separate'])



def verify(path, fixture, plaintext_safe=False):
    original = Path(path).read_bytes()
    oracle = ORACLES[fixture]
    require(sha256(original) == oracle['sha'], 'Independent experiment fixture differs')
    native = analyze_driver(original)
    annotations(native, oracle)  # independent exact-fixture landmarks remain controls
    changed, manifest = experiment(original, native, plaintext_safe=plaintext_safe)
    result = verify_generated_hooks(original, changed, manifest, native)
    result['fixture'] = fixture
    return result


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--driver',required=True,type=Path)
    p.add_argument('--fixture',required=True,choices=tuple(ORACLES))
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args()
    result=verify(a.driver,a.fixture)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x',encoding='utf-8') as f:
        json.dump(result,f,indent=2)
        f.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('manifest','source_sha256')},indent=2))
