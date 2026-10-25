"""Independent real-input checks and bounded ARM loader syscall simulation.

Only the small decoder prefix is emulated with explicit function-entry inputs.
Syscalls are intercepted; this cannot decrypt, run the driver, or contact hardware.
Fixture hashes/landmarks here are independent oracles, not recognition rules.
"""
from __future__ import annotations

import argparse
import io
import json
import platform
from pathlib import Path
import struct
import sys
import _lzma

import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_R7, UC_ARM_REG_SP, UC_ARM_REG_PC)
from elftools.elf.elffile import ELFFile

from firmware import sha256
from generic import read_bounded
from generic_inventory import inventory
from generic_packing import inspect_packed, decode_lzma
from generic_plan import insertion_layout

FIXTURES = {
    'february': dict(image='5c00b2e47aca6efc15625a1887ed857b1dceac691ff9dde96ac7de2f00adf8f8',
                     packed='baaa1ee60d43ee6a67264bb05dfcb7da9948c386c05a9e7c6be4568408e957cd',
                     header='feabea6a9d6de999657bc2642dccc253166a9ce6c3c558eec917fe87fb6ee2e8',
                     size=469516, code_header=0x149, code_size=204149, entry=0x4230c),
    'october': dict(image='24589f1b71b95d87379ee2a10e130e939cd45c28bcd3ec328499f5bbd2bc477e',
                    packed='614fa754065dcecd7465bfdc283d551abdc0c1d630c9c0c76b520a4272867cdb',
                    header='ecc60fbe83e684438c7a47e5b53faaad077981220dbbef9e181b7e9cf742db01',
                    size=478664, code_header=0x148, code_size=209209, entry=0x4370c),
}
SOURCE_PINS = {
    'patchUPX.diff': '4a736766c1d514c715e9326bddf7e2aa6f29f3ac07779024abe1f4cc1cf8ad18',
    'p_lx_elf.cpp': '506634e05ec9b15c6be14de2fbbc281c985a208d6328eadde04c85214e449590',
    'compress_lzma.cpp': '616a9a47d414b0dd45b5de24085af61072051a98cee2d1509e83a40c9252b4a0',
}
SOURCE_URLS = {
    'patchUPX.diff': 'https://raw.githubusercontent.com/ludwig-v/wireless-carplay-dongle-reverse-engineering/b437135316275a5d3c375bdd1ceac2a6bcf1315b/Debug_Tools/Source/upx-3.96/patchUPX.diff',
    'p_lx_elf.cpp': 'https://raw.githubusercontent.com/upx/upx/v3.96/src/p_lx_elf.cpp',
    'compress_lzma.cpp': 'https://raw.githubusercontent.com/upx/upx/v3.96/src/compress_lzma.cpp',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def loader_request(packed, fixture):
    """Simulate the observed ARM decoder prefix, stopping BEFORE ioctl executes."""
    entry = fixture['entry']
    require(struct.unpack_from('<I', packed, 24)[0] == entry, 'Packed entry differs')
    # Disassembly annotation: after bootstrap/type test, push r2,r3,fp,lr.
    start = entry + 20
    require(packed[start - 0x10000:start - 0x10000 + 4] == bytes.fromhex('0c482de9'),
            'Decoder function prefix differs')
    source_offset = fixture['code_header'] + 12
    source = 0x10000 + source_offset
    size = fixture['code_size']
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(0x10000, (len(packed) + 4095) & ~4095)
    uc.mem_write(0x10000, packed)
    uc.mem_map(0x200000, 0x1000)
    uc.mem_map(0x400000, 0x4000)
    uc.reg_write(UC_ARM_REG_SP, 0x402000)
    for reg, value in ((UC_ARM_REG_R0, source), (UC_ARM_REG_R1, size),
                       (UC_ARM_REG_R2, 0x200100), (UC_ARM_REG_R3, 0x200000)):
        uc.reg_write(reg, value)
    uc.mem_write(0x200000, struct.pack('<I', 500000))
    events = []

    def syscall(machine, number, context):
        call = machine.reg_read(UC_ARM_REG_R7)
        args = [machine.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        if call == 192:  # mmap2: mock anonymous RAM allocation
            require(not events and args[1] == size + 1024, 'Unexpected loader mmap')
            machine.mem_map(0x600000, (args[1] + 4095) & ~4095)
            machine.reg_write(UC_ARM_REG_R0, 0x600000)
            events.append(dict(syscall='mmap2', requested_bytes=args[1], simulated=True))
        elif call == 5:  # open: synthetic fd; no host open
            path = bytes(machine.mem_read(args[0], 32)).split(b'\0', 1)[0]
            require(path == b'/dev/hwaes' and args[1] == 2, 'Unexpected loader device open')
            machine.reg_write(UC_ARM_REG_R0, 3)
            events.append(dict(syscall='open', path=path.decode(), flags=args[1], simulated=True))
        elif call == 54:  # ioctl: inspect and stop; never supply invented plaintext
            src, dst, length = struct.unpack('<III', machine.mem_read(args[2], 12))
            require(args[0:2] == [3, 0xc00c6206] and src == source
                    and dst == 0x600000 and length == size, 'Unexpected hardware decoder request')
            require(bytes(machine.mem_read(src, length)) == packed[source_offset:source_offset + size],
                    'Loader input bytes changed')
            events.append(dict(syscall='ioctl', request=hex(args[1]), input_file_offset=source_offset,
                               requested_bytes=length, input_sha256=sha256(bytes(machine.mem_read(src, length))),
                               execution='withheld; emulation stopped before syscall',
                               pc_after_svc=machine.reg_read(UC_ARM_REG_PC)))
            machine.emu_stop()
        else:
            raise ValueError(f'Unexpected loader syscall: {call}')

    uc.hook_add(UC_HOOK_INTR, syscall)
    uc.emu_start(start, 0, count=200)
    require(len(events) == 3 and events[-1]['syscall'] == 'ioctl', 'Decoder did not reach hardware request')
    return dict(level='bounded decoder-prefix emulation with mocked syscalls',
                start_va=start, entry_assumption='r0=compressed block; r1=compressed length; r2=output; r3=size pointer',
                events=events, decryption_performed=False, hardware_tested=False,
                limit='Does not execute bootstrap, kernel AES, decompression after ioctl, or driver semantics')


def verify(february, october, original, extracted, tool, research_sources):
    native = read_bounded(original, 16 * 1024 * 1024)
    require(sha256(native) == '0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee',
            'October independent native fixture differs')
    sources = {n: sha256((research_sources / n).read_bytes()) for n in SOURCE_PINS}
    require(sources == SOURCE_PINS, 'Research source bytes differ from recorded source provenance')
    tool_bytes = read_bounded(tool, 4 * 1024 * 1024)
    require(sha256(tool_bytes) == 'c41472232b5eb4b3ca5ffa0ea7a677be7fd832a8a10446bd4ba4077964ad4f42',
            'Hardware-aware UPX tool differs')
    reports = {}
    for name, path in (('february', february), ('october', october)):
        fixture = FIXTURES[name]
        image = read_bounded(path, 64 * 1024 * 1024)
        require(sha256(image) == fixture['image'], f'{name} image fixture differs')
        stock, files = inventory(image)
        packed = files['usr/sbin/ARMadb-driver']
        require(sha256(packed) == fixture['packed'], f'{name} packed fixture differs')
        if name == 'february':
            require(read_bounded(extracted, 16 * 1024 * 1024) == packed,
                    'Previously extracted February member differs from genuine image')
        report = inspect_packed(packed)
        require(report['original_file_bytes'] == fixture['size']
                and report['original_header_sha256'] == fixture['header'], 'Original header oracle differs')
        code = report['blocks'][1]
        require(code['header_offset'] == fixture['code_header']
                and code['compressed_bytes'] == fixture['code_size']
                and code['hardware_upx_decrypt_predicate'] and code['status'] == 'not decoded',
                'Encrypted executable block oracle differs')
        comparisons = []
        for b in report['blocks']:
            if 'decoded_sha256' not in b:
                continue
            off, size = b['payload_offset'], b['compressed_bytes']
            decoded = decode_lzma(packed[off:off + size], b['uncompressed_bytes'])
            if name == 'october':
                dest = b['destination_file_offset']
                require(decoded == native[dest:dest + len(decoded)], 'October decoded extent != hardware-exported ELF')
                comparisons.append(dict(role=b['role'], bytes=len(decoded), comparison='exact October exported bytes'))
        report.update(image_sha256=stock['image_sha256'], independently_compared_extents=comparisons,
                      loader_simulation=loader_request(packed, fixture))
        reports[name] = report
    # Independent pyelftools program header and old layout annotations.
    layout = insertion_layout(native)
    require((layout['insertion_file_offset'], layout['rx_va'], layout['state_va'],
             layout['inserted_file_gap_bytes']) == (0x732e0, 0x832e0, 0x120320, 65536),
            'October independent insertion annotations differ')
    elf = ELFFile(io.BytesIO(native))
    rw = [p for p in elf.iter_segments() if p['p_type'] == 'PT_LOAD' and p['p_flags'] == 6][0]
    require(sha256(rw.data()) == layout['source_rw_sha256'], 'Insertion source RW digest differs')
    return dict(status='PASS', evidence_level='host partial decoding, independent October comparison, decoder-prefix simulation',
                python=sys.version, platform=platform.platform(), unicorn_version=unicorn.__version__,
                host_decoder=dict(method='UPX two-byte properties to size-delimited Python liblzma FORMAT_RAW LZMA1',
                                  lzma_extension_sha256=sha256(Path(_lzma.__file__).read_bytes())),
                source_sha256=sources, source_urls=SOURCE_URLS,
                implementation_sha256={n: sha256((Path(__file__).parent / n).read_bytes()) for n in (
                    'generic_packing.py', 'generic_plan.py', 'verify_packing.py')},
                hardware_upx=dict(sha256=sha256(tool_bytes), bytes=len(tool_bytes), executed=False,
                                  upstream_commit='b437135316275a5d3c375bdd1ceac2a6bcf1315b',
                                  upstream_path='Debug_Tools/upx',
                                  source_decrypt_limit_bytes=8192,
                                  checksum_errors='patched tool prints warning instead of failing'),
                inputs=reports, october_insertion_proposal=layout,
                february_complete_unpacked_sha256=None, generic_images_emitted=False,
                blockers=['Exact February code block needs verified hardware AES decoding or validated host equivalent',
                          'No compatible hardware endpoint/access established',
                          'Full native functional control/data-flow/channel/ABI proofs and new generation remain incomplete'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ('february-stock', 'october-stock', 'october-driver', 'february-extracted',
                 'hardware-upx', 'research-sources', 'output'):
        p.add_argument('--' + flag, required=True, type=Path)
    a = p.parse_args()
    result = verify(a.february_stock, a.october_stock, a.october_driver, a.february_extracted,
                    a.hardware_upx, a.research_sources)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], report=str(a.output.resolve()),
                          february_complete_native_input=False, generic_images_emitted=False), indent=2))
