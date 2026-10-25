"""Read-only ELF mappings, relevant strings and ARM/Thumb disassembly."""
import argparse
import hashlib
import io
from pathlib import Path
import re

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile


def file_offset(loads, address):
    for segment in loads:
        if segment['p_vaddr'] <= address < segment['p_vaddr'] + segment['p_filesz']:
            return segment['p_offset'] + address - segment['p_vaddr']
    raise ValueError(f'VA {address:#x} is not file-backed by PT_LOAD')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True, type=Path)
    parser.add_argument('--start', type=lambda x: int(x, 0))
    parser.add_argument('--end', type=lambda x: int(x, 0))
    parser.add_argument('--arm', action='store_true', help='ARM disassembly; default: Thumb')
    parser.add_argument('--strings', action='store_true', help='Locate geometry/protocol-related ASCII strings')
    args = parser.parse_args()
    data = args.driver.read_bytes()
    elf = ELFFile(io.BytesIO(data))
    if elf.elfclass != 32 or not elf.little_endian or elf['e_machine'] != 'EM_ARM':
        parser.error('Expected a 32-bit little-endian ARM ELF; this tool does not unpack inputs')
    loads = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    print(f'SHA256 {hashlib.sha256(data).hexdigest()} bytes={len(data)} entry={elf["e_entry"]:#x}')
    for s in loads:
        print(f'LOAD file={s["p_offset"]:#x} va={s["p_vaddr"]:#x} filesz={s["p_filesz"]:#x} memsz={s["p_memsz"]:#x} flags={s["p_flags"]} align={s["p_align"]:#x}')
    if args.strings:
        wanted = re.compile(rb'Open|HU_SCREEN|RemoteCxCy|AndroidAuto|MiddleMan|scaled_|screen_dpi|phonemirror|adb-driver', re.I)
        for match in re.finditer(rb'[\x20-\x7e]{5,}', data):
            if not wanted.search(match[0]):
                continue
            address = next((s['p_vaddr'] + match.start() - s['p_offset'] for s in loads
                            if s['p_offset'] <= match.start() < s['p_offset'] + s['p_filesz']), None)
            where = f'{address:#x}' if address is not None else 'unmapped'
            print(f'STR file={match.start():#x} va={where} {match[0][:240].decode("ascii")}')
    if (args.start is None) != (args.end is None):
        parser.error('--start and --end are required together')
    if args.start is not None:
        if not 0 < args.end - args.start <= 65536:
            parser.error('Disassembly window must be between 1 and 65536 bytes')
        try:
            begin, end = file_offset(loads, args.start), file_offset(loads, args.end - 1) + 1
        except ValueError as error:
            parser.error(str(error))
        if end - begin != args.end - args.start or not any(
            s['p_vaddr'] <= args.start < args.end <= s['p_vaddr'] + s['p_filesz'] for s in loads
        ):
            parser.error('Disassembly window must stay inside one file-backed LOAD segment')
        disassembler = Cs(CS_ARCH_ARM, CS_MODE_ARM if args.arm else CS_MODE_THUMB)
        for ins in disassembler.disasm(data[begin:end], args.start):
            print(f'{ins.address:08x} {ins.bytes.hex():10} {ins.mnemonic:9} {ins.op_str}')


if __name__ == '__main__':
    main()
