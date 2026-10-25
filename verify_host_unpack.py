"""Two genuine host decodes, October export oracle, and independent ARM LZMA.

Emulates only each packed file's bounded decompressor routine. mmap/open/close/
ioctl are mocked; CBC is supplied by host crypto. The actual ARM LZMA decoder
runs, independently checking Python liblzma output. No driver or device is run.
"""
import argparse
import json
from pathlib import Path
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_R7, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

from firmware import sha256
from generic_inventory import inventory
from generic_packing import inspect_packed, decode_lzma
from generic_unpack import unpack_driver, kernel_material


def arm_lzma(packed, kernel):
    structure = inspect_packed(packed)
    block = structure['blocks'][1]
    key, iv, _ = kernel_material(kernel)
    offset, compressed, size = block['payload_offset'], block['compressed_bytes'], block['uncompressed_bytes']
    entry = structure['loader']['entry_va'] + 20
    if packed[entry - 0x10000:entry - 0x10000 + 4] != bytes.fromhex('0c482de9'):
        raise ValueError('Unsupported independent ARM decoder entry')
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(0x10000, (len(packed) + 4095) & ~4095)
    uc.mem_write(0x10000, packed)
    uc.mem_map(0x200000, 0x100000)
    uc.mem_map(0x301000, 0x1000)
    uc.mem_map(0x400000, 0x20000)
    uc.mem_map(0x500000, 0x1000)
    uc.reg_write(UC_ARM_REG_SP, 0x410000)
    uc.reg_write(UC_ARM_REG_LR, 0x500000)
    for register, value in ((UC_ARM_REG_R0, 0x10000 + offset), (UC_ARM_REG_R1, compressed),
                            (UC_ARM_REG_R2, 0x200000), (UC_ARM_REG_R3, 0x301000)):
        uc.reg_write(register, value)
    uc.mem_write(0x301000, struct.pack('<I', size))
    events = []

    def syscall(machine, number, context):
        call = machine.reg_read(UC_ARM_REG_R7)
        args = [machine.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        if call == 192:
            if events or args[1] != compressed + 1024:
                raise ValueError('Unexpected decoder allocation')
            machine.mem_map(0x600000, (args[1] + 4095) & ~4095)
            result = 0x600000
        elif call == 5:
            if bytes(machine.mem_read(args[0], 32)).split(b'\0', 1)[0] != b'/dev/hwaes':
                raise ValueError('Unexpected decoder device open')
            result = 3
        elif call == 54:
            source, dest, length = struct.unpack('<III', machine.mem_read(args[2], 12))
            if args[:2] != [3, 0xc00c6206] or source != 0x10000 + offset or dest != 0x600000 or length != compressed:
                raise ValueError('Unexpected decoder ioctl arguments')
            raw = bytes(machine.mem_read(source, length))
            if raw != packed[offset:offset + compressed]:
                raise ValueError('Independent decoder input changed')
            worker = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            plain = worker.update(raw[:8192]) + worker.finalize() + raw[8192:]
            machine.mem_write(dest, plain)
            result = 0
        elif call in (6, 91, 0xf0002):  # close, munmap, cacheflush: mocked OS boundaries
            result = 0
        else:
            raise ValueError(f'Unexpected decoder syscall {call}')
        events.append(dict(syscall=call, simulated=True))
        machine.reg_write(UC_ARM_REG_R0, result)

    uc.hook_add(UC_HOOK_INTR, syscall)
    started = time.monotonic()
    uc.emu_start(entry, 0x500000, count=200000000)
    if (uc.reg_read(UC_ARM_REG_PC) != 0x500000 or uc.reg_read(UC_ARM_REG_R0) != 0
            or struct.unpack('<I', uc.mem_read(0x301000, 4))[0] != size):
        raise ValueError('Independent ARM decompressor did not return exact length')
    decoded = bytes(uc.mem_read(0x200000, size))
    raw = packed[offset:offset + compressed]
    worker = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    python_decoded = decode_lzma(worker.update(raw[:8192]) + worker.finalize() + raw[8192:], size)
    if decoded != python_decoded:
        raise ValueError('ARM and host LZMA decoders disagree')
    return dict(status='PASS', decoded_bytes=size, filtered_sha256=sha256(decoded), seconds=time.monotonic() - started,
                events=events, level='actual ARM LZMA routine; host AES and mocked OS boundaries', hardware_tested=False)


def verify(february, october, original, kernel_path):
    kernel = Path(kernel_path).read_bytes()
    exact = Path(original).read_bytes()
    if sha256(exact) != '0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee':
        raise ValueError('Independent October hardware export differs')
    reports = {}
    for name, path, expected_image, expected_driver in (
        ('october', october, '24589f1b71b95d87379ee2a10e130e939cd45c28bcd3ec328499f5bbd2bc477e', sha256(exact)),
        ('february', february, '5c00b2e47aca6efc15625a1887ed857b1dceac691ff9dde96ac7de2f00adf8f8',
         'a9fb4ed7aef64a5a7a9cbc221582bcb2716421fc19904a5eafba2e57c6d09eba')):
        image = Path(path).read_bytes()
        if sha256(image) != expected_image:
            raise ValueError('Independent real image fixture differs')
        stock, files = inventory(image)
        packed = files['usr/sbin/ARMadb-driver']
        decoded, evidence = unpack_driver(packed, kernel)
        if sha256(decoded) != expected_driver or name == 'october' and decoded != exact:
            raise ValueError('Host reconstruction differs from independent native oracle')
        evidence.update(image_sha256=stock['image_sha256'], version=stock['version'],
                        independent_arm_lzma=arm_lzma(packed, kernel),
                        exact_hardware_export_comparison='byte-for-byte' if name == 'october' else 'no February hardware export exists')
        reports[name] = evidence
    return dict(status='PASS', inputs=reports, hardware_access=False, generic_images_emitted=False,
                source_sha256={n: sha256((Path(__file__).parent / n).read_bytes()) for n in (
                    'generic_unpack.py', 'generic_packing.py', 'verify_host_unpack.py')})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('february-stock', 'october-stock', 'october-driver', 'kernel', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    report = verify(args.february_stock, args.october_stock, args.october_driver, args.kernel)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status='PASS', report=str(args.output.resolve())), indent=2))
