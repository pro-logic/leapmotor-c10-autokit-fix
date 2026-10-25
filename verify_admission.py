"""Independent real-input header/stream-callback/seed-writer emulation.

Native header validation, stream-reader object handling, virtual dispatch and
seed guards execute. Socket/read/send/logger boundaries are explicit mocks;
this is neither OS/device execution nor complete indirect-entry proof.
"""
import argparse
import json
from pathlib import Path
import struct

from unicorn.arm_const import UC_ARM_REG_R8

from firmware import sha256
from generic_admission import analyze_admission
from generic_analysis import Driver, analyze_driver
from generic_plan import HERE, SOURCES
from tests import generic_arm as arm


ORACLES = {
    'october': dict(sha='0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee',
        dispatch=0x1dd98, vtable=0x6cae8, callback=0x64394, callback_entry=0x6436c,
        reader=0x6482c, header=0x645ec, state=0x11f408, writer_guard=0x1f798,
        writer=0x1f7ca, writer_exit=0x1f7d6, send=0x18598, logger=0x688d4, initializer=0x64650),
    'february': dict(sha='a9fb4ed7aef64a5a7a9cbc221582bcb2716421fc19904a5eafba2e57c6d09eba',
        dispatch=0x1d2e0, vtable=0x6afd8, callback=0x62b38, callback_entry=0x62b10,
        reader=0x62fd0, header=0x62d90, state=0x11d03c, writer_guard=0x1e8b4,
        writer=0x1e8e4, writer_exit=0x1e8f0, send=0x18e2c, logger=0x66e64, initializer=0x62df4),
}
PLAIN, ENCRYPTED = 0x55aa55aa, 0x55bb55bb


def require(condition, message):
    if not condition:
        raise ValueError(message)


def header_checks(data, oracle):
    count = 0
    for marker in (PLAIN, ENCRYPTED, 0, 0xffffffff, PLAIN ^ 1, ENCRYPTED ^ 1):
        for kind in (0, 1, 240, 0x80000000, 0xffffffff):
            for valid_inverse in (False, True):
                machine = arm.Machine(data)
                inverse = (~kind & 0xffffffff) ^ (0 if valid_inverse else 1)
                descriptor = struct.pack('<4I', marker, 0x12345678, kind, inverse)
                machine.write(machine.message, descriptor)
                before = machine.rw_snapshot()
                machine.reg(arm.UC_ARM_REG_R0, machine.message)
                machine.run(oracle['header'], (machine.stop,))
                expected = int(marker in (PLAIN, ENCRYPTED) and valid_inverse)
                require(machine.reg(arm.UC_ARM_REG_R0) == expected, 'Native header acceptance differs')
                require(machine.read(machine.message, 16) == descriptor, 'Header leaf modified descriptor')
                require(machine.rw_snapshot() == before, 'Header leaf modified original writable mapping')
                require(machine.reg(arm.UC_ARM_REG_SP) == machine.stack, 'Header leaf changed SP')
                count += 1
    return count


def callback_checks(data, oracle):
    count = 0
    payload = bytes((index * 73 + 11) & 255 for index in range(28))
    for state in (-1, 0, 1):
        for marker in (PLAIN, ENCRYPTED):
            machine = arm.Machine(data)
            obj = machine.scratch + 0x3000
            message = obj + 0x38
            machine.reg(arm.UC_ARM_REG_R0, message)
            machine.run(oracle['initializer'], (machine.stop,))
            machine.word(obj, oracle['vtable'])
            machine.word(obj + 0x1c, 7)
            machine.word(oracle['state'], state)
            before = machine.rw_snapshot()
            wire = bytearray(struct.pack('<4I', marker, 28, 1, 0xfffffffe) + payload)

            def getsockname(m):
                # A non-socket descriptor selects the real stream-reader path.
                m.reg(arm.UC_ARM_REG_R0, 0xffffffff)

            def read(m):
                require(m.reg(arm.UC_ARM_REG_R0) == 7, 'Reader used wrong FD')
                size = m.reg(arm.UC_ARM_REG_R2)
                require(0 < size <= len(wire), 'Unexpected stream read extent')
                m.write(m.reg(arm.UC_ARM_REG_R1), wire[:size])
                del wire[:size]
                m.reg(arm.UC_ARM_REG_R0, size)

            machine.reg(arm.UC_ARM_REG_SP, machine.stack)
            machine.reg(arm.UC_ARM_REG_LR, machine.stop | 1)
            machine.reg(arm.UC_ARM_REG_R0, obj)
            machine.reg(arm.UC_ARM_REG_R1, 1)
            machine.run(oracle['callback_entry'], (oracle['dispatch'], machine.stop),
                        import_handlers={'getsockname': getsockname, 'read': read})
            require(machine.reg(arm.UC_ARM_REG_PC) == oracle['dispatch'], 'Framed message did not reach virtual dispatch')
            require((machine.reg(arm.UC_ARM_REG_R0), machine.reg(arm.UC_ARM_REG_R1)) == (obj, message),
                    'Virtual callback object/message arguments differ')
            require(not wire, 'Reader did not consume exact header/payload')
            require(machine.word(message) == marker and machine.packet(message) == dict(size=28, type=1, payload=payload),
                    'Transport changed framed marker or payload')
            require(machine.rw_snapshot() == before, 'Transport modified crypto state or original writable mapping')
            count += 1
    return count


def writer_checks(data, oracle):
    count = 0
    for length in (0, 3, 4, 5):
        for value in (-2147483648, -1, 0, 1, 2147483647):
            machine = arm.Machine(data)
            machine.word(oracle['state'], 37)
            machine.word(machine.message + 4, length)
            machine.word(machine.message + 8, 240)
            machine.word(machine.message + 16, machine.payload)
            machine.word(machine.payload, value)
            before = machine.rw_snapshot()
            machine.reg(arm.UC_ARM_REG_R4, oracle['state'])
            machine.reg(arm.UC_ARM_REG_R6, machine.message)
            machine.reg(arm.UC_ARM_REG_R7, machine.scratch + 0x3000)
            machine.reg(UC_ARM_REG_R8, machine.scratch + 0x3000)
            machine.run(oracle['writer_guard'], (oracle['writer_exit'],),
                        (oracle['send'], oracle['logger']))
            accepted = length == 4 and value > 0
            require(machine.word(oracle['state']) == (value if accepted else 37), 'Seed writer guard/result differs')
            expected = [bytearray(part) for part in before]
            for index, (va, size) in enumerate(machine.writable):
                if va <= oracle['state'] < va + size:
                    struct.pack_into('<I', expected[index], oracle['state'] - va, value if accepted else 37)
            require(machine.rw_snapshot() == [bytes(part) for part in expected], 'Seed writer changed unrelated writable mapping')
            require(machine.word(machine.payload) == value & 0xffffffff, 'Seed writer changed source payload')
            count += 1
    return count


def verify(path, fixture):
    data = Path(path).read_bytes()
    oracle = ORACLES[fixture]
    require(sha256(data) == oracle['sha'], 'Independent admission verifier requires exact selected fixture')
    native = analyze_driver(data)
    opened = native['semantic_evidence']['open'][0]
    contract = opened['preprocessing'][0]['open_cfb_contract']
    report = analyze_admission(Driver(data), opened['graph']['entry'], contract)
    require(len(report['vtables']) == len(report['callback_readers']) == len(report['crypto_state_writers']) == 1,
            'Need unique bounded admission findings')
    table, callback, writer = report['vtables'][0], report['callback_readers'][0], report['crypto_state_writers'][0]
    require((table['address_point_va'], callback['callback_va'], callback['function_entry'], callback['reader_entry'],
             writer['guard_va'], writer['store_va'], writer['destination_va']) ==
            (oracle['vtable'], oracle['callback'], oracle['callback_entry'], oracle['reader'],
             oracle['writer_guard'], oracle['writer'], oracle['state']), 'Independent admission landmarks differ')
    require(len(callback['header_validation_calls']) == 2, 'Expected stream/recvmsg header validator calls')
    require(all(v['contract']['function_entry'] == oracle['header'] and v['contract']['plain_marker'] == PLAIN
                for v in callback['header_validation_calls']), 'Independent header validator landmark differs')
    require(report['elf_zero_initialized'], 'Crypto state is not derived BSS zero initialization')
    return dict(status='PASS', fixture=fixture, driver_sha256=sha256(data), admission_evidence=report,
                header_cases=header_checks(data, oracle), stream_callback_cases=callback_checks(data, oracle),
                state_writer_cases=writer_checks(data, oracle),
                source_sha256={n: sha256((HERE / n).read_bytes()) for n in sorted(set(SOURCES) | {
                    'generic_admission.py', 'tests/test_generic_admission.py', 'verify_admission.py'})},
                evidence_level='bounded static discovery and actual native header/stream/callback/seed-guard emulation',
                mocks=['getsockname selects stream path', 'read supplies exact framed bytes',
                       'native packet allocator host implementation', 'seed acknowledgement sender and diagnostic return'],
                limits=['recvmsg/ancillary-FD path is statically identified, not newly emulated',
                        'all indirect entries, aliases/writers, IPC/library contracts and runtime ordering remain unproved',
                        'header validity admits encrypted framing independently of crypto readiness'],
                generation_allowed=False, hardware_tested=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True, type=Path)
    parser.add_argument('--fixture', required=True, choices=tuple(ORACLES))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Refusing to overwrite existing evidence')
    result = verify(args.driver, args.fixture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({k: result[k] for k in ('status', 'fixture', 'header_cases', 'stream_callback_cases', 'state_writer_cases')}, indent=2))
